// Geographic Rate Limiting Plugin - gRPC Implementation
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// Plugin constants
const (
	PluginName    = "ratelimit-geo"
	PluginVersion = "1.0.0"
	Priority      = 20

	// Physical limits for detection
	MaxReasonableSpeed = 1000.0 // km/h - faster than commercial aircraft
	EarthRadiusKm      = 6371.0 // Earth's radius in kilometers
)

// GeoRateLimitPlugin implements gRPC-based geographic rate limiting
type GeoRateLimitPlugin struct {
	proto.UnimplementedHKPPluginServer
	config   *GeoConfig
	tracker  *LocationTracker
	analyzer *TravelAnalyzer
	detector *ClusterDetector
	mu       sync.RWMutex
}

// GeoConfig holds the plugin configuration
type GeoConfig struct {
	Enabled                 bool          `json:"enabled"`
	GeoIPDatabasePath       string        `json:"geoip_database_path"`
	TrackingTTL             time.Duration `json:"tracking_ttl"`
	MaxLocations            int           `json:"max_locations"`
	ImpossibleTravelEnabled bool          `json:"impossible_travel_enabled"`
	MaxTravelSpeed          float64       `json:"max_travel_speed_kmh"`
	ClusteringEnabled       bool          `json:"clustering_enabled"`
	ClusterRadius           float64       `json:"cluster_radius_km"`
	ClusterSizeThreshold    int           `json:"cluster_size_threshold"`
	ClusterTimeWindow       time.Duration `json:"cluster_time_window"`
	BanDuration             time.Duration `json:"ban_duration"`
	ImpossibleTravelBan     time.Duration `json:"impossible_travel_ban"`
	ClusteringBan           time.Duration `json:"clustering_ban"`
}

// GeoLocation represents a geographic location with timing
type GeoLocation struct {
	Latitude    float64   `json:"latitude"`
	Longitude   float64   `json:"longitude"`
	Country     string    `json:"country"`
	City        string    `json:"city"`
	ASN         uint      `json:"asn"`
	ASNOrg      string    `json:"asn_org"`
	Timestamp   time.Time `json:"timestamp"`
	RequestPath string    `json:"request_path"`
}

// LocationTracker tracks IP locations over time
type LocationTracker struct {
	locations map[string][]*GeoLocation
	mu        sync.RWMutex
}

// TravelAnalyzer analyzes impossible travel patterns
type TravelAnalyzer struct {
	config *GeoConfig
}

// ClusterDetector detects suspicious geographic clustering
type ClusterDetector struct {
	config *GeoConfig
}

// NewGeoRateLimitPlugin creates a new geographic rate limiting plugin
func NewGeoRateLimitPlugin() *GeoRateLimitPlugin {
	config := &GeoConfig{
		Enabled:                 true,
		GeoIPDatabasePath:       "/usr/share/GeoIP/GeoLite2-City.mmdb",
		TrackingTTL:             24 * time.Hour,
		MaxLocations:            100,
		ImpossibleTravelEnabled: true,
		MaxTravelSpeed:          MaxReasonableSpeed,
		ClusteringEnabled:       true,
		ClusterRadius:           50.0, // 50km radius
		ClusterSizeThreshold:    5,    // 5+ IPs in cluster
		ClusterTimeWindow:       1 * time.Hour,
		BanDuration:             1 * time.Hour,
		ImpossibleTravelBan:     6 * time.Hour,
		ClusteringBan:           2 * time.Hour,
	}

	return &GeoRateLimitPlugin{
		config:   config,
		tracker:  NewLocationTracker(),
		analyzer: NewTravelAnalyzer(config),
		detector: NewClusterDetector(config),
	}
}

// Initialize implements the gRPC HKPPlugin interface
func (p *GeoRateLimitPlugin) Initialize(ctx context.Context, req *proto.InitRequest) (*proto.InitResponse, error) {
	// Parse configuration
	if req.ConfigJson != "" {
		if err := json.Unmarshal([]byte(req.ConfigJson), p.config); err != nil {
			return &proto.InitResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to parse config: %v", err),
			}, nil
		}
	}

	log.Printf("Geographic Rate Limiting plugin initialized - enabled: %t, impossible_travel: %t",
		p.config.Enabled, p.config.ImpossibleTravelEnabled)

	return &proto.InitResponse{
		Success: true,
		Info: &proto.PluginInfo{
			Name:         PluginName,
			Version:      PluginVersion,
			Description:  "Geospatial analysis and impossible travel detection for rate limiting",
			Capabilities: []string{"rate_limiting", "geographic_analysis", "clustering_detection"},
		},
	}, nil
}

// HandleHTTPRequest implements HTTP request processing with geographic analysis
func (p *GeoRateLimitPlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
	// Skip if not enabled
	if !p.config.Enabled {
		return &proto.HTTPResponse{
			StatusCode:    200,
			ContinueChain: true,
		}, nil
	}

	// Extract client IP
	clientIP := p.extractClientIP(req)

	// Get geographic location for this IP
	location, err := p.getLocationForIP(clientIP, req.Path)
	if err != nil {
		// If we can't get location, allow the request but log the error
		log.Printf("Failed to get location for IP %s: %v", clientIP, err)
		return &proto.HTTPResponse{
			StatusCode:    200,
			ContinueChain: true,
		}, nil
	}

	// Track this location
	p.tracker.TrackLocation(clientIP, location)

	// Analyze for impossible travel
	if p.config.ImpossibleTravelEnabled {
		if violation := p.analyzer.AnalyzeTravel(clientIP, location, p.tracker.GetLocations(clientIP)); violation != nil {
			log.Printf("Impossible travel detected: %s from %s to %s (%.1f km in %.1f minutes, %.1f km/h)",
				clientIP, violation.FromCity, violation.ToCity, violation.Distance, violation.TimeDelta.Minutes(), violation.Speed)

			return &proto.HTTPResponse{
				StatusCode: 429,
				Body:       []byte("Rate limit exceeded: Impossible travel detected"),
				Headers: map[string]string{
					"X-Geo-Plugin":    fmt.Sprintf("%s/%s", PluginName, PluginVersion),
					"X-Geo-Violation": "impossible_travel",
					"X-Geo-Distance":  fmt.Sprintf("%.1f", violation.Distance),
					"X-Geo-Speed":     fmt.Sprintf("%.1f", violation.Speed),
					"Retry-After":     fmt.Sprintf("%d", int(p.config.ImpossibleTravelBan.Seconds())),
				},
				ContinueChain: false,
			}, nil
		}
	}

	// Analyze for geographic clustering
	if p.config.ClusteringEnabled {
		if cluster := p.detector.DetectClustering(location); cluster != nil {
			log.Printf("Geographic clustering detected: %d IPs in %.1f km radius around %s",
				cluster.Size, cluster.Radius, cluster.CenterCity)

			return &proto.HTTPResponse{
				StatusCode: 429,
				Body:       []byte("Rate limit exceeded: Suspicious geographic clustering detected"),
				Headers: map[string]string{
					"X-Geo-Plugin":    fmt.Sprintf("%s/%s", PluginName, PluginVersion),
					"X-Geo-Violation": "clustering",
					"X-Geo-Cluster":   fmt.Sprintf("%d", cluster.Size),
					"Retry-After":     fmt.Sprintf("%d", int(p.config.ClusteringBan.Seconds())),
				},
				ContinueChain: false,
			}, nil
		}
	}

	// Add geographic information to headers
	headers := map[string]string{
		"X-Geo-Plugin":  fmt.Sprintf("%s/%s", PluginName, PluginVersion),
		"X-Geo-Country": location.Country,
		"X-Geo-City":    location.City,
		"X-Geo-Coords":  fmt.Sprintf("%.4f,%.4f", location.Latitude, location.Longitude),
	}

	return &proto.HTTPResponse{
		StatusCode:    200,
		Headers:       headers,
		ContinueChain: true,
	}, nil
}

// CheckRateLimit implements geographic rate limiting
func (p *GeoRateLimitPlugin) CheckRateLimit(ctx context.Context, req *proto.RateLimitCheck) (*proto.RateLimitResponse, error) {
	if !p.config.Enabled {
		return &proto.RateLimitResponse{Allowed: true}, nil
	}

	// Extract IP from identifier
	clientIP := req.Identifier

	// Check recent locations for this IP
	locations := p.tracker.GetLocations(clientIP)
	if len(locations) < 2 {
		return &proto.RateLimitResponse{Allowed: true}, nil
	}

	// Quick check for impossible travel using most recent locations
	recent := locations[len(locations)-1]
	previous := locations[len(locations)-2]

	distance := p.calculateDistance(previous.Latitude, previous.Longitude,
		recent.Latitude, recent.Longitude)
	timeDelta := recent.Timestamp.Sub(previous.Timestamp)
	speed := distance / (timeDelta.Hours())

	if speed > p.config.MaxTravelSpeed {
		return &proto.RateLimitResponse{
			Allowed:           false,
			RetryAfterSeconds: int32(p.config.ImpossibleTravelBan.Seconds()),
			Reason:            fmt.Sprintf("Impossible travel detected: %.1f km/h", speed),
		}, nil
	}

	return &proto.RateLimitResponse{Allowed: true}, nil
}

// Helper methods

func (p *GeoRateLimitPlugin) extractClientIP(req *proto.HTTPRequest) string {
	// Check X-Forwarded-For
	if xForwardedFor, exists := req.Headers["X-Forwarded-For"]; exists {
		return xForwardedFor
	}

	// Check X-Real-IP
	if xRealIP, exists := req.Headers["X-Real-IP"]; exists {
		return xRealIP
	}

	// Use remote address
	return req.RemoteAddr
}

func (p *GeoRateLimitPlugin) getLocationForIP(ip, path string) (*GeoLocation, error) {
	// Simplified geolocation - in reality would use GeoIP database
	// For demo purposes, we'll generate deterministic fake locations based on IP

	// Parse IP to get last octet for deterministic positioning
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Create a deterministic but varied location based on IP
	ipBytes := parsedIP.To4()
	if ipBytes == nil {
		ipBytes = parsedIP.To16()[12:] // Use last 4 bytes of IPv6
	}

	// Generate latitude/longitude based on IP
	lat := float64(int(ipBytes[2])%180) - 90.0  // -90 to +90
	lng := float64(int(ipBytes[3])%360) - 180.0 // -180 to +180

	// Add some randomness but keep it deterministic for the same IP
	seed := int64(ipBytes[0]) + int64(ipBytes[1])<<8
	lat += float64((seed%100)-50) / 1000.0  // ±0.05 degrees
	lng += float64((seed%200)-100) / 1000.0 // ±0.1 degrees

	// Determine country/city based on location
	country := "Unknown"
	city := "Unknown"

	if lat > 25 && lat < 50 && lng > -130 && lng < -65 {
		country = "United States"
		if lat > 40 {
			city = "New York"
		} else {
			city = "Los Angeles"
		}
	} else if lat > 45 && lat < 70 && lng > -15 && lng < 30 {
		country = "Germany"
		city = "Berlin"
	} else {
		country = "Other"
		city = "Unknown"
	}

	return &GeoLocation{
		Latitude:    lat,
		Longitude:   lng,
		Country:     country,
		City:        city,
		ASN:         uint(ipBytes[0]) + 1000,
		ASNOrg:      fmt.Sprintf("ISP-%d", ipBytes[0]),
		Timestamp:   time.Now(),
		RequestPath: path,
	}, nil
}

func (p *GeoRateLimitPlugin) calculateDistance(lat1, lng1, lat2, lng2 float64) float64 {
	// Haversine formula for calculating distance between two points on Earth
	dLat := (lat2 - lat1) * math.Pi / 180.0
	dLng := (lng2 - lng1) * math.Pi / 180.0

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180.0)*math.Cos(lat2*math.Pi/180.0)*
			math.Sin(dLng/2)*math.Sin(dLng/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return EarthRadiusKm * c
}

// Required gRPC methods

func (p *GeoRateLimitPlugin) GetInfo(ctx context.Context, req *proto.Empty) (*proto.PluginInfo, error) {
	return &proto.PluginInfo{
		Name:         PluginName,
		Version:      PluginVersion,
		Description:  "Geospatial analysis and impossible travel detection for rate limiting",
		Capabilities: []string{"rate_limiting", "geographic_analysis", "clustering_detection"},
		Metadata: map[string]string{
			"priority":         fmt.Sprintf("%d", Priority),
			"max_travel_speed": fmt.Sprintf("%.1f", p.config.MaxTravelSpeed),
			"cluster_enabled":  fmt.Sprintf("%t", p.config.ClusteringEnabled),
		},
	}, nil
}

func (p *GeoRateLimitPlugin) HandleKeyChange(ctx context.Context, req *proto.KeyChangeEvent) (*proto.Event, error) {
	// Geographic analysis doesn't typically need to process key changes
	eventData := map[string]string{
		"fingerprint":  req.Fingerprint,
		"geo_analyzed": "false",
	}

	dataBytes, _ := json.Marshal(eventData)

	return &proto.Event{
		Type:      "geo.key.skipped",
		Source:    PluginName,
		Timestamp: time.Now().Unix(),
		Data:      dataBytes,
	}, nil
}

func (p *GeoRateLimitPlugin) SubscribeEvents(req *proto.EventFilter, stream proto.HKPPlugin_SubscribeEventsServer) error {
	<-stream.Context().Done()
	return nil
}

func (p *GeoRateLimitPlugin) PublishEvent(ctx context.Context, req *proto.Event) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

func (p *GeoRateLimitPlugin) QueryStorage(ctx context.Context, req *proto.StorageQuery) (*proto.StorageResponse, error) {
	return &proto.StorageResponse{
		Success: false,
		Error:   "Storage queries not supported by geo rate limiting plugin",
	}, nil
}

func (p *GeoRateLimitPlugin) ReportThreat(ctx context.Context, req *proto.ThreatInfo) (*proto.Empty, error) {
	// Could use threat reports to enhance geographic analysis
	return &proto.Empty{}, nil
}

func (p *GeoRateLimitPlugin) HealthCheck(ctx context.Context, req *proto.Empty) (*proto.HealthStatus, error) {
	status := proto.HealthStatus_HEALTHY
	message := "Geographic rate limiting plugin is healthy"

	// Check if we have location data
	locationCount := p.tracker.GetLocationCount()

	return &proto.HealthStatus{
		Status:    status,
		Message:   message,
		Timestamp: time.Now().Unix(),
		Details: map[string]string{
			"enabled":            fmt.Sprintf("%t", p.config.Enabled),
			"impossible_travel":  fmt.Sprintf("%t", p.config.ImpossibleTravelEnabled),
			"clustering_enabled": fmt.Sprintf("%t", p.config.ClusteringEnabled),
			"tracked_ips":        fmt.Sprintf("%d", locationCount),
			"max_travel_speed":   fmt.Sprintf("%.1f", p.config.MaxTravelSpeed),
		},
	}, nil
}

func (p *GeoRateLimitPlugin) Shutdown(ctx context.Context, req *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	log.Printf("Geographic rate limiting plugin shutting down...")
	return &proto.ShutdownResponse{Success: true}, nil
}

func main() {
	// Get gRPC address from environment
	address := os.Getenv("PLUGIN_GRPC_ADDRESS")
	if address == "" {
		address = "localhost:50003"
	}

	// Create listener
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create and register plugin
	plugin := NewGeoRateLimitPlugin()
	proto.RegisterHKPPluginServer(grpcServer, plugin)

	// Register health service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	log.Printf("Geographic Rate Limiting gRPC plugin starting on %s", address)

	// Start serving
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
