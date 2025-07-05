// Package ratelimitgeo implements geospatial analysis and impossible travel detection
// as a Hockeypuck middleware plugin using the interpose framework.
package ratelimitgeo

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	PluginName        = "ratelimit-geo"
	PluginVersion     = "1.0.0"
	PluginDescription = "Geospatial analysis and impossible travel detection for rate limiting"

	// Physical limits for detection
	MaxReasonableSpeed = 1000.0 // km/h - faster than commercial aircraft
	EarthRadiusKm      = 6371.0 // Earth's radius in kilometers

	// Default configuration values
	DefaultGeoIPPath       = "/usr/share/GeoIP/GeoLite2-City.mmdb"
	DefaultTrackingTTL     = 24 * time.Hour
	DefaultCleanupInterval = 1 * time.Hour
	DefaultMaxLocations    = 100 // Maximum locations to track per IP
)

// Plugin configuration structure
type Config struct {
	Enabled           bool          `toml:"enabled"`
	GeoIPDatabasePath string        `toml:"geoip_database_path"`
	TrackingTTL       time.Duration `toml:"tracking_ttl"`
	CleanupInterval   time.Duration `toml:"cleanup_interval"`
	MaxLocations      int           `toml:"max_locations"`

	// Detection thresholds
	ImpossibleTravelEnabled bool    `toml:"impossible_travel_enabled"`
	MaxTravelSpeed          float64 `toml:"max_travel_speed_kmh"`

	// Geographic clustering detection
	ClusteringEnabled    bool          `toml:"clustering_enabled"`
	ClusterRadius        float64       `toml:"cluster_radius_km"`
	ClusterSizeThreshold int           `toml:"cluster_size_threshold"`
	ClusterTimeWindow    time.Duration `toml:"cluster_time_window"`

	// ASN analysis
	ASNAnalysisEnabled bool `toml:"asn_analysis_enabled"`
	MaxASNsPerIP       int  `toml:"max_asns_per_ip"`

	// Ban settings
	BanDuration         time.Duration `toml:"ban_duration"`
	ImpossibleTravelBan time.Duration `toml:"impossible_travel_ban"`
	ClusteringBan       time.Duration `toml:"clustering_ban"`
	ASNJumpingBan       time.Duration `toml:"asn_jumping_ban"`
}

// Default configuration
func DefaultConfig() Config {
	return Config{
		Enabled:                 true,
		GeoIPDatabasePath:       DefaultGeoIPPath,
		TrackingTTL:             DefaultTrackingTTL,
		CleanupInterval:         DefaultCleanupInterval,
		MaxLocations:            DefaultMaxLocations,
		ImpossibleTravelEnabled: true,
		MaxTravelSpeed:          MaxReasonableSpeed,
		ClusteringEnabled:       true,
		ClusterRadius:           50.0, // 50km radius
		ClusterSizeThreshold:    5,    // 5+ IPs in cluster
		ClusterTimeWindow:       1 * time.Hour,
		ASNAnalysisEnabled:      true,
		MaxASNsPerIP:            3,
		BanDuration:             1 * time.Hour,
		ImpossibleTravelBan:     6 * time.Hour,
		ClusteringBan:           2 * time.Hour,
		ASNJumpingBan:           30 * time.Minute,
	}
}

// Geographic location data
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

// IP tracking data
type IPGeoProfile struct {
	IP            string         `json:"ip"`
	Locations     []GeoLocation  `json:"locations"`
	FirstSeen     time.Time      `json:"first_seen"`
	LastSeen      time.Time      `json:"last_seen"`
	TotalRequests int            `json:"total_requests"`
	ASNs          map[uint]int   `json:"asns"`      // ASN -> request count
	Countries     map[string]int `json:"countries"` // Country -> request count

	mutex sync.RWMutex
}

// Travel anomaly detection result
type TravelAnomaly struct {
	From        GeoLocation   `json:"from"`
	To          GeoLocation   `json:"to"`
	Distance    float64       `json:"distance_km"`
	TimeDiff    time.Duration `json:"time_diff"`
	Speed       float64       `json:"speed_kmh"`
	Severity    string        `json:"severity"`
	Description string        `json:"description"`
}

// Geographic cluster detection
type GeoCluster struct {
	CenterLat    float64   `json:"center_lat"`
	CenterLng    float64   `json:"center_lng"`
	Radius       float64   `json:"radius_km"`
	IPs          []string  `json:"ips"`
	RequestCount int       `json:"request_count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// Plugin implementation
type GeoRateLimitPlugin struct {
	plugin.BasePlugin

	config  Config
	geoIPDB *geoip2.Reader
	host    plugin.PluginHost

	// IP tracking
	ipProfiles map[string]*IPGeoProfile
	profilesMu sync.RWMutex

	// Cluster tracking
	clusters   map[string]*GeoCluster
	clustersMu sync.RWMutex

	// Banned IPs with reasons
	bannedIPs map[string]BanInfo
	bannedMu  sync.RWMutex

	// Background tasks
	cleanupDone chan struct{}

	// Metrics
	metrics *GeoMetrics
}

// Ban information
type BanInfo struct {
	Reason    string         `json:"reason"`
	ExpiresAt time.Time      `json:"expires_at"`
	Anomaly   *TravelAnomaly `json:"anomaly,omitempty"`
	Cluster   *GeoCluster    `json:"cluster,omitempty"`
}

// Prometheus metrics
type GeoMetrics struct {
	impossibleTravelDetected prometheus.Counter
	clusteringDetected       prometheus.Counter
	asnJumpingDetected       prometheus.Counter
	totalBans                prometheus.Counter
	activeProfiles           prometheus.Gauge
	activeClusters           prometheus.Gauge
	geoLookupDuration        prometheus.Histogram
}

// Initialize the plugin
func (p *GeoRateLimitPlugin) Initialize(ctx context.Context, host plugin.PluginHost, configData map[string]interface{}) error {
	p.host = host

	// Load configuration
	if err := p.loadConfig(configData); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if !p.config.Enabled {
		return nil // Plugin disabled
	}

	// Initialize GeoIP database
	if err := p.initGeoIPDB(); err != nil {
		return fmt.Errorf("failed to initialize GeoIP database: %w", err)
	}

	// Initialize data structures
	p.ipProfiles = make(map[string]*IPGeoProfile)
	p.clusters = make(map[string]*GeoCluster)
	p.bannedIPs = make(map[string]BanInfo)
	p.cleanupDone = make(chan struct{})

	// Initialize metrics
	p.initMetrics()

	// Register middleware with the server
	middleware, err := p.CreateMiddleware(plugin.MiddlewareConfig{})
	if err != nil {
		return fmt.Errorf("failed to create middleware: %w", err)
	}

	// Register with interpose-style middleware chain
	if err := host.RegisterMiddleware("/pks/", middleware); err != nil {
		return fmt.Errorf("failed to register middleware: %w", err)
	}

	// Start background cleanup task
	if err := host.RegisterTask("geo-cleanup", p.config.CleanupInterval, p.cleanupTask); err != nil {
		return fmt.Errorf("failed to register cleanup task: %w", err)
	}

	return nil
}

// Load and validate configuration
func (p *GeoRateLimitPlugin) loadConfig(configData map[string]interface{}) error {
	p.config = DefaultConfig()

	// Parse configuration from map (this would be done by TOML parser in practice)
	if enabled, ok := configData["enabled"].(bool); ok {
		p.config.Enabled = enabled
	}
	if path, ok := configData["geoip_database_path"].(string); ok {
		p.config.GeoIPDatabasePath = path
	}
	if speed, ok := configData["max_travel_speed_kmh"].(float64); ok {
		p.config.MaxTravelSpeed = speed
	}

	// Validate configuration
	if p.config.MaxTravelSpeed <= 0 {
		return fmt.Errorf("max_travel_speed_kmh must be positive")
	}
	if p.config.ClusterRadius <= 0 {
		return fmt.Errorf("cluster_radius_km must be positive")
	}

	return nil
}

// Initialize GeoIP database
func (p *GeoRateLimitPlugin) initGeoIPDB() error {
	db, err := geoip2.Open(p.config.GeoIPDatabasePath)
	if err != nil {
		return fmt.Errorf("failed to open GeoIP database at %s: %w", p.config.GeoIPDatabasePath, err)
	}
	p.geoIPDB = db
	return nil
}

// Initialize Prometheus metrics
func (p *GeoRateLimitPlugin) initMetrics() {
	p.metrics = &GeoMetrics{
		impossibleTravelDetected: promauto.NewCounter(prometheus.CounterOpts{
			Name: "hockeypuck_geo_impossible_travel_total",
			Help: "Total number of impossible travel detections",
		}),
		clusteringDetected: promauto.NewCounter(prometheus.CounterOpts{
			Name: "hockeypuck_geo_clustering_total",
			Help: "Total number of geographic clustering detections",
		}),
		asnJumpingDetected: promauto.NewCounter(prometheus.CounterOpts{
			Name: "hockeypuck_geo_asn_jumping_total",
			Help: "Total number of ASN jumping detections",
		}),
		totalBans: promauto.NewCounter(prometheus.CounterOpts{
			Name: "hockeypuck_geo_bans_total",
			Help: "Total number of geographic-based bans",
		}),
		activeProfiles: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_geo_active_profiles",
			Help: "Number of active IP geographic profiles",
		}),
		activeClusters: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_geo_active_clusters",
			Help: "Number of active geographic clusters",
		}),
		geoLookupDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "hockeypuck_geo_lookup_duration_seconds",
			Help:    "Duration of GeoIP lookups",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		}),
	}
}

// Create middleware handler - interpose compatible
func (p *GeoRateLimitPlugin) CreateMiddleware(config plugin.MiddlewareConfig) (func(http.Handler) http.Handler, error) {
	if !p.config.Enabled {
		// Return pass-through middleware if disabled
		return func(next http.Handler) http.Handler {
			return next
		}, nil
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract client IP
			clientIP := p.extractClientIP(r)
			if clientIP == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if IP is currently banned
			if banned, banInfo := p.isBanned(clientIP); banned {
				p.handleBannedRequest(w, r, banInfo)
				return
			}

			// Perform geospatial analysis
			if violation := p.analyzeRequest(clientIP, r); violation != nil {
				p.handleViolation(w, r, clientIP, violation)
				return
			}

			// Request passed all checks
			next.ServeHTTP(w, r)
		})
	}, nil
}

// Extract client IP from request
func (p *GeoRateLimitPlugin) extractClientIP(r *http.Request) string {
	// Try X-Forwarded-For header first (if behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Try X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}

// Check if IP is currently banned
func (p *GeoRateLimitPlugin) isBanned(ip string) (bool, BanInfo) {
	p.bannedMu.RLock()
	defer p.bannedMu.RUnlock()

	banInfo, exists := p.bannedIPs[ip]
	if !exists {
		return false, BanInfo{}
	}

	// Check if ban has expired
	if time.Now().After(banInfo.ExpiresAt) {
		// Clean up expired ban
		go func() {
			p.bannedMu.Lock()
			delete(p.bannedIPs, ip)
			p.bannedMu.Unlock()
		}()
		return false, BanInfo{}
	}

	return true, banInfo
}

// Analyze request for geographic anomalies
func (p *GeoRateLimitPlugin) analyzeRequest(ip string, r *http.Request) *TravelAnomaly {
	start := time.Now()
	defer func() {
		p.metrics.geoLookupDuration.Observe(time.Since(start).Seconds())
	}()

	// Get geographic location for IP
	location, err := p.getGeoLocation(ip, r.URL.Path)
	if err != nil {
		// Log error but don't block request
		return nil
	}

	// Update IP profile
	profile := p.updateIPProfile(ip, location)

	// Check for impossible travel
	if p.config.ImpossibleTravelEnabled {
		if anomaly := p.detectImpossibleTravel(profile, location); anomaly != nil {
			p.metrics.impossibleTravelDetected.Inc()
			return anomaly
		}
	}

	// Check for ASN jumping
	if p.config.ASNAnalysisEnabled {
		if anomaly := p.detectASNJumping(profile, location); anomaly != nil {
			p.metrics.asnJumpingDetected.Inc()
			return anomaly
		}
	}

	// Check for geographic clustering (coordinated attacks)
	if p.config.ClusteringEnabled {
		if p.detectGeographicClustering(location) {
			p.metrics.clusteringDetected.Inc()
			return &TravelAnomaly{
				To:          location,
				Severity:    "medium",
				Description: "Geographic clustering detected - potential coordinated attack",
			}
		}
	}

	return nil
}

// Get geographic location for IP
func (p *GeoRateLimitPlugin) getGeoLocation(ip string, requestPath string) (GeoLocation, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return GeoLocation{}, fmt.Errorf("invalid IP address: %s", ip)
	}

	record, err := p.geoIPDB.City(parsedIP)
	if err != nil {
		return GeoLocation{}, fmt.Errorf("GeoIP lookup failed: %w", err)
	}

	location := GeoLocation{
		Latitude:  record.Location.Latitude,
		Longitude: record.Location.Longitude,
		Country:   record.Country.IsoCode,
		// ASN:         record.Traits.AutonomousSystemNumber,
		// ASNOrg:      record.Traits.AutonomousSystemOrganization,
		Timestamp:   time.Now(),
		RequestPath: requestPath,
	}

	// Get city name if available
	if len(record.City.Names) > 0 {
		if cityName, ok := record.City.Names["en"]; ok {
			location.City = cityName
		}
	}

	return location, nil
}

// Update IP geographic profile
func (p *GeoRateLimitPlugin) updateIPProfile(ip string, location GeoLocation) *IPGeoProfile {
	p.profilesMu.Lock()
	defer p.profilesMu.Unlock()

	profile, exists := p.ipProfiles[ip]
	if !exists {
		profile = &IPGeoProfile{
			IP:        ip,
			FirstSeen: time.Now(),
			ASNs:      make(map[uint]int),
			Countries: make(map[string]int),
		}
		p.ipProfiles[ip] = profile
	}

	profile.mutex.Lock()
	defer profile.mutex.Unlock()

	// Add location to profile
	profile.Locations = append(profile.Locations, location)

	// Limit the number of stored locations
	if len(profile.Locations) > p.config.MaxLocations {
		profile.Locations = profile.Locations[1:]
	}

	// Update metadata
	profile.LastSeen = time.Now()
	profile.TotalRequests++
	profile.ASNs[location.ASN]++
	profile.Countries[location.Country]++

	return profile
}

// Detect impossible travel patterns
func (p *GeoRateLimitPlugin) detectImpossibleTravel(profile *IPGeoProfile, currentLocation GeoLocation) *TravelAnomaly {
	profile.mutex.RLock()
	defer profile.mutex.RUnlock()

	if len(profile.Locations) < 2 {
		return nil // Need at least 2 locations to detect travel
	}

	// Get the most recent previous location
	prevLocation := profile.Locations[len(profile.Locations)-2]

	// Calculate distance and time difference
	distance := p.calculateDistance(prevLocation, currentLocation)
	timeDiff := currentLocation.Timestamp.Sub(prevLocation.Timestamp)

	// Calculate travel speed
	if timeDiff <= 0 {
		return nil // Invalid time difference
	}

	speedKmH := distance / timeDiff.Hours()

	// Check if speed exceeds threshold
	if speedKmH > p.config.MaxTravelSpeed {
		return &TravelAnomaly{
			From:        prevLocation,
			To:          currentLocation,
			Distance:    distance,
			TimeDiff:    timeDiff,
			Speed:       speedKmH,
			Severity:    p.determineSeverity(speedKmH),
			Description: fmt.Sprintf("Impossible travel: %.1f km in %v (%.1f km/h)", distance, timeDiff, speedKmH),
		}
	}

	return nil
}

// Detect ASN jumping (rapid changes in network providers)
func (p *GeoRateLimitPlugin) detectASNJumping(profile *IPGeoProfile, currentLocation GeoLocation) *TravelAnomaly {
	profile.mutex.RLock()
	defer profile.mutex.RUnlock()

	// Check if we've seen too many different ASNs
	if len(profile.ASNs) > p.config.MaxASNsPerIP {
		return &TravelAnomaly{
			To:          currentLocation,
			Severity:    "medium",
			Description: fmt.Sprintf("ASN jumping detected: %d different networks", len(profile.ASNs)),
		}
	}

	return nil
}

// Detect geographic clustering (coordinated attacks)
func (p *GeoRateLimitPlugin) detectGeographicClustering(location GeoLocation) bool {
	p.clustersMu.Lock()
	defer p.clustersMu.Unlock()

	// Find or create cluster for this location
	clusterKey := fmt.Sprintf("%.1f,%.1f", location.Latitude, location.Longitude)

	cluster, exists := p.clusters[clusterKey]
	if !exists {
		cluster = &GeoCluster{
			CenterLat: location.Latitude,
			CenterLng: location.Longitude,
			Radius:    p.config.ClusterRadius,
			FirstSeen: time.Now(),
		}
		p.clusters[clusterKey] = cluster
	}

	// Update cluster
	cluster.RequestCount++
	cluster.LastSeen = time.Now()

	// Check if cluster size exceeds threshold
	return cluster.RequestCount >= p.config.ClusterSizeThreshold
}

// Calculate distance between two geographic points using Haversine formula
func (p *GeoRateLimitPlugin) calculateDistance(from, to GeoLocation) float64 {
	lat1Rad := from.Latitude * math.Pi / 180
	lon1Rad := from.Longitude * math.Pi / 180
	lat2Rad := to.Latitude * math.Pi / 180
	lon2Rad := to.Longitude * math.Pi / 180

	dlat := lat2Rad - lat1Rad
	dlon := lon2Rad - lon1Rad

	a := math.Sin(dlat/2)*math.Sin(dlat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(dlon/2)*math.Sin(dlon/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return EarthRadiusKm * c
}

// Determine severity based on travel speed
func (p *GeoRateLimitPlugin) determineSeverity(speedKmH float64) string {
	switch {
	case speedKmH > 5000: // Faster than fastest aircraft
		return "critical"
	case speedKmH > 2000: // Faster than commercial aircraft
		return "high"
	case speedKmH > 1000: // Default threshold
		return "medium"
	default:
		return "low"
	}
}

// Handle geographic violation
func (p *GeoRateLimitPlugin) handleViolation(w http.ResponseWriter, r *http.Request, ip string, anomaly *TravelAnomaly) {
	// Determine ban duration based on violation type
	var banDuration time.Duration
	var reason string

	switch {
	case anomaly.Speed > 0: // Impossible travel
		banDuration = p.config.ImpossibleTravelBan
		reason = fmt.Sprintf("Impossible travel detected: %s", anomaly.Description)
	case anomaly.Description == "Geographic clustering detected - potential coordinated attack":
		banDuration = p.config.ClusteringBan
		reason = "Geographic clustering detected"
	default:
		banDuration = p.config.ASNJumpingBan
		reason = anomaly.Description
	}

	// Add to ban list
	p.bannedMu.Lock()
	p.bannedIPs[ip] = BanInfo{
		Reason:    reason,
		ExpiresAt: time.Now().Add(banDuration),
		Anomaly:   anomaly,
	}
	p.bannedMu.Unlock()

	p.metrics.totalBans.Inc()

	// Set response headers for load balancer intelligence (detailed)
	w.Header().Set("X-RateLimit-Ban", formatDuration(banDuration))
	w.Header().Set("X-RateLimit-Ban-Reason", reason)
	w.Header().Set("X-RateLimit-Ban-Type", "geo")

	// Send sanitized response to client
	http.Error(w, "Rate limit exceeded: Geographic anomaly detected", http.StatusTooManyRequests)

	// Log the violation
	p.host.Logger().Warn("Geographic violation detected",
		"ip", ip,
		"reason", reason,
		"ban_duration", banDuration.String(),
	)
}

// Handle banned request
func (p *GeoRateLimitPlugin) handleBannedRequest(w http.ResponseWriter, r *http.Request, banInfo BanInfo) {
	remainingDuration := time.Until(banInfo.ExpiresAt)

	// Set response headers
	w.Header().Set("X-RateLimit-Ban", formatDuration(remainingDuration))
	w.Header().Set("X-RateLimit-Ban-Reason", banInfo.Reason)
	w.Header().Set("X-RateLimit-Ban-Type", "geo")

	// Send sanitized response to client
	http.Error(w, "Rate limit exceeded: Access temporarily restricted", http.StatusTooManyRequests)
}

// Cleanup task for old profiles and expired bans
func (p *GeoRateLimitPlugin) cleanupTask(ctx context.Context) error {
	now := time.Now()
	cutoff := now.Add(-p.config.TrackingTTL)

	// Clean up old profiles
	p.profilesMu.Lock()
	for ip, profile := range p.ipProfiles {
		if profile.LastSeen.Before(cutoff) {
			delete(p.ipProfiles, ip)
		}
	}
	p.profilesMu.Unlock()

	// Clean up expired bans
	p.bannedMu.Lock()
	for ip, banInfo := range p.bannedIPs {
		if now.After(banInfo.ExpiresAt) {
			delete(p.bannedIPs, ip)
		}
	}
	p.bannedMu.Unlock()

	// Clean up old clusters
	p.clustersMu.Lock()
	for key, cluster := range p.clusters {
		if cluster.LastSeen.Before(cutoff) {
			delete(p.clusters, key)
		}
	}
	p.clustersMu.Unlock()

	// Update metrics
	p.profilesMu.RLock()
	p.metrics.activeProfiles.Set(float64(len(p.ipProfiles)))
	p.profilesMu.RUnlock()

	p.clustersMu.RLock()
	p.metrics.activeClusters.Set(float64(len(p.clusters)))
	p.clustersMu.RUnlock()

	return nil
}

// Format duration for headers
func formatDuration(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmt.Sprintf("%.0fd", d.Hours()/24)
	} else if d >= time.Hour {
		return fmt.Sprintf("%.0fh", d.Hours())
	} else {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
}

// Plugin interface methods
func (p *GeoRateLimitPlugin) Name() string {
	return PluginName
}

func (p *GeoRateLimitPlugin) Version() string {
	return PluginVersion
}

func (p *GeoRateLimitPlugin) Description() string {
	return PluginDescription
}

func (p *GeoRateLimitPlugin) Dependencies() []plugin.PluginDependency {
	// No dependencies for this standalone plugin
	return []plugin.PluginDependency{}
}

func (p *GeoRateLimitPlugin) Priority() int {
	return 100 // Run after core rate limiting
}

func (p *GeoRateLimitPlugin) ApplicablePaths() []string {
	return []string{"/pks/"}
}

func (p *GeoRateLimitPlugin) Shutdown(ctx context.Context) error {
	if p.geoIPDB != nil {
		p.geoIPDB.Close()
	}

	close(p.cleanupDone)
	return nil
}

// Plugin entry point
// GetPlugin returns a new instance of the plugin for dynamic loading
func GetPlugin() plugin.Plugin {
	return &GeoRateLimitPlugin{}
}

// Example configuration for the plugin
const ExampleConfig = `
[plugins.config.ratelimit-geo]
enabled = true
geoip_database_path = "/usr/share/GeoIP/GeoLite2-City.mmdb"
tracking_ttl = "24h"
cleanup_interval = "1h"
max_locations = 100

# Impossible travel detection
impossible_travel_enabled = true
max_travel_speed_kmh = 1000.0

# Geographic clustering detection
clustering_enabled = true
cluster_radius_km = 50.0
cluster_size_threshold = 5
cluster_time_window = "1h"

# ASN analysis
asn_analysis_enabled = true
max_asns_per_ip = 3

# Ban durations
ban_duration = "1h"
impossible_travel_ban = "6h"
clustering_ban = "2h"
asn_jumping_ban = "30m"
`

// Compatibility alias for main.go
type RateLimitGeoPlugin = GeoRateLimitPlugin
