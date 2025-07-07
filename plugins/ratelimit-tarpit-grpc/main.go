// Tarpit Rate Limiting Plugin - gRPC Implementation
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// Plugin constants
const (
	PluginName    = "ratelimit-tarpit"
	PluginVersion = "1.0.0"
	Priority      = 50
)

// TarpitPlugin implements gRPC-based defensive connection management
type TarpitPlugin struct {
	proto.UnimplementedHKPPluginServer
	config                *TarpitConfig
	tarpit                *Tarpit
	honeypot              *Honeypot
	connManager           *ConnectionManager
	intelligenceCollector *IntelligenceCollector
	metrics               *TarpitMetrics
	mu                    sync.RWMutex
}

// TarpitConfig holds configuration
type TarpitConfig struct {
	Enabled              bool                     `json:"enabled"`
	TarpitMode           string                   `json:"tarpit_mode"` // slow, sticky, random
	DelayMin             string                   `json:"delay_min"`
	DelayMax             string                   `json:"delay_max"`
	ResponseChunkSize    int                      `json:"response_chunk_size"`
	ConnectionTimeout    string                   `json:"connection_timeout"`
	MaxConcurrentTarpits int                      `json:"max_concurrent_tarpits"`
	HoneypotEnabled      bool                     `json:"honeypot_enabled"`
	HoneypotPaths        []string                 `json:"honeypot_paths"`
	IntelligenceMode     bool                     `json:"intelligence_mode"`
	AutoTarpitThreshold  float64                  `json:"auto_tarpit_threshold"`
	ResourceExhaustion   ResourceExhaustionConfig `json:"resource_exhaustion"`
}

// ResourceExhaustionConfig configures resource exhaustion tactics
type ResourceExhaustionConfig struct {
	Enabled         bool   `json:"enabled"`
	CPUIntensive    bool   `json:"cpu_intensive"`
	MemoryIntensive bool   `json:"memory_intensive"`
	BandwidthMode   string `json:"bandwidth_mode"` // slow, burst, random
	FakeDataSize    int    `json:"fake_data_size"`
}

// ConnectionInfo tracks tarpit connection details
type ConnectionInfo struct {
	ClientIP      string
	ConnectedAt   time.Time
	BytesSent     int64
	DelaysApplied int
	State         string // active, draining, closed
	Reason        string // why connection was tarpitted
	Intelligence  AttackerIntelligence
}

// AttackerIntelligence gathered from tarpitted connections
type AttackerIntelligence struct {
	Patterns       []string
	Tools          []string
	Techniques     []string
	Persistence    int
	Sophistication string // low, medium, high
}

// NewTarpitPlugin creates a new tarpit plugin
func NewTarpitPlugin() *TarpitPlugin {
	config := &TarpitConfig{
		Enabled:              true,
		TarpitMode:           "slow",
		DelayMin:             "100ms",
		DelayMax:             "10s",
		ResponseChunkSize:    64,
		ConnectionTimeout:    "5m",
		MaxConcurrentTarpits: 1000,
		HoneypotEnabled:      true,
		HoneypotPaths:        []string{"/admin", "/wp-admin", "/.git", "/.env", "/phpmyadmin"},
		IntelligenceMode:     true,
		AutoTarpitThreshold:  0.8,
		ResourceExhaustion: ResourceExhaustionConfig{
			Enabled:         true,
			CPUIntensive:    false,
			MemoryIntensive: false,
			BandwidthMode:   "slow",
			FakeDataSize:    1024,
		},
	}

	return &TarpitPlugin{
		config:                config,
		tarpit:                NewTarpit(config),
		honeypot:              NewHoneypot(config.HoneypotPaths),
		connManager:           NewConnectionManager(config.MaxConcurrentTarpits),
		intelligenceCollector: NewIntelligenceCollector(),
		metrics:               NewTarpitMetrics(),
	}
}

// Initialize implements the gRPC HKPPlugin interface
func (p *TarpitPlugin) Initialize(ctx context.Context, req *proto.InitRequest) (*proto.InitResponse, error) {
	// Parse configuration
	if req.ConfigJson != "" {
		if err := json.Unmarshal([]byte(req.ConfigJson), p.config); err != nil {
			return &proto.InitResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to parse config: %v", err),
			}, nil
		}
	}

	log.Printf("Tarpit plugin initialized - enabled: %t, honeypot: %t, intelligence: %t",
		p.config.Enabled, p.config.HoneypotEnabled, p.config.IntelligenceMode)

	return &proto.InitResponse{
		Success: true,
		Info: &proto.PluginInfo{
			Name:         PluginName,
			Version:      PluginVersion,
			Description:  "Defensive connection management with tarpit and honeypot functionality",
			Capabilities: []string{"rate_limiting", "tarpit", "honeypot", "intelligence_gathering"},
		},
	}, nil
}

// HandleHTTPRequest implements HTTP request processing with tarpit analysis
func (p *TarpitPlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
	// Skip if not enabled
	if !p.config.Enabled {
		return &proto.HTTPResponse{
			StatusCode:    200,
			ContinueChain: true,
		}, nil
	}

	// Extract client IP
	clientIP := p.extractClientIP(req)

	// Check if should tarpit
	if shouldTarpit, reason := p.shouldTarpit(clientIP, req); shouldTarpit {
		return p.handleTarpit(ctx, req, clientIP, reason)
	}

	// Check if honeypot path
	if p.config.HoneypotEnabled && p.honeypot.IsHoneypotPath(req.Path) {
		return p.handleHoneypot(req, clientIP)
	}

	// Add defensive headers
	headers := map[string]string{
		"X-Tarpit-Plugin": fmt.Sprintf("%s/%s", PluginName, PluginVersion),
		"X-Tarpit-Status": "monitored",
	}

	return &proto.HTTPResponse{
		StatusCode:    200,
		Headers:       headers,
		ContinueChain: true,
	}, nil
}

// CheckRateLimit implements tarpit-based rate limiting
func (p *TarpitPlugin) CheckRateLimit(ctx context.Context, req *proto.RateLimitCheck) (*proto.RateLimitResponse, error) {
	if !p.config.Enabled {
		return &proto.RateLimitResponse{Allowed: true}, nil
	}

	clientIP := req.Identifier

	// Check if IP is currently tarpitted
	if conn := p.connManager.GetConnection(clientIP); conn != nil {
		remainingTime := p.getRemainingTarpitTime(conn)
		if remainingTime > 0 {
			return &proto.RateLimitResponse{
				Allowed:           false,
				RetryAfterSeconds: int32(remainingTime.Seconds()),
				Reason:            fmt.Sprintf("Tarpitted: %s", conn.Reason),
			}, nil
		}
	}

	return &proto.RateLimitResponse{Allowed: true}, nil
}

// Helper methods

func (p *TarpitPlugin) extractClientIP(req *proto.HTTPRequest) string {
	// Check X-Forwarded-For
	if xForwardedFor, exists := req.Headers["X-Forwarded-For"]; exists {
		return xForwardedFor
	}

	// Check X-Real-IP
	if xRealIP, exists := req.Headers["X-Real-IP"]; exists {
		return xRealIP
	}

	return req.RemoteAddr
}

func (p *TarpitPlugin) shouldTarpit(clientIP string, req *proto.HTTPRequest) (bool, string) {
	// Check various criteria

	// 1. Check if already marked for tarpit
	if marked, exists := req.Headers["X-Tarpit-Candidate"]; exists && marked == "true" {
		return true, "marked_by_rate_limiter"
	}

	// 2. Check honeypot access attempts
	if p.honeypot.IsHoneypotPath(req.Path) {
		return true, "honeypot_access"
	}

	// 3. Check for scanner patterns
	userAgent := strings.ToLower(req.Headers["User-Agent"])
	scanners := []string{"nikto", "nmap", "masscan", "sqlmap", "dirbuster"}
	for _, scanner := range scanners {
		if strings.Contains(userAgent, scanner) {
			return true, fmt.Sprintf("scanner_detected: %s", scanner)
		}
	}

	// 4. Check for attack patterns in URL
	attackPatterns := []string{"../", "union select", "<script>", "eval(", "base64_decode"}
	urlStr := strings.ToLower(req.Path)
	for _, pattern := range attackPatterns {
		if strings.Contains(urlStr, pattern) {
			return true, fmt.Sprintf("attack_pattern: %s", pattern)
		}
	}

	return false, ""
}

func (p *TarpitPlugin) handleTarpit(ctx context.Context, req *proto.HTTPRequest, clientIP string, reason string) (*proto.HTTPResponse, error) {
	// Add connection
	connInfo := p.connManager.AddConnection(clientIP, reason)

	// Collect intelligence if enabled
	if p.config.IntelligenceMode {
		p.intelligenceCollector.AnalyzeRequest(clientIP, req, connInfo)
	}

	// Record metrics
	p.metrics.RecordTarpit(clientIP, reason)

	log.Printf("Tarpitting client %s: %s", clientIP, reason)

	// Generate tarpit response
	tarpitResponse := p.tarpit.GenerateTarpitResponse(connInfo)

	return &proto.HTTPResponse{
		StatusCode: 200,
		Body:       tarpitResponse,
		Headers: map[string]string{
			"X-Tarpit-Plugin":  fmt.Sprintf("%s/%s", PluginName, PluginVersion),
			"X-Tarpit":         "active",
			"X-Tarpit-Reason":  reason,
			"Cache-Control":    "no-cache, no-store, must-revalidate",
			"Connection":       "keep-alive",
			"Content-Type":     "text/plain",
		},
		ContinueChain: false,
	}, nil
}

func (p *TarpitPlugin) handleHoneypot(req *proto.HTTPRequest, clientIP string) (*proto.HTTPResponse, error) {
	// Get trap data
	trap := p.honeypot.GetTrap(req.Path)

	// Record honeypot access
	p.metrics.RecordHoneypotAccess(clientIP, req.Path)

	log.Printf("Honeypot accessed by %s: %s (%s)", clientIP, req.Path, trap.TrapType)

	// Prepare headers
	headers := make(map[string]string)
	for k, v := range trap.Headers {
		headers[k] = v
	}
	headers["X-Tarpit-Plugin"] = fmt.Sprintf("%s/%s", PluginName, PluginVersion)
	headers["X-Honey-Token"] = generateHoneyToken()

	return &proto.HTTPResponse{
		StatusCode:    int32(trap.StatusCode),
		Body:          []byte(trap.Response),
		Headers:       headers,
		ContinueChain: false,
	}, nil
}

func (p *TarpitPlugin) getRemainingTarpitTime(conn *ConnectionInfo) time.Duration {
	timeout, _ := time.ParseDuration(p.config.ConnectionTimeout)
	elapsed := time.Since(conn.ConnectedAt)
	remaining := timeout - elapsed

	if remaining < 0 {
		return 0
	}
	return remaining
}

// Required gRPC methods

func (p *TarpitPlugin) GetInfo(ctx context.Context, req *proto.Empty) (*proto.PluginInfo, error) {
	return &proto.PluginInfo{
		Name:         PluginName,
		Version:      PluginVersion,
		Description:  "Defensive connection management with tarpit and honeypot functionality",
		Capabilities: []string{"rate_limiting", "tarpit", "honeypot", "intelligence_gathering"},
		Metadata: map[string]string{
			"priority":          fmt.Sprintf("%d", Priority),
			"tarpit_mode":       p.config.TarpitMode,
			"honeypot_enabled":  fmt.Sprintf("%t", p.config.HoneypotEnabled),
			"intelligence_mode": fmt.Sprintf("%t", p.config.IntelligenceMode),
		},
	}, nil
}

func (p *TarpitPlugin) HandleKeyChange(ctx context.Context, req *proto.KeyChangeEvent) (*proto.Event, error) {
	// Tarpit plugin doesn't typically process key changes
	eventData := map[string]string{
		"fingerprint":    req.Fingerprint,
		"tarpit_checked": "false",
	}

	dataBytes, _ := json.Marshal(eventData)

	return &proto.Event{
		Type:      "tarpit.key.skipped",
		Source:    PluginName,
		Timestamp: time.Now().Unix(),
		Data:      dataBytes,
	}, nil
}

func (p *TarpitPlugin) SubscribeEvents(req *proto.EventFilter, stream proto.HKPPlugin_SubscribeEventsServer) error {
	<-stream.Context().Done()
	return nil
}

func (p *TarpitPlugin) PublishEvent(ctx context.Context, req *proto.Event) (*proto.Empty, error) {
	// Could use events from other plugins to trigger tarpit actions
	if req.Type == "ml.abuse.detected" || req.Type == "ratelimit.violation" {
		// Extract client IP and trigger tarpit if needed
		var data map[string]interface{}
		if err := json.Unmarshal(req.Data, &data); err == nil {
			if clientIP, ok := data["client_ip"].(string); ok {
				if score, ok := data["anomaly_score"].(float64); ok && score >= p.config.AutoTarpitThreshold {
					p.connManager.AddConnection(clientIP, "auto_tarpit_trigger")
					p.metrics.RecordAutoTarpit(clientIP, score)
				}
			}
		}
	}
	return &proto.Empty{}, nil
}

func (p *TarpitPlugin) QueryStorage(ctx context.Context, req *proto.StorageQuery) (*proto.StorageResponse, error) {
	return &proto.StorageResponse{
		Success: false,
		Error:   "Storage queries not supported by tarpit plugin",
	}, nil
}

func (p *TarpitPlugin) ReportThreat(ctx context.Context, req *proto.ThreatInfo) (*proto.Empty, error) {
	// Use threat reports to trigger tarpit
	if clientIP, exists := req.Indicators["client_ip"]; exists {
		p.connManager.AddConnection(clientIP, fmt.Sprintf("threat_reported: %s", req.Type))
		p.metrics.RecordTarpit(clientIP, "threat_report")
	}
	return &proto.Empty{}, nil
}

func (p *TarpitPlugin) HealthCheck(ctx context.Context, req *proto.Empty) (*proto.HealthStatus, error) {
	status := proto.HealthStatus_HEALTHY
	message := "Tarpit plugin is healthy"

	// Check active connections
	activeConnections := p.connManager.GetActiveCount()
	if activeConnections > p.config.MaxConcurrentTarpits {
		status = proto.HealthStatus_DEGRADED
		message = "Too many active tarpit connections"
	}

	return &proto.HealthStatus{
		Status:    status,
		Message:   message,
		Timestamp: time.Now().Unix(),
		Details: map[string]string{
			"enabled":              fmt.Sprintf("%t", p.config.Enabled),
			"active_tarpits":       fmt.Sprintf("%d", activeConnections),
			"honeypot_enabled":     fmt.Sprintf("%t", p.config.HoneypotEnabled),
			"intelligence_mode":    fmt.Sprintf("%t", p.config.IntelligenceMode),
			"tarpit_mode":          p.config.TarpitMode,
			"max_concurrent":       fmt.Sprintf("%d", p.config.MaxConcurrentTarpits),
			"total_tarpitted":      fmt.Sprintf("%d", p.metrics.GetTarpittedCount()),
			"honeypot_accesses":    fmt.Sprintf("%d", p.metrics.GetHoneypotCount()),
		},
	}, nil
}

func (p *TarpitPlugin) Shutdown(ctx context.Context, req *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	log.Printf("Tarpit plugin shutting down...")

	// Drain all active connections
	p.connManager.DrainAll()

	return &proto.ShutdownResponse{Success: true}, nil
}

func main() {
	// Get gRPC address from environment
	address := os.Getenv("PLUGIN_GRPC_ADDRESS")
	if address == "" {
		address = "localhost:50006"
	}

	// Create listener
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create and register plugin
	plugin := NewTarpitPlugin()
	proto.RegisterHKPPluginServer(grpcServer, plugin)

	// Register health service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	log.Printf("Tarpit gRPC plugin starting on %s", address)

	// Start serving
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}