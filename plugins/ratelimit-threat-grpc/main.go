// Threat Intelligence Rate Limiting Plugin - gRPC Implementation
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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
	PluginName    = "ratelimit-threat-intel"
	PluginVersion = "1.0.0"
	Priority      = 15
)

// ThreatIntelPlugin implements gRPC-based threat intelligence integration
type ThreatIntelPlugin struct {
	proto.UnimplementedHKPPluginServer
	config         *ThreatIntelConfig
	feedManager    *ThreatFeedManager
	ipReputation   *IPReputationService
	threatMatcher  *ThreatMatcher
	blocklistCache *BlocklistCache
	metrics        *ThreatMetrics
	mu             sync.RWMutex
}

// ThreatIntelConfig holds configuration
type ThreatIntelConfig struct {
	Enabled             bool               `json:"enabled"`
	ThreatFeeds         []ThreatFeedConfig `json:"threat_feeds"`
	UpdateInterval      string             `json:"update_interval"`
	CacheSize           int                `json:"cache_size"`
	BlockDuration       string             `json:"block_duration"`
	ReputationThreshold float64            `json:"reputation_threshold"`
	AutoBlock           bool               `json:"auto_block"`
	ShareThreatData     bool               `json:"share_threat_data"`
	LocalBlocklist      string             `json:"local_blocklist"`
}

// ThreatFeedConfig defines a threat intelligence feed
type ThreatFeedConfig struct {
	Name       string            `json:"name"`
	URL        string            `json:"url"`
	Type       string            `json:"type"`   // ip, domain, hash, pattern
	Format     string            `json:"format"` // csv, json, txt
	UpdateFreq string            `json:"update_freq"`
	Enabled    bool              `json:"enabled"`
	APIKey     string            `json:"api_key,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// ThreatIndicator represents a threat indicator
type ThreatIndicator struct {
	Value       string
	Type        string // ip, domain, url, hash, pattern
	ThreatType  string // malware, phishing, spam, botnet, scanner
	Severity    string // low, medium, high, critical
	Confidence  float64
	Source      string
	FirstSeen   time.Time
	LastSeen    time.Time
	Tags        []string
	Description string
}

// IPReputation represents IP reputation data
type IPReputation struct {
	IP              string
	ReputationScore float64 // 0-1, where 0 is worst
	Categories      []string
	ThreatLevel     string
	LastActivity    time.Time
	Reports         int
	Sources         []string
}

// NewThreatIntelPlugin creates a new threat intelligence plugin
func NewThreatIntelPlugin() *ThreatIntelPlugin {
	config := &ThreatIntelConfig{
		Enabled:             true,
		UpdateInterval:      "1h",
		CacheSize:           100000,
		BlockDuration:       "24h",
		ReputationThreshold: 0.3,
		AutoBlock:           true,
		ShareThreatData:     false,
		ThreatFeeds: []ThreatFeedConfig{
			{
				Name:       "EmergingThreats",
				URL:        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
				Type:       "ip",
				Format:     "txt",
				UpdateFreq: "1h",
				Enabled:    true,
			},
		},
	}

	return &ThreatIntelPlugin{
		config:         config,
		feedManager:    NewThreatFeedManager(config.ThreatFeeds),
		ipReputation:   NewIPReputationService(),
		threatMatcher:  NewThreatMatcher(),
		blocklistCache: NewBlocklistCache(config.CacheSize),
		metrics:        NewThreatMetrics(),
	}
}

// Initialize implements the gRPC HKPPlugin interface
func (p *ThreatIntelPlugin) Initialize(ctx context.Context, req *proto.InitRequest) (*proto.InitResponse, error) {
	// Parse configuration
	if req.ConfigJson != "" {
		if err := json.Unmarshal([]byte(req.ConfigJson), p.config); err != nil {
			return &proto.InitResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to parse config: %v", err),
			}, nil
		}
	}

	// Initialize components with new config
	p.feedManager = NewThreatFeedManager(p.config.ThreatFeeds)
	p.blocklistCache = NewBlocklistCache(p.config.CacheSize)

	// Load local blocklist if specified
	if p.config.LocalBlocklist != "" {
		if err := p.loadLocalBlocklist(); err != nil {
			return &proto.InitResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to load local blocklist: %v", err),
			}, nil
		}
	}

	// Start background feed updates
	go p.runFeedUpdates(ctx)
	go p.runReputationUpdates(ctx)

	log.Printf("Threat Intelligence plugin initialized - enabled: %t, feeds: %d, auto_block: %t",
		p.config.Enabled, len(p.config.ThreatFeeds), p.config.AutoBlock)

	return &proto.InitResponse{
		Success: true,
		Info: &proto.PluginInfo{
			Name:         PluginName,
			Version:      PluginVersion,
			Description:  "Threat intelligence integration for enhanced rate limiting",
			Capabilities: []string{"rate_limiting", "threat_intelligence", "ip_reputation", "blocklist"},
		},
	}, nil
}

// HandleHTTPRequest implements HTTP request processing with threat intelligence
func (p *ThreatIntelPlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
	// Skip if not enabled
	if !p.config.Enabled {
		return &proto.HTTPResponse{
			StatusCode:    200,
			ContinueChain: true,
		}, nil
	}

	// Extract client IP
	clientIP := p.extractClientIP(req)

	// Check blocklist cache first
	if blocked, threat := p.blocklistCache.IsBlocked(clientIP); blocked {
		p.metrics.RecordBlock(clientIP, threat)
		return p.respondToThreat(threat)
	}

	// Check IP reputation
	reputation := p.ipReputation.GetReputation(clientIP)
	if reputation != nil && reputation.ReputationScore < p.config.ReputationThreshold {
		if p.config.AutoBlock {
			p.blockIP(clientIP, reputation)
			return p.respondToLowReputation(reputation)
		}
	}

	// Check request patterns against threat indicators
	if threats := p.threatMatcher.MatchRequest(req); len(threats) > 0 {
		return p.handleMatchedThreats(clientIP, threats)
	}

	// Add threat intelligence headers
	headers := p.createThreatHeaders(clientIP, reputation)

	return &proto.HTTPResponse{
		StatusCode:    200,
		Headers:       headers,
		ContinueChain: true,
	}, nil
}

// CheckRateLimit implements threat-based rate limiting
func (p *ThreatIntelPlugin) CheckRateLimit(ctx context.Context, req *proto.RateLimitCheck) (*proto.RateLimitResponse, error) {
	if !p.config.Enabled {
		return &proto.RateLimitResponse{Allowed: true}, nil
	}

	clientIP := req.Identifier

	// Check if IP is blocked by threat intelligence
	if blocked, threat := p.blocklistCache.IsBlocked(clientIP); blocked {
		return &proto.RateLimitResponse{
			Allowed:           false,
			RetryAfterSeconds: int32(p.getRemainingBlockTime(threat).Seconds()),
			Reason:            fmt.Sprintf("Blocked by threat intelligence: %s", threat.ThreatType),
		}, nil
	}

	// Check reputation
	reputation := p.ipReputation.GetReputation(clientIP)
	if reputation != nil && reputation.ReputationScore < p.config.ReputationThreshold {
		return &proto.RateLimitResponse{
			Allowed: false,
			Reason:  fmt.Sprintf("Low reputation score: %.2f", reputation.ReputationScore),
		}, nil
	}

	return &proto.RateLimitResponse{Allowed: true}, nil
}

// Helper methods

func (p *ThreatIntelPlugin) extractClientIP(req *proto.HTTPRequest) string {
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

func (p *ThreatIntelPlugin) respondToThreat(threat *ThreatIndicator) (*proto.HTTPResponse, error) {
	headers := map[string]string{
		"X-Threat-Plugin":   fmt.Sprintf("%s/%s", PluginName, PluginVersion),
		"X-Threat-Detected": "true",
		"X-Threat-Type":     threat.ThreatType,
		"X-Threat-Severity": threat.Severity,
		"X-Threat-Source":   threat.Source,
	}

	statusCode := int32(403)
	message := "Access denied: Threat detected"

	if threat.Severity == "critical" {
		statusCode = 403
		message = "Access denied: Critical threat detected"
	}

	return &proto.HTTPResponse{
		StatusCode:    statusCode,
		Body:          []byte(message),
		Headers:       headers,
		ContinueChain: false,
	}, nil
}

func (p *ThreatIntelPlugin) respondToLowReputation(reputation *IPReputation) (*proto.HTTPResponse, error) {
	headers := map[string]string{
		"X-Threat-Plugin":    fmt.Sprintf("%s/%s", PluginName, PluginVersion),
		"X-Reputation-Score": fmt.Sprintf("%.2f", reputation.ReputationScore),
		"X-Threat-Level":     reputation.ThreatLevel,
		"X-Reputation-Block": "true",
	}

	return &proto.HTTPResponse{
		StatusCode:    403,
		Body:          []byte("Access denied: Low reputation score"),
		Headers:       headers,
		ContinueChain: false,
	}, nil
}

func (p *ThreatIntelPlugin) blockIP(ip string, reputation *IPReputation) {
	duration, _ := time.ParseDuration(p.config.BlockDuration)

	threat := &ThreatIndicator{
		Value:       ip,
		Type:        "ip",
		ThreatType:  "low_reputation",
		Severity:    reputation.ThreatLevel,
		Confidence:  1.0 - reputation.ReputationScore,
		Source:      "reputation_service",
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		Description: fmt.Sprintf("Low reputation score: %.2f", reputation.ReputationScore),
	}

	p.blocklistCache.AddBlock(ip, threat, duration)
}

func (p *ThreatIntelPlugin) handleMatchedThreats(ip string, threats []*ThreatIndicator) (*proto.HTTPResponse, error) {
	// Find highest severity threat
	var mostSevere *ThreatIndicator
	severityOrder := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

	for _, threat := range threats {
		if mostSevere == nil || severityOrder[threat.Severity] > severityOrder[mostSevere.Severity] {
			mostSevere = threat
		}
	}

	// Block if severe enough
	if severityOrder[mostSevere.Severity] >= 3 {
		duration, _ := time.ParseDuration(p.config.BlockDuration)
		p.blocklistCache.AddBlock(ip, mostSevere, duration)
	}

	// Update reputation
	p.ipReputation.UpdateReputation(ip, ReputationUpdate{
		Type:   "threat_detected",
		Source: "pattern_matcher",
	})

	// Record metrics
	p.metrics.RecordThreatMatch(ip, threats)

	// Respond
	return p.respondToThreat(mostSevere)
}

func (p *ThreatIntelPlugin) createThreatHeaders(ip string, reputation *IPReputation) map[string]string {
	headers := map[string]string{
		"X-Threat-Plugin": fmt.Sprintf("%s/%s", PluginName, PluginVersion),
		"X-Threat-Check":  "passed",
	}

	if reputation != nil {
		headers["X-IP-Reputation"] = fmt.Sprintf("%.2f", reputation.ReputationScore)
		headers["X-Threat-Level"] = reputation.ThreatLevel
	}

	return headers
}

func (p *ThreatIntelPlugin) loadLocalBlocklist() error {
	// Example local blocklist entries
	exampleThreats := []struct {
		ip         string
		threatType string
		severity   string
	}{
		{"192.0.2.1", "scanner", "high"},
		{"198.51.100.1", "botnet", "critical"},
		{"203.0.113.1", "spam", "medium"},
	}

	for _, ex := range exampleThreats {
		threat := &ThreatIndicator{
			Value:      ex.ip,
			Type:       "ip",
			ThreatType: ex.threatType,
			Severity:   ex.severity,
			Confidence: 0.9,
			Source:     "local_blocklist",
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
		}

		duration, _ := time.ParseDuration(p.config.BlockDuration)
		p.blocklistCache.AddBlock(ex.ip, threat, duration)
	}

	return nil
}

func (p *ThreatIntelPlugin) getRemainingBlockTime(threat *ThreatIndicator) time.Duration {
	// Simplified - in production would track actual expiry
	duration, _ := time.ParseDuration(p.config.BlockDuration)
	return duration
}

// Background tasks

func (p *ThreatIntelPlugin) runFeedUpdates(ctx context.Context) {
	interval, _ := time.ParseDuration(p.config.UpdateInterval)
	if interval == 0 {
		interval = 1 * time.Hour
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial update
	if err := p.feedManager.UpdateFeeds(); err != nil {
		log.Printf("Initial feed update failed: %v", err)
	}

	for {
		select {
		case <-ticker.C:
			if err := p.feedManager.UpdateFeeds(); err != nil {
				log.Printf("Scheduled feed update failed: %v", err)
				p.metrics.RecordError("feed_update", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (p *ThreatIntelPlugin) runReputationUpdates(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanupExpiredEntries()
		case <-ctx.Done():
			return
		}
	}
}

func (p *ThreatIntelPlugin) cleanupExpiredEntries() {
	// Clean blocklist cache
	p.blocklistCache.mu.Lock()
	now := time.Now()
	for ip, entry := range p.blocklistCache.entries {
		if now.After(entry.ExpiresAt) {
			delete(p.blocklistCache.entries, ip)
		}
	}
	p.blocklistCache.mu.Unlock()

	// Clean old reputation data
	p.ipReputation.mu.Lock()
	cutoff := now.Add(-7 * 24 * time.Hour) // 7 days
	for ip, rep := range p.ipReputation.reputations {
		if rep.LastActivity.Before(cutoff) && rep.ReputationScore > 0.5 {
			delete(p.ipReputation.reputations, ip)
		}
	}
	p.ipReputation.mu.Unlock()
}

// Required gRPC methods

func (p *ThreatIntelPlugin) GetInfo(ctx context.Context, req *proto.Empty) (*proto.PluginInfo, error) {
	return &proto.PluginInfo{
		Name:         PluginName,
		Version:      PluginVersion,
		Description:  "Threat intelligence integration for enhanced rate limiting",
		Capabilities: []string{"rate_limiting", "threat_intelligence", "ip_reputation", "blocklist"},
		Metadata: map[string]string{
			"priority":             fmt.Sprintf("%d", Priority),
			"reputation_threshold": fmt.Sprintf("%.2f", p.config.ReputationThreshold),
			"auto_block":           fmt.Sprintf("%t", p.config.AutoBlock),
			"feeds_configured":     fmt.Sprintf("%d", len(p.config.ThreatFeeds)),
			"update_interval":      p.config.UpdateInterval,
		},
	}, nil
}

func (p *ThreatIntelPlugin) HandleKeyChange(ctx context.Context, req *proto.KeyChangeEvent) (*proto.Event, error) {
	// Threat intelligence doesn't typically process key changes directly
	eventData := map[string]string{
		"fingerprint":    req.Fingerprint,
		"threat_checked": "false",
	}

	dataBytes, _ := json.Marshal(eventData)

	return &proto.Event{
		Type:      "threat-intel.key.skipped",
		Source:    PluginName,
		Timestamp: time.Now().Unix(),
		Data:      dataBytes,
	}, nil
}

func (p *ThreatIntelPlugin) SubscribeEvents(req *proto.EventFilter, stream proto.HKPPlugin_SubscribeEventsServer) error {
	<-stream.Context().Done()
	return nil
}

func (p *ThreatIntelPlugin) PublishEvent(ctx context.Context, req *proto.Event) (*proto.Empty, error) {
	// Process relevant events
	if req.Type == "security.threat.detected" || req.Type == "ratelimit.violation" {
		var data map[string]interface{}
		if err := json.Unmarshal(req.Data, &data); err == nil {
			if clientIP, ok := data["client_ip"].(string); ok {
				// Update reputation based on event
				updateType := "threat_detected"
				if req.Type == "ratelimit.violation" {
					updateType = "rate_limit_violation"
				}

				p.ipReputation.UpdateReputation(clientIP, ReputationUpdate{
					Type:   updateType,
					Source: req.Source,
				})
			}
		}
	}
	return &proto.Empty{}, nil
}

func (p *ThreatIntelPlugin) QueryStorage(ctx context.Context, req *proto.StorageQuery) (*proto.StorageResponse, error) {
	return &proto.StorageResponse{
		Success: false,
		Error:   "Storage queries not supported by threat intelligence plugin",
	}, nil
}

func (p *ThreatIntelPlugin) ReportThreat(ctx context.Context, req *proto.ThreatInfo) (*proto.Empty, error) {
	// Process threat reports
	if clientIP, exists := req.Indicators["client_ip"]; exists {
		// Determine severity and confidence from threat type
		severity := "medium"
		confidence := 0.7

		// Map threat types to severity levels
		switch req.Type {
		case "malware", "botnet":
			severity = "critical"
			confidence = 0.9
		case "scanner", "brute_force":
			severity = "high"
			confidence = 0.8
		case "spam", "phishing":
			severity = "medium"
			confidence = 0.7
		}

		// Create threat indicator
		threat := &ThreatIndicator{
			Value:       clientIP,
			Type:        "ip",
			ThreatType:  req.Type,
			Severity:    severity,
			Confidence:  confidence,
			Source:      "threat_report",
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Description: req.Description,
		}

		// Add to blocklist if severe enough
		if severity == "high" || severity == "critical" {
			duration, _ := time.ParseDuration(p.config.BlockDuration)
			p.blocklistCache.AddBlock(clientIP, threat, duration)
		}

		// Update reputation
		p.ipReputation.UpdateReputation(clientIP, ReputationUpdate{
			Type:   "threat_detected",
			Source: "threat_report",
		})

		// Share threat data if enabled
		if p.config.ShareThreatData {
			log.Printf("Sharing threat intelligence: %s (%s)", clientIP, req.Type)
		}
	}

	return &proto.Empty{}, nil
}

func (p *ThreatIntelPlugin) HealthCheck(ctx context.Context, req *proto.Empty) (*proto.HealthStatus, error) {
	status := proto.HealthStatus_HEALTHY
	message := "Threat intelligence plugin is healthy"

	// Check feed manager
	feedCount := len(p.config.ThreatFeeds)
	indicatorCount := p.feedManager.GetIndicatorCount()

	// Check blocklist cache
	activeBlocks := p.blocklistCache.GetActiveCount()
	reputationCount := p.ipReputation.GetReputationCount()

	return &proto.HealthStatus{
		Status:    status,
		Message:   message,
		Timestamp: time.Now().Unix(),
		Details: map[string]string{
			"enabled":              fmt.Sprintf("%t", p.config.Enabled),
			"feeds_configured":     fmt.Sprintf("%d", feedCount),
			"threat_indicators":    fmt.Sprintf("%d", indicatorCount),
			"active_blocks":        fmt.Sprintf("%d", activeBlocks),
			"tracked_ips":          fmt.Sprintf("%d", reputationCount),
			"auto_block":           fmt.Sprintf("%t", p.config.AutoBlock),
			"reputation_threshold": fmt.Sprintf("%.2f", p.config.ReputationThreshold),
		},
	}, nil
}

func (p *ThreatIntelPlugin) Shutdown(ctx context.Context, req *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	log.Printf("Threat intelligence plugin shutting down...")

	// Save state
	if err := p.blocklistCache.SaveState(); err != nil {
		log.Printf("Failed to save blocklist state: %v", err)
	}

	return &proto.ShutdownResponse{Success: true}, nil
}

func main() {
	// Get gRPC address from environment
	address := os.Getenv("PLUGIN_GRPC_ADDRESS")
	if address == "" {
		address = "localhost:50005"
	}

	// Create listener
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create and register plugin
	plugin := NewThreatIntelPlugin()
	proto.RegisterHKPPluginServer(grpcServer, plugin)

	// Register health service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	log.Printf("Threat Intelligence gRPC plugin starting on %s", address)

	// Start serving
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
