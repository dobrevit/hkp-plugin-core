// Package ratelimitthreat provides threat intelligence integration for rate limiting
package ratelimitthreat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	log "github.com/sirupsen/logrus"

	"gopkg.in/tomb.v2"
)

// Plugin constants
const (
	PluginName        = "ratelimit-threat-intel"
	PluginVersion     = "1.0.0"
	PluginDescription = "Threat intelligence integration for enhanced rate limiting"
	PluginPriority    = 30
)

// ThreatIntelPlugin integrates threat intelligence feeds with rate limiting
type ThreatIntelPlugin struct {
	host           plugin.PluginHost
	config         *ThreatIntelConfig
	feedManager    *ThreatFeedManager
	ipReputation   *IPReputationService
	threatMatcher  *ThreatMatcher
	blocklistCache *BlocklistCache
	metrics        *ThreatMetrics
	mu             sync.RWMutex
	tomb           tomb.Tomb
}

// ThreatIntelConfig holds configuration
type ThreatIntelConfig struct {
	Enabled             bool               `json:"enabled"`
	ThreatFeeds         []ThreatFeedConfig `json:"threatFeeds"`
	UpdateInterval      string             `json:"updateInterval"`
	CacheSize           int                `json:"cacheSize"`
	BlockDuration       string             `json:"blockDuration"`
	ReputationThreshold float64            `json:"reputationThreshold"`
	AutoBlock           bool               `json:"autoBlock"`
	ShareThreatData     bool               `json:"shareThreatData"`
	LocalBlocklist      string             `json:"localBlocklist"`
}

// ThreatFeedConfig defines a threat intelligence feed
type ThreatFeedConfig struct {
	Name       string            `json:"name"`
	URL        string            `json:"url"`
	Type       string            `json:"type"`   // ip, domain, hash, pattern
	Format     string            `json:"format"` // csv, json, txt
	UpdateFreq string            `json:"updateFreq"`
	Enabled    bool              `json:"enabled"`
	APIKey     string            `json:"apiKey,omitempty"`
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

// Initialize implements the Plugin interface
func (p *ThreatIntelPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
	// Debug: Log raw configuration received
	host.Logger().Debug("ThreatIntelPlugin Initialize called", "config", config)

	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	p.config = &ThreatIntelConfig{
		Enabled:             true,
		UpdateInterval:      "1h",
		CacheSize:           100000,
		BlockDuration:       "24h",
		ReputationThreshold: 0.3,
		AutoBlock:           true,
		ShareThreatData:     false,
	}

	if err := json.Unmarshal(configBytes, p.config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Debug: Log parsed configuration
	host.Logger().Debug("ThreatIntelPlugin config parsed",
		"enabled", p.config.Enabled,
		"numThreatFeeds", len(p.config.ThreatFeeds),
		"updateInterval", p.config.UpdateInterval,
		"autoBlock", p.config.AutoBlock,
		"reputationThreshold", p.config.ReputationThreshold)

	// Debug: Log individual threat feeds
	for i, feed := range p.config.ThreatFeeds {
		host.Logger().Debug("Threat feed configured",
			"index", i,
			"name", feed.Name,
			"url", feed.URL,
			"type", feed.Type,
			"enabled", feed.Enabled,
			"updateFreq", feed.UpdateFreq)
	}

	p.host = host

	// Initialize components
	p.feedManager = NewThreatFeedManager(p.config.ThreatFeeds, p.host.Logger())
	p.ipReputation = NewIPReputationService()
	p.threatMatcher = NewThreatMatcher()
	p.blocklistCache = NewBlocklistCache(p.config.CacheSize)
	p.metrics = NewThreatMetrics()

	// Load local blocklist if specified
	if p.config.LocalBlocklist != "" {
		if err := p.loadLocalBlocklist(); err != nil {
			return fmt.Errorf("failed to load local blocklist: %w", err)
		}
	}

	// Register middleware
	middleware, err := p.CreateMiddleware()
	if err != nil {
		return fmt.Errorf("failed to create middleware: %w", err)
	}

	if err := host.RegisterMiddleware("/", middleware); err != nil {
		return fmt.Errorf("failed to register middleware: %w", err)
	}

	// Register endpoints
	host.RegisterHandler("/ratelimit/threatintel/status", p.handleStatus)
	host.RegisterHandler("/ratelimit/threatintel/check", p.handleCheck)
	host.RegisterHandler("/ratelimit/threatintel/report", p.handleReport)

	// Start background tasks
	host.Logger().Debug("Starting background tasks for ThreatIntelPlugin")

	p.tomb.Go(func() error {
		host.Logger().Debug("Starting runFeedUpdates goroutine")
		return p.runFeedUpdates(ctx)
	})

	p.tomb.Go(func() error {
		host.Logger().Debug("Starting runReputationUpdates goroutine")
		return p.runReputationUpdates(ctx)
	})

	host.Logger().Debug("Background tasks started successfully")

	// Subscribe to events
	host.SubscribeEvent("security.threat.detected", p.handleThreatDetected)
	host.SubscribeEvent("ratelimit.violation", p.handleRateLimitViolation)

	host.Logger().Info("ThreatIntelPlugin initialized successfully",
		"enabled", p.config.Enabled,
		"numFeeds", len(p.config.ThreatFeeds),
		"backgroundTasksStarted", true)

	return nil
}

// Name returns the plugin name
func (p *ThreatIntelPlugin) Name() string {
	return PluginName
}

// Version returns the plugin version
func (p *ThreatIntelPlugin) Version() string {
	return PluginVersion
}

// Description returns the plugin description
func (p *ThreatIntelPlugin) Description() string {
	return "Threat intelligence integration for enhanced rate limiting"
}

// Dependencies returns required dependencies
func (p *ThreatIntelPlugin) Dependencies() []plugin.PluginDependency {
	// No dependencies for this standalone plugin
	return []plugin.PluginDependency{}
}

// Shutdown gracefully stops the plugin
func (p *ThreatIntelPlugin) Shutdown(ctx context.Context) error {
	// Signal shutdown to all goroutines
	p.tomb.Kill(nil)

	// Wait for all goroutines to finish with context timeout
	done := make(chan error, 1)
	go func() {
		done <- p.tomb.Wait()
	}()

	select {
	case err := <-done:
		// Save state before returning
		if saveErr := p.blocklistCache.SaveState(); saveErr != nil {
			p.host.Logger().Error("Failed to save blocklist state during shutdown", "error", saveErr)
		}
		return err
	case <-ctx.Done():
		// Timeout - return error
		return fmt.Errorf("plugin shutdown timed out")
	}
}

// CreateMiddleware creates the threat intelligence middleware
func (p *ThreatIntelPlugin) CreateMiddleware() (func(http.Handler) http.Handler, error) {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := p.extractClientIP(r)

			// Check blocklist cache first
			if blocked, threat := p.blocklistCache.IsBlocked(clientIP); blocked {
				p.metrics.RecordBlock(clientIP, threat)
				p.respondToThreat(w, r, threat)
				return
			}

			// Check IP reputation
			reputation := p.ipReputation.GetReputation(clientIP)
			if reputation != nil && reputation.ReputationScore < p.config.ReputationThreshold {
				if p.config.AutoBlock {
					p.blockIP(clientIP, reputation)
					p.respondToLowReputation(w, r, reputation)
					return
				}
			}

			// Check request patterns against threat indicators
			if threats := p.threatMatcher.MatchRequest(r); len(threats) > 0 {
				p.handleMatchedThreats(clientIP, threats, w, r)
				return
			}

			// Add threat intelligence headers
			p.addThreatHeaders(w, clientIP, reputation)

			// Continue with request
			next.ServeHTTP(w, r)
		})
	}, nil
}

// ThreatFeedManager manages threat intelligence feeds
type ThreatFeedManager struct {
	feeds      []ThreatFeedConfig
	indicators map[string]*ThreatIndicator
	lastUpdate map[string]time.Time
	httpClient *http.Client
	mu         sync.RWMutex
	logger     *log.Logger
}

func NewThreatFeedManager(feeds []ThreatFeedConfig, logger *log.Logger) *ThreatFeedManager {
	return &ThreatFeedManager{
		feeds:      feeds,
		indicators: make(map[string]*ThreatIndicator),
		lastUpdate: make(map[string]time.Time),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

func (tfm *ThreatFeedManager) UpdateFeeds() error {
	tfm.logger.Debug("UpdateFeeds triggered", "totalFeeds", len(tfm.feeds))

	for _, feed := range tfm.feeds {
		if !feed.Enabled {
			tfm.logger.Debug("Skipping disabled feed", "feedName", feed.Name)
			continue
		}

		// Check update frequency
		if lastUpdate, exists := tfm.lastUpdate[feed.Name]; exists {
			updateFreq, _ := time.ParseDuration(feed.UpdateFreq)
			if time.Since(lastUpdate) < updateFreq {
				tfm.logger.Debug("Skipping feed - not time to update yet",
					"feedName", feed.Name,
					"lastUpdate", lastUpdate,
					"updateFreq", updateFreq,
					"timeSinceLastUpdate", time.Since(lastUpdate))
				continue
			}
		}

		// Update feed
		tfm.logger.Debug("Attempting to update feed", "feedName", feed.Name, "url", feed.URL)

		if err := tfm.updateFeed(feed); err != nil {
			// Log error but continue with other feeds
			tfm.logger.Error("Failed to update feed", "feed", feed.Name, "error", err)
			continue
		}

		tfm.lastUpdate[feed.Name] = time.Now()
		tfm.logger.Debug("Feed updated successfully", "feedName", feed.Name, "updateTime", time.Now())
	}

	tfm.logger.Debug("UpdateFeeds completed", "totalIndicators", len(tfm.indicators))
	return nil
}

func (tfm *ThreatFeedManager) updateFeed(feed ThreatFeedConfig) error {
	tfm.logger.Debug("updateFeed called", "feedName", feed.Name, "url", feed.URL, "type", feed.Type)

	// Create request
	req, err := http.NewRequest("GET", feed.URL, nil)
	if err != nil {
		tfm.logger.Error("Failed to create request", "feedName", feed.Name, "error", err)
		return err
	}

	// Add headers
	for k, v := range feed.Headers {
		req.Header.Set(k, v)
	}

	// Add API key if specified
	if feed.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+feed.APIKey)
	}

	// Make request
	tfm.logger.Debug("Making HTTP request to feed", "feedName", feed.Name, "url", feed.URL)

	resp, err := tfm.httpClient.Do(req)
	if err != nil {
		tfm.logger.Error("HTTP request failed", "feedName", feed.Name, "error", err)
		return err
	}
	defer resp.Body.Close()

	tfm.logger.Debug("Feed response received", "feedName", feed.Name, "statusCode", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		tfm.logger.Error("Feed returned non-OK status", "feedName", feed.Name, "statusCode", resp.StatusCode)
		return fmt.Errorf("feed returned status %d", resp.StatusCode)
	}

	// Parse feed based on format
	tfm.logger.Debug("Parsing feed data", "feedName", feed.Name, "format", feed.Format)

	indicators, err := tfm.parseFeed(feed, resp.Body)
	if err != nil {
		tfm.logger.Error("Failed to parse feed", "feedName", feed.Name, "error", err)
		return err
	}

	tfm.logger.Debug("Feed parsed successfully", "feedName", feed.Name, "indicatorCount", len(indicators))

	// Update indicators
	tfm.mu.Lock()
	for _, indicator := range indicators {
		tfm.indicators[indicator.Value] = indicator
	}
	tfm.mu.Unlock()

	return nil
}

func (tfm *ThreatFeedManager) parseFeed(feed ThreatFeedConfig, reader io.Reader) ([]*ThreatIndicator, error) {
	var indicators []*ThreatIndicator

	switch feed.Format {
	case "json-array":
		// Parse JSON array feed
		var data []string
		if err := json.NewDecoder(reader).Decode(&data); err != nil {
			return nil, fmt.Errorf("failed to decode JSON array: %w", err)
		}
		for _, value := range data {
			indicator := &ThreatIndicator{
				Value:      value,
				Type:       feed.Type,
				ThreatType: "generic",
				Severity:   "medium",
				Confidence: 0.7,
				Source:     feed.Name,
				FirstSeen:  time.Now(),
				LastSeen:   time.Now(),
			}
			indicators = append(indicators, indicator)
		}

	case "json":
		// Parse JSON feed
		var data []map[string]interface{}
		if err := json.NewDecoder(reader).Decode(&data); err != nil {
			return nil, err
		}

		for _, item := range data {
			indicator := &ThreatIndicator{
				Type:      feed.Type,
				Source:    feed.Name,
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
			}

			// Extract fields based on feed schema
			if val, ok := item["ip"].(string); ok {
				indicator.Value = val
			}
			if val, ok := item["threat_type"].(string); ok {
				indicator.ThreatType = val
			}
			if val, ok := item["severity"].(string); ok {
				indicator.Severity = val
			}
			if val, ok := item["confidence"].(float64); ok {
				indicator.Confidence = val
			}

			indicators = append(indicators, indicator)
		}

	case "csv":
		// Parse CSV feed (simplified)
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}

		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue // Skip header and empty lines
			}

			parts := strings.Split(line, ",")
			if len(parts) > 0 {
				indicator := &ThreatIndicator{
					Value:      strings.TrimSpace(parts[0]),
					Type:       feed.Type,
					ThreatType: "generic",
					Severity:   "medium",
					Confidence: 0.7,
					Source:     feed.Name,
					FirstSeen:  time.Now(),
					LastSeen:   time.Now(),
				}
				indicators = append(indicators, indicator)
			}
		}

	case "txt":
		// Parse text file (one indicator per line)
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				indicator := &ThreatIndicator{
					Value:      line,
					Type:       feed.Type,
					ThreatType: "generic",
					Severity:   "medium",
					Confidence: 0.7,
					Source:     feed.Name,
					FirstSeen:  time.Now(),
					LastSeen:   time.Now(),
				}
				indicators = append(indicators, indicator)
			}
		}
	}

	return indicators, nil
}

// IPReputationService manages IP reputation data
type IPReputationService struct {
	reputations map[string]*IPReputation
	mu          sync.RWMutex
}

func NewIPReputationService() *IPReputationService {
	return &IPReputationService{
		reputations: make(map[string]*IPReputation),
	}
}

func (irs *IPReputationService) GetReputation(ip string) *IPReputation {
	irs.mu.RLock()
	defer irs.mu.RUnlock()

	if rep, exists := irs.reputations[ip]; exists {
		return rep
	}

	// Check if IP is in private range (always good reputation)
	if isPrivateIP(ip) {
		return &IPReputation{
			IP:              ip,
			ReputationScore: 1.0,
			ThreatLevel:     "none",
			Categories:      []string{"private"},
		}
	}

	return nil
}

func (irs *IPReputationService) UpdateReputation(ip string, update ReputationUpdate) {
	irs.mu.Lock()
	defer irs.mu.Unlock()

	rep, exists := irs.reputations[ip]
	if !exists {
		rep = &IPReputation{
			IP:           ip,
			LastActivity: time.Now(),
		}
		irs.reputations[ip] = rep
	}

	// Update reputation based on event
	switch update.Type {
	case "threat_detected":
		rep.ReputationScore *= 0.8
		rep.Reports++
		rep.ThreatLevel = calculateThreatLevel(rep.ReputationScore)

	case "rate_limit_violation":
		rep.ReputationScore *= 0.9
		rep.Reports++

	case "good_behavior":
		rep.ReputationScore = math.Min(1.0, rep.ReputationScore*1.1)
	}

	rep.LastActivity = time.Now()

	// Add source if not already present
	sourceExists := false
	for _, s := range rep.Sources {
		if s == update.Source {
			sourceExists = true
			break
		}
	}
	if !sourceExists {
		rep.Sources = append(rep.Sources, update.Source)
	}
}

type ReputationUpdate struct {
	Type   string
	Source string
	Score  float64
}

// ThreatMatcher matches requests against threat patterns
type ThreatMatcher struct {
	patterns []ThreatPattern
	mu       sync.RWMutex
}

type ThreatPattern struct {
	Name       string
	Pattern    string
	Type       string // url, header, body
	Severity   string
	Confidence float64
}

func NewThreatMatcher() *ThreatMatcher {
	tm := &ThreatMatcher{}
	tm.initializePatterns()
	return tm
}

func (tm *ThreatMatcher) initializePatterns() {
	// Initialize with common threat patterns
	tm.patterns = []ThreatPattern{
		{
			Name:       "SQL Injection",
			Pattern:    `(?i)(union|select|insert|update|delete|drop).*(?i)(from|where)`,
			Type:       "url",
			Severity:   "high",
			Confidence: 0.8,
		},
		{
			Name:       "Path Traversal",
			Pattern:    `\.\.\/|\.\.\\|%2e%2e`,
			Type:       "url",
			Severity:   "high",
			Confidence: 0.9,
		},
		{
			Name:       "Command Injection",
			Pattern:    `[;&|]|\$\(|` + "`",
			Type:       "url",
			Severity:   "critical",
			Confidence: 0.7,
		},
		{
			Name:       "Scanner Detection",
			Pattern:    `(nikto|nmap|masscan|zap|burp)`,
			Type:       "header",
			Severity:   "medium",
			Confidence: 0.9,
		},
	}
}

func (tm *ThreatMatcher) MatchRequest(r *http.Request) []*ThreatIndicator {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var threats []*ThreatIndicator

	// Check URL patterns
	urlStr := r.URL.String()
	for _, pattern := range tm.patterns {
		if pattern.Type == "url" && strings.Contains(urlStr, pattern.Pattern) {
			threat := &ThreatIndicator{
				Value:      urlStr,
				Type:       "pattern",
				ThreatType: pattern.Name,
				Severity:   pattern.Severity,
				Confidence: pattern.Confidence,
				Source:     "pattern_matcher",
				FirstSeen:  time.Now(),
				LastSeen:   time.Now(),
			}
			threats = append(threats, threat)
		}
	}

	// Check headers
	for _, pattern := range tm.patterns {
		if pattern.Type == "header" {
			for key, values := range r.Header {
				for _, value := range values {
					if strings.Contains(strings.ToLower(key+value), pattern.Pattern) {
						threat := &ThreatIndicator{
							Value:      key + ": " + value,
							Type:       "pattern",
							ThreatType: pattern.Name,
							Severity:   pattern.Severity,
							Confidence: pattern.Confidence,
							Source:     "pattern_matcher",
							FirstSeen:  time.Now(),
							LastSeen:   time.Now(),
						}
						threats = append(threats, threat)
					}
				}
			}
		}
	}

	return threats
}

// BlocklistCache manages the blocklist with efficient lookups
type BlocklistCache struct {
	entries map[string]*BlocklistEntry
	maxSize int
	mu      sync.RWMutex
}

type BlocklistEntry struct {
	IP        string
	Threat    *ThreatIndicator
	BlockedAt time.Time
	ExpiresAt time.Time
	HitCount  int64
}

func NewBlocklistCache(maxSize int) *BlocklistCache {
	return &BlocklistCache{
		entries: make(map[string]*BlocklistEntry),
		maxSize: maxSize,
	}
}

func (bc *BlocklistCache) IsBlocked(ip string) (bool, *ThreatIndicator) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if entry, exists := bc.entries[ip]; exists {
		if time.Now().Before(entry.ExpiresAt) {
			entry.HitCount++
			return true, entry.Threat
		}
		// Expired, will be cleaned up later
	}

	return false, nil
}

func (bc *BlocklistCache) AddBlock(ip string, threat *ThreatIndicator, duration time.Duration) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Check cache size
	if len(bc.entries) >= bc.maxSize {
		bc.evictOldest()
	}

	entry := &BlocklistEntry{
		IP:        ip,
		Threat:    threat,
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(duration),
		HitCount:  0,
	}

	bc.entries[ip] = entry
}

func (bc *BlocklistCache) evictOldest() {
	var oldestIP string
	var oldestTime time.Time

	for ip, entry := range bc.entries {
		if oldestIP == "" || entry.BlockedAt.Before(oldestTime) {
			oldestIP = ip
			oldestTime = entry.BlockedAt
		}
	}

	if oldestIP != "" {
		delete(bc.entries, oldestIP)
	}
}

func (bc *BlocklistCache) SaveState() error {
	// In production, would persist to disk
	return nil
}

// Helper functions

func (p *ThreatIntelPlugin) extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

func (p *ThreatIntelPlugin) respondToThreat(w http.ResponseWriter, r *http.Request, threat *ThreatIndicator) {
	// Add threat headers
	w.Header().Set("X-Threat-Detected", "true")
	w.Header().Set("X-Threat-Type", threat.ThreatType)
	w.Header().Set("X-Threat-Severity", threat.Severity)

	// Return appropriate response
	if threat.Severity == "critical" {
		http.Error(w, "Access denied: Critical threat detected", http.StatusForbidden)
	} else {
		http.Error(w, "Access denied: Threat detected", http.StatusForbidden)
	}
}

func (p *ThreatIntelPlugin) respondToLowReputation(w http.ResponseWriter, r *http.Request, reputation *IPReputation) {
	w.Header().Set("X-Reputation-Score", fmt.Sprintf("%.2f", reputation.ReputationScore))
	w.Header().Set("X-Threat-Level", reputation.ThreatLevel)

	http.Error(w, "Access denied: Low reputation score", http.StatusForbidden)
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

func (p *ThreatIntelPlugin) handleMatchedThreats(ip string, threats []*ThreatIndicator, w http.ResponseWriter, r *http.Request) {
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
	p.respondToThreat(w, r, mostSevere)
}

func (p *ThreatIntelPlugin) addThreatHeaders(w http.ResponseWriter, ip string, reputation *IPReputation) {
	if reputation != nil {
		w.Header().Set("X-IP-Reputation", fmt.Sprintf("%.2f", reputation.ReputationScore))
		w.Header().Set("X-Threat-Level", reputation.ThreatLevel)
	}
}

func (p *ThreatIntelPlugin) loadLocalBlocklist() error {
	// In production, would load from file
	// For now, add some example entries
	exampleThreats := []struct {
		ip         string
		threatType string
	}{
		{"192.0.2.1", "scanner"},
		{"198.51.100.1", "botnet"},
		{"203.0.113.1", "spam"},
	}

	for _, ex := range exampleThreats {
		threat := &ThreatIndicator{
			Value:      ex.ip,
			Type:       "ip",
			ThreatType: ex.threatType,
			Severity:   "high",
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

// Background tasks

func (p *ThreatIntelPlugin) runFeedUpdates(ctx context.Context) error {
	p.host.Logger().Debug("runFeedUpdates started")

	interval, _ := time.ParseDuration(p.config.UpdateInterval)
	if interval == 0 {
		interval = 1 * time.Hour
	}

	p.host.Logger().Debug("Feed update interval configured", "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial update
	p.host.Logger().Debug("Performing initial feed update")
	if err := p.feedManager.UpdateFeeds(); err != nil {
		p.host.Logger().Error("Initial feed update failed", "error", err)
	}

	for {
		select {
		case <-ticker.C:
			p.host.Logger().Debug("Feed update timer triggered")
			if err := p.feedManager.UpdateFeeds(); err != nil {
				p.host.Logger().Error("Scheduled feed update failed", "error", err)
				p.metrics.RecordError("feed_update", err)
			} else {
				p.host.Logger().Debug("Scheduled feed update completed successfully")
			}
		case <-p.tomb.Dying():
			p.host.Logger().Debug("runFeedUpdates stopping - tomb dying")
			return nil
		case <-ctx.Done():
			p.host.Logger().Debug("runFeedUpdates stopping - context done")
			return ctx.Err()
		}
	}
}

func (p *ThreatIntelPlugin) runReputationUpdates(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanupExpiredEntries()
		case <-p.tomb.Dying():
			return nil
		case <-ctx.Done():
			return ctx.Err()
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

// Event handlers

func (p *ThreatIntelPlugin) handleThreatDetected(event plugin.PluginEvent) error {
	data := event.Data
	if len(data) == 0 {
		return fmt.Errorf("empty event data")
	}

	ip, _ := data["client_ip"].(string)
	threatType, _ := data["threat_type"].(string)

	// Create threat indicator
	threat := &ThreatIndicator{
		Value:      ip,
		Type:       "ip",
		ThreatType: threatType,
		Severity:   "high",
		Confidence: 0.9,
		Source:     "threat_detection",
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
	}

	// Add to blocklist
	duration, _ := time.ParseDuration(p.config.BlockDuration)
	p.blocklistCache.AddBlock(ip, threat, duration)

	// Update reputation
	p.ipReputation.UpdateReputation(ip, ReputationUpdate{
		Type:   "threat_detected",
		Source: "threat_detection",
	})

	// Share threat data if enabled
	if p.config.ShareThreatData {
		p.shareThreatIntelligence(threat)
	}

	return nil
}

func (p *ThreatIntelPlugin) handleRateLimitViolation(event plugin.PluginEvent) error {
	data := event.Data
	if len(data) == 0 {
		return fmt.Errorf("empty event data")
	}

	ip, _ := data["client_ip"].(string)

	// Update reputation
	p.ipReputation.UpdateReputation(ip, ReputationUpdate{
		Type:   "rate_limit_violation",
		Source: "rate_limiter",
	})

	return nil
}

func (p *ThreatIntelPlugin) shareThreatIntelligence(threat *ThreatIndicator) {
	// In production, would share with threat intelligence network
	// For now, just log
	p.host.Logger().Info("Sharing threat intelligence", "threat", threat)
}

// HTTP handlers

func (p *ThreatIntelPlugin) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"enabled":           p.config.Enabled,
		"feeds":             len(p.config.ThreatFeeds),
		"active_blocks":     len(p.blocklistCache.entries),
		"tracked_ips":       len(p.ipReputation.reputations),
		"threat_indicators": len(p.feedManager.indicators),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (p *ThreatIntelPlugin) handleCheck(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "Missing IP parameter", http.StatusBadRequest)
		return
	}

	result := map[string]interface{}{
		"ip": ip,
	}

	// Check blocklist
	if blocked, threat := p.blocklistCache.IsBlocked(ip); blocked {
		result["blocked"] = true
		result["threat"] = threat
	} else {
		result["blocked"] = false
	}

	// Check reputation
	if rep := p.ipReputation.GetReputation(ip); rep != nil {
		result["reputation"] = rep
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (p *ThreatIntelPlugin) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var report ThreatReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Create threat indicator from report
	threat := &ThreatIndicator{
		Value:       report.IP,
		Type:        "ip",
		ThreatType:  report.ThreatType,
		Severity:    report.Severity,
		Confidence:  0.7, // User reports have moderate confidence
		Source:      "user_report",
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		Description: report.Description,
	}

	// Add to blocklist if severe enough
	if report.Severity == "high" || report.Severity == "critical" {
		duration, _ := time.ParseDuration(p.config.BlockDuration)
		p.blocklistCache.AddBlock(report.IP, threat, duration)
	}

	// Update reputation
	p.ipReputation.UpdateReputation(report.IP, ReputationUpdate{
		Type:   "user_report",
		Source: "user",
	})

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status":"accepted"}`))
}

type ThreatReport struct {
	IP          string `json:"ip"`
	ThreatType  string `json:"threat_type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// ThreatMetrics tracks threat intelligence metrics
type ThreatMetrics struct {
	blockedIPs      int64
	threatsDetected int64
	feedUpdates     int64
	errors          map[string]int64
	threatsByType   map[string]int64
	mu              sync.RWMutex
}

func NewThreatMetrics() *ThreatMetrics {
	return &ThreatMetrics{
		errors:        make(map[string]int64),
		threatsByType: make(map[string]int64),
	}
}

func (tm *ThreatMetrics) RecordBlock(ip string, threat *ThreatIndicator) {
	atomic.AddInt64(&tm.blockedIPs, 1)

	tm.mu.Lock()
	tm.threatsByType[threat.ThreatType]++
	tm.mu.Unlock()
}

func (tm *ThreatMetrics) RecordRateLimit(ip string, reason string) {
	atomic.AddInt64(&tm.threatsDetected, 1)
}

func (tm *ThreatMetrics) RecordThreatMatch(ip string, threats []*ThreatIndicator) {
	atomic.AddInt64(&tm.threatsDetected, int64(len(threats)))

	tm.mu.Lock()
	for _, threat := range threats {
		tm.threatsByType[threat.ThreatType]++
	}
	tm.mu.Unlock()
}

func (tm *ThreatMetrics) RecordError(errorType string, err error) {
	tm.mu.Lock()
	tm.errors[errorType]++
	tm.mu.Unlock()
}

// Utility functions

func isPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}

	for _, cidr := range privateRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		ipAddr := net.ParseIP(ip)
		if ipAddr != nil && ipnet.Contains(ipAddr) {
			return true
		}
	}

	return false
}

func calculateThreatLevel(score float64) string {
	switch {
	case score < 0.2:
		return "critical"
	case score < 0.4:
		return "high"
	case score < 0.6:
		return "medium"
	case score < 0.8:
		return "low"
	default:
		return "none"
	}
}

// Priority returns the plugin priority (higher numbers run later)
func (p *ThreatIntelPlugin) Priority() int {
	return 150 // Run after basic rate limiting, before tarpit
}

// GetPlugin returns a new instance of the plugin for dynamic loading
func GetPlugin() plugin.Plugin {
	return &ThreatIntelPlugin{}
}
