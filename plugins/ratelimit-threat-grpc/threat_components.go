// Threat intelligence components for enhanced rate limiting
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
)

// ThreatFeedManager manages threat intelligence feeds
type ThreatFeedManager struct {
	feeds      []ThreatFeedConfig
	indicators map[string]*ThreatIndicator
	lastUpdate map[string]time.Time
	httpClient *http.Client
	mu         sync.RWMutex
}

func NewThreatFeedManager(feeds []ThreatFeedConfig) *ThreatFeedManager {
	return &ThreatFeedManager{
		feeds:      feeds,
		indicators: make(map[string]*ThreatIndicator),
		lastUpdate: make(map[string]time.Time),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (tfm *ThreatFeedManager) UpdateFeeds() error {
	for _, feed := range tfm.feeds {
		if !feed.Enabled {
			continue
		}

		// Check update frequency
		if lastUpdate, exists := tfm.lastUpdate[feed.Name]; exists {
			updateFreq, _ := time.ParseDuration(feed.UpdateFreq)
			if time.Since(lastUpdate) < updateFreq {
				continue
			}
		}

		// Update feed
		if err := tfm.updateFeed(feed); err != nil {
			// Log error but continue with other feeds
			continue
		}

		tfm.lastUpdate[feed.Name] = time.Now()
	}

	return nil
}

func (tfm *ThreatFeedManager) updateFeed(feed ThreatFeedConfig) error {
	// Create request
	req, err := http.NewRequest("GET", feed.URL, nil)
	if err != nil {
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
	resp, err := tfm.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("feed returned status %d", resp.StatusCode)
	}

	// Parse feed based on format
	indicators, err := tfm.parseFeed(feed, resp.Body)
	if err != nil {
		return err
	}

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

func (tfm *ThreatFeedManager) GetIndicatorCount() int {
	tfm.mu.RLock()
	defer tfm.mu.RUnlock()
	return len(tfm.indicators)
}

func (tfm *ThreatFeedManager) GetIndicator(value string) *ThreatIndicator {
	tfm.mu.RLock()
	defer tfm.mu.RUnlock()
	return tfm.indicators[value]
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
			IP:              ip,
			LastActivity:    time.Now(),
			ReputationScore: 0.5, // Start with neutral reputation
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

func (irs *IPReputationService) GetReputationCount() int {
	irs.mu.RLock()
	defer irs.mu.RUnlock()
	return len(irs.reputations)
}

// ReputationUpdate represents a reputation update event
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
	Regex      *regexp.Regexp
}

func NewThreatMatcher() *ThreatMatcher {
	tm := &ThreatMatcher{}
	tm.initializePatterns()
	return tm
}

func (tm *ThreatMatcher) initializePatterns() {
	// Initialize with common threat patterns
	patterns := []ThreatPattern{
		{
			Name:       "SQL Injection",
			Pattern:    `(?i)(union|select|insert|update|delete|drop).*(from|where)`,
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
			Pattern:    `(nikto|nmap|masscan|zap|burp|sqlmap)`,
			Type:       "header",
			Severity:   "medium",
			Confidence: 0.9,
		},
	}

	// Compile regex patterns
	for _, pattern := range patterns {
		if regex, err := regexp.Compile(pattern.Pattern); err == nil {
			pattern.Regex = regex
			tm.patterns = append(tm.patterns, pattern)
		}
	}
}

func (tm *ThreatMatcher) MatchRequest(req *proto.HTTPRequest) []*ThreatIndicator {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var threats []*ThreatIndicator

	// Check URL patterns
	urlStr := req.Path
	for _, pattern := range tm.patterns {
		if pattern.Type == "url" && pattern.Regex != nil {
			if pattern.Regex.MatchString(urlStr) {
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
	}

	// Check headers
	for _, pattern := range tm.patterns {
		if pattern.Type == "header" && pattern.Regex != nil {
			for key, value := range req.Headers {
				headerStr := strings.ToLower(key + ": " + value)
				if pattern.Regex.MatchString(headerStr) {
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
			atomic.AddInt64(&entry.HitCount, 1)
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

func (bc *BlocklistCache) GetActiveCount() int {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, entry := range bc.entries {
		if now.Before(entry.ExpiresAt) {
			count++
		}
	}
	return count
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

func (tm *ThreatMetrics) GetBlockedCount() int64 {
	return atomic.LoadInt64(&tm.blockedIPs)
}

func (tm *ThreatMetrics) GetThreatCount() int64 {
	return atomic.LoadInt64(&tm.threatsDetected)
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
