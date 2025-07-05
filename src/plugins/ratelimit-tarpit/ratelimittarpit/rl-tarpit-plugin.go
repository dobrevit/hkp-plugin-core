// Package ratelimittarpit provides defensive connection management through tarpit functionality
package ratelimittarpit

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
)

// Plugin constants
const (
	PluginName    = "ratelimit-tarpit"
	PluginVersion = "1.0.0"
)

// TarpitPlugin implements defensive connection management
type TarpitPlugin struct {
	host                  plugin.PluginHost
	config                *TarpitConfig
	tarpit                *Tarpit
	honeypot              *Honeypot
	connManager           *ConnectionManager
	intelligenceCollector *IntelligenceCollector
	metrics               *TarpitMetrics
	mu                    sync.RWMutex
	shutdownCh            chan struct{}
	shutdownWg            sync.WaitGroup
}

// TarpitConfig holds configuration
type TarpitConfig struct {
	Enabled              bool                     `json:"enabled"`
	TarpitMode           string                   `json:"tarpitMode"` // slow, sticky, random
	DelayMin             string                   `json:"delayMin"`
	DelayMax             string                   `json:"delayMax"`
	ResponseChunkSize    int                      `json:"responseChunkSize"`
	ConnectionTimeout    string                   `json:"connectionTimeout"`
	MaxConcurrentTarpits int                      `json:"maxConcurrentTarpits"`
	HoneypotEnabled      bool                     `json:"honeypotEnabled"`
	HoneypotPaths        []string                 `json:"honeypotPaths"`
	IntelligenceMode     bool                     `json:"intelligenceMode"`
	AutoTarpitThreshold  float64                  `json:"autoTarpitThreshold"`
	ResourceExhaustion   ResourceExhaustionConfig `json:"resourceExhaustion"`
}

// ResourceExhaustionConfig configures resource exhaustion tactics
type ResourceExhaustionConfig struct {
	Enabled         bool   `json:"enabled"`
	CPUIntensive    bool   `json:"cpuIntensive"`
	MemoryIntensive bool   `json:"memoryIntensive"`
	BandwidthMode   string `json:"bandwidthMode"` // slow, burst, random
	FakeDataSize    int    `json:"fakeDataSize"`
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

// Initialize implements the Plugin interface
func (p *TarpitPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	p.config = &TarpitConfig{
		Enabled:              true,
		TarpitMode:           "slow",
		DelayMin:             "100ms",
		DelayMax:             "10s",
		ResponseChunkSize:    64,
		ConnectionTimeout:    "5m",
		MaxConcurrentTarpits: 1000,
		HoneypotEnabled:      true,
		IntelligenceMode:     true,
		AutoTarpitThreshold:  0.8,
	}

	if err := json.Unmarshal(configBytes, p.config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	p.host = host
	p.shutdownCh = make(chan struct{})

	// Initialize components
	p.tarpit = NewTarpit(p.config)
	p.honeypot = NewHoneypot(p.config.HoneypotPaths)
	p.connManager = NewConnectionManager(p.config.MaxConcurrentTarpits)
	p.intelligenceCollector = NewIntelligenceCollector()
	p.metrics = NewTarpitMetrics()

	// Register middleware
	middleware, err := p.CreateMiddleware()
	if err != nil {
		return fmt.Errorf("failed to create middleware: %w", err)
	}

	if err := host.RegisterMiddleware("/", middleware); err != nil {
		return fmt.Errorf("failed to register middleware: %w", err)
	}

	// Register honeypot paths
	for _, path := range p.config.HoneypotPaths {
		host.RegisterHandler(path, plugin.WrapStandardHandler(p.handleHoneypot))
	}

	// Register management endpoints
	host.RegisterHandler("/ratelimit/tarpit/status", plugin.WrapStandardHandler(p.handleStatus))
	host.RegisterHandler("/ratelimit/tarpit/connections", plugin.WrapStandardHandler(p.handleConnections))

	// Start background tasks
	p.shutdownWg.Add(2)
	go func() {
		defer p.shutdownWg.Done()
		p.runConnectionManager(ctx)
	}()
	go func() {
		defer p.shutdownWg.Done()
		p.runIntelligenceAnalysis(ctx)
	}()

	// Subscribe to events
	host.SubscribeEvent("ratelimit.violation", p.handleRateLimitViolation)
	host.SubscribeEvent("ml.abuse.detected", p.handleAbuseDetected)

	return nil
}

// Name returns the plugin name
func (p *TarpitPlugin) Name() string {
	return PluginName
}

// Version returns the plugin version
func (p *TarpitPlugin) Version() string {
	return PluginVersion
}

// Description returns the plugin description
func (p *TarpitPlugin) Description() string {
	return "Defensive connection management with tarpit and honeypot functionality"
}

// Dependencies returns required dependencies
func (p *TarpitPlugin) Dependencies() []plugin.PluginDependency {
	// No dependencies for this standalone plugin
	return []plugin.PluginDependency{}
}

// Priority returns the plugin priority (higher numbers run later)
func (p *TarpitPlugin) Priority() int {
	return 200 // Run after core rate limiting plugins
}

// Shutdown gracefully stops the plugin
func (p *TarpitPlugin) Shutdown(ctx context.Context) error {
	// Signal shutdown to all goroutines
	close(p.shutdownCh)

	// Wait for all goroutines to finish or timeout
	done := make(chan struct{})
	go func() {
		p.shutdownWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines finished
	case <-ctx.Done():
		// Timeout - return error
		return fmt.Errorf("plugin shutdown timed out")
	}

	// Drain active connections
	p.connManager.DrainAll()

	return nil
}

// CreateMiddleware creates the tarpit middleware
func (p *TarpitPlugin) CreateMiddleware() (func(http.Handler) http.Handler, error) {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := p.extractClientIP(r)

			// Check if should tarpit
			if shouldTarpit, reason := p.shouldTarpit(clientIP, r); shouldTarpit {
				p.handleTarpit(w, r, clientIP, reason)
				return
			}

			// Check if honeypot path
			if p.honeypot.IsHoneypotPath(r.URL.Path) {
				p.handleHoneypot(w, r)
				return
			}

			// Continue normally
			next.ServeHTTP(w, r)
		})
	}, nil
}

// Tarpit implements the tarpit functionality
type Tarpit struct {
	config    *TarpitConfig
	delayMin  time.Duration
	delayMax  time.Duration
	chunkSize int
}

func NewTarpit(config *TarpitConfig) *Tarpit {
	delayMin, _ := time.ParseDuration(config.DelayMin)
	delayMax, _ := time.ParseDuration(config.DelayMax)

	return &Tarpit{
		config:    config,
		delayMin:  delayMin,
		delayMax:  delayMax,
		chunkSize: config.ResponseChunkSize,
	}
}

func (t *Tarpit) SlowResponse(w http.ResponseWriter, r *http.Request, connInfo *ConnectionInfo) {
	// Set headers to prevent caching and keep connection alive
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Tarpit", "active")

	// Flush headers
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// Generate fake response data
	fakeData := t.generateFakeData()

	// Send response slowly
	for i := 0; i < len(fakeData); i += t.chunkSize {
		select {
		case <-r.Context().Done():
			// Client disconnected
			connInfo.State = "closed"
			return
		default:
			// Calculate delay
			delay := t.calculateDelay(connInfo)
			time.Sleep(delay)

			// Write chunk
			end := i + t.chunkSize
			if end > len(fakeData) {
				end = len(fakeData)
			}

			chunk := fakeData[i:end]
			if _, err := w.Write(chunk); err != nil {
				connInfo.State = "closed"
				return
			}

			// Update metrics
			atomic.AddInt64(&connInfo.BytesSent, int64(len(chunk)))
			connInfo.DelaysApplied++

			// Flush if possible
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}

			// Resource exhaustion if enabled
			if t.config.ResourceExhaustion.Enabled {
				t.applyResourceExhaustion(connInfo)
			}
		}
	}

	connInfo.State = "draining"
}

func (t *Tarpit) calculateDelay(connInfo *ConnectionInfo) time.Duration {
	switch t.config.TarpitMode {
	case "slow":
		// Gradually increase delay
		factor := float64(connInfo.DelaysApplied) / 10.0
		delay := t.delayMin + time.Duration(factor*float64(t.delayMax-t.delayMin))
		if delay > t.delayMax {
			delay = t.delayMax
		}
		return delay

	case "sticky":
		// Keep connection open with minimal data
		return t.delayMax

	case "random":
		// Random delays to confuse attackers
		r := rand.Float64()
		return t.delayMin + time.Duration(r*float64(t.delayMax-t.delayMin))

	default:
		return t.delayMin
	}
}

func (t *Tarpit) generateFakeData() []byte {
	// Generate plausible but useless data
	templates := []string{
		"Processing request...\n",
		"Loading data...\n",
		"Please wait while we process your request...\n",
		"Fetching results...\n",
		"Almost done...\n",
		"Just a moment more...\n",
	}

	// Build response
	var response strings.Builder
	response.WriteString("HTTP/1.1 200 OK\r\n\r\n")

	// Add random content
	for i := 0; i < 1000; i++ {
		template := templates[rand.Intn(len(templates))]
		response.WriteString(template)

		// Add some random data
		if rand.Float64() < 0.3 {
			response.WriteString(fmt.Sprintf("<!-- %s -->\n", generateRandomString(50)))
		}
	}

	return []byte(response.String())
}

func (t *Tarpit) applyResourceExhaustion(connInfo *ConnectionInfo) {
	if t.config.ResourceExhaustion.CPUIntensive {
		// Perform CPU-intensive operations
		go func() {
			result := 1
			for i := 0; i < 10000; i++ {
				result = result * i % 1000000
			}
			_ = result
		}()
	}

	if t.config.ResourceExhaustion.MemoryIntensive {
		// Allocate temporary memory
		data := make([]byte, 1024*1024) // 1MB
		rand.Read(data)
		// Let it be garbage collected
	}
}

// Honeypot implements honeypot functionality
type Honeypot struct {
	paths    map[string]bool
	trapData map[string]HoneypotTrap
	mu       sync.RWMutex
}

type HoneypotTrap struct {
	Path       string
	TrapType   string // fake_admin, fake_api, fake_vuln
	Response   string
	StatusCode int
	Headers    map[string]string
}

func NewHoneypot(paths []string) *Honeypot {
	h := &Honeypot{
		paths:    make(map[string]bool),
		trapData: make(map[string]HoneypotTrap),
	}

	// Default honeypot paths if none specified
	if len(paths) == 0 {
		paths = []string{
			"/admin", "/wp-admin", "/.git", "/.env",
			"/phpmyadmin", "/api/v1/users", "/backup.sql",
		}
	}

	// Initialize traps
	for _, path := range paths {
		h.paths[path] = true
		h.trapData[path] = h.generateTrap(path)
	}

	return h
}

func (h *Honeypot) IsHoneypotPath(path string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.paths[path]
}

func (h *Honeypot) generateTrap(path string) HoneypotTrap {
	trap := HoneypotTrap{
		Path:    path,
		Headers: make(map[string]string),
	}

	// Generate trap based on path
	switch {
	case strings.Contains(path, "admin"):
		trap.TrapType = "fake_admin"
		trap.StatusCode = 200
		trap.Response = generateFakeAdminPage()
		trap.Headers["Content-Type"] = "text/html"

	case strings.Contains(path, ".git"):
		trap.TrapType = "fake_git"
		trap.StatusCode = 403
		trap.Response = "Forbidden"

	case strings.Contains(path, "api"):
		trap.TrapType = "fake_api"
		trap.StatusCode = 200
		trap.Response = `{"error": "API endpoint not found"}`
		trap.Headers["Content-Type"] = "application/json"

	default:
		trap.TrapType = "generic"
		trap.StatusCode = 404
		trap.Response = "Not Found"
	}

	return trap
}

// ConnectionManager manages active tarpit connections
type ConnectionManager struct {
	connections map[string]*ConnectionInfo
	maxActive   int
	mu          sync.RWMutex
}

func NewConnectionManager(maxActive int) *ConnectionManager {
	return &ConnectionManager{
		connections: make(map[string]*ConnectionInfo),
		maxActive:   maxActive,
	}
}

func (cm *ConnectionManager) AddConnection(clientIP string, reason string) *ConnectionInfo {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Check if already exists
	if conn, exists := cm.connections[clientIP]; exists {
		return conn
	}

	// Check capacity
	if len(cm.connections) >= cm.maxActive {
		// Remove oldest connection
		cm.removeOldest()
	}

	conn := &ConnectionInfo{
		ClientIP:    clientIP,
		ConnectedAt: time.Now(),
		State:       "active",
		Reason:      reason,
	}

	cm.connections[clientIP] = conn
	return conn
}

func (cm *ConnectionManager) removeOldest() {
	var oldestIP string
	var oldestTime time.Time

	for ip, conn := range cm.connections {
		if oldestIP == "" || conn.ConnectedAt.Before(oldestTime) {
			oldestIP = ip
			oldestTime = conn.ConnectedAt
		}
	}

	if oldestIP != "" {
		delete(cm.connections, oldestIP)
	}
}

func (cm *ConnectionManager) DrainAll() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for _, conn := range cm.connections {
		conn.State = "draining"
	}
}

// IntelligenceCollector gathers attacker intelligence
type IntelligenceCollector struct {
	intelligence map[string]*AttackerProfile
	patterns     []PatternDetector
	mu           sync.RWMutex
}

type AttackerProfile struct {
	IP             string
	FirstSeen      time.Time
	LastSeen       time.Time
	Requests       int
	Techniques     map[string]int
	Tools          map[string]bool
	Persistence    int
	Sophistication string
}

type PatternDetector struct {
	Name     string
	Pattern  string
	Category string // tool, technique, behavior
}

func NewIntelligenceCollector() *IntelligenceCollector {
	ic := &IntelligenceCollector{
		intelligence: make(map[string]*AttackerProfile),
	}

	// Initialize pattern detectors
	ic.patterns = []PatternDetector{
		{Name: "Nikto", Pattern: "nikto", Category: "tool"},
		{Name: "SQLMap", Pattern: "sqlmap", Category: "tool"},
		{Name: "Nmap", Pattern: "nmap", Category: "tool"},
		{Name: "DirBuster", Pattern: "dirbuster", Category: "tool"},
		{Name: "SQL Injection", Pattern: "union.*select", Category: "technique"},
		{Name: "XSS", Pattern: "<script>", Category: "technique"},
		{Name: "Path Traversal", Pattern: "../", Category: "technique"},
	}

	return ic
}

func (ic *IntelligenceCollector) AnalyzeRequest(clientIP string, r *http.Request, connInfo *ConnectionInfo) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	profile, exists := ic.intelligence[clientIP]
	if !exists {
		profile = &AttackerProfile{
			IP:         clientIP,
			FirstSeen:  time.Now(),
			Techniques: make(map[string]int),
			Tools:      make(map[string]bool),
		}
		ic.intelligence[clientIP] = profile
	}

	profile.LastSeen = time.Now()
	profile.Requests++

	// Analyze for patterns
	userAgent := r.Header.Get("User-Agent")
	urlPath := r.URL.String()

	for _, detector := range ic.patterns {
		if strings.Contains(strings.ToLower(userAgent), detector.Pattern) ||
			strings.Contains(strings.ToLower(urlPath), detector.Pattern) {

			switch detector.Category {
			case "tool":
				profile.Tools[detector.Name] = true
			case "technique":
				profile.Techniques[detector.Name]++
			}
		}
	}

	// Update sophistication
	profile.Sophistication = ic.calculateSophistication(profile)

	// Update connection info
	connInfo.Intelligence = AttackerIntelligence{
		Tools:          ic.getTools(profile),
		Techniques:     ic.getTechniques(profile),
		Persistence:    profile.Persistence,
		Sophistication: profile.Sophistication,
	}
}

func (ic *IntelligenceCollector) calculateSophistication(profile *AttackerProfile) string {
	score := 0

	// More tools = higher sophistication
	score += len(profile.Tools) * 10

	// More techniques = higher sophistication
	score += len(profile.Techniques) * 15

	// Persistence adds to sophistication
	if profile.Requests > 100 {
		score += 20
	}

	switch {
	case score < 20:
		return "low"
	case score < 50:
		return "medium"
	default:
		return "high"
	}
}

func (ic *IntelligenceCollector) getTools(profile *AttackerProfile) []string {
	tools := make([]string, 0, len(profile.Tools))
	for tool := range profile.Tools {
		tools = append(tools, tool)
	}
	return tools
}

func (ic *IntelligenceCollector) getTechniques(profile *AttackerProfile) []string {
	techniques := make([]string, 0, len(profile.Techniques))
	for technique := range profile.Techniques {
		techniques = append(techniques, technique)
	}
	return techniques
}

// Helper functions

func (p *TarpitPlugin) shouldTarpit(clientIP string, r *http.Request) (bool, string) {
	// Check various criteria

	// 1. Check if already marked for tarpit
	if r.Header.Get("X-Tarpit-Candidate") == "true" {
		return true, "marked_by_rate_limiter"
	}

	// 2. Check honeypot access attempts
	if p.honeypot.IsHoneypotPath(r.URL.Path) {
		return true, "honeypot_access"
	}

	// 3. Check for scanner patterns
	userAgent := strings.ToLower(r.Header.Get("User-Agent"))
	scanners := []string{"nikto", "nmap", "masscan", "sqlmap", "dirbuster"}
	for _, scanner := range scanners {
		if strings.Contains(userAgent, scanner) {
			return true, fmt.Sprintf("scanner_detected: %s", scanner)
		}
	}

	// 4. Check for attack patterns in URL
	attackPatterns := []string{"../", "union select", "<script>", "eval(", "base64_decode"}
	urlStr := strings.ToLower(r.URL.String())
	for _, pattern := range attackPatterns {
		if strings.Contains(urlStr, pattern) {
			return true, fmt.Sprintf("attack_pattern: %s", pattern)
		}
	}

	return false, ""
}

func (p *TarpitPlugin) handleTarpit(w http.ResponseWriter, r *http.Request, clientIP string, reason string) {
	// Add connection
	connInfo := p.connManager.AddConnection(clientIP, reason)

	// Collect intelligence if enabled
	if p.config.IntelligenceMode {
		p.intelligenceCollector.AnalyzeRequest(clientIP, r, connInfo)
	}

	// Record metrics
	p.metrics.RecordTarpit(clientIP, reason)

	// Apply tarpit
	p.tarpit.SlowResponse(w, r, connInfo)

	// Log intelligence gathered
	if p.config.IntelligenceMode && connInfo.Intelligence.Sophistication != "" {
		p.host.PublishEvent(plugin.PluginEvent{
			Type: "tarpit.intelligence",
			Data: map[string]interface{}{
				"client_ip":      clientIP,
				"tools":          connInfo.Intelligence.Tools,
				"techniques":     connInfo.Intelligence.Techniques,
				"sophistication": connInfo.Intelligence.Sophistication,
			},
		})
	}
}

func (p *TarpitPlugin) handleHoneypot(w http.ResponseWriter, r *http.Request) {
	clientIP := p.extractClientIP(r)

	// Get trap data
	trap := p.honeypot.trapData[r.URL.Path]

	// Record honeypot access
	p.metrics.RecordHoneypotAccess(clientIP, r.URL.Path)

	// Set headers
	for k, v := range trap.Headers {
		w.Header().Set(k, v)
	}

	// Add honey token
	w.Header().Set("X-Honey-Token", generateHoneyToken())

	// Publish event
	p.host.PublishEvent(plugin.PluginEvent{
		Type: "honeypot.accessed",
		Data: map[string]interface{}{
			"client_ip": clientIP,
			"path":      r.URL.Path,
			"trap_type": trap.TrapType,
		},
	})

	// Return trap response
	w.WriteHeader(trap.StatusCode)
	w.Write([]byte(trap.Response))
}

func (p *TarpitPlugin) extractClientIP(r *http.Request) string {
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

// Background tasks

func (p *TarpitPlugin) runConnectionManager(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanupConnections()
		case <-p.shutdownCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (p *TarpitPlugin) cleanupConnections() {
	p.connManager.mu.Lock()
	defer p.connManager.mu.Unlock()

	timeout, _ := time.ParseDuration(p.config.ConnectionTimeout)
	cutoff := time.Now().Add(-timeout)

	for ip, conn := range p.connManager.connections {
		if conn.ConnectedAt.Before(cutoff) || conn.State == "closed" {
			delete(p.connManager.connections, ip)
		}
	}
}

func (p *TarpitPlugin) runIntelligenceAnalysis(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.analyzeIntelligence()
		case <-p.shutdownCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (p *TarpitPlugin) analyzeIntelligence() {
	p.intelligenceCollector.mu.RLock()
	defer p.intelligenceCollector.mu.RUnlock()

	// Analyze patterns
	highSophistication := 0
	commonTools := make(map[string]int)
	commonTechniques := make(map[string]int)

	for _, profile := range p.intelligenceCollector.intelligence {
		if profile.Sophistication == "high" {
			highSophistication++
		}

		for tool := range profile.Tools {
			commonTools[tool]++
		}

		for technique, count := range profile.Techniques {
			commonTechniques[technique] += count
		}
	}

	// Publish intelligence summary
	if len(p.intelligenceCollector.intelligence) > 0 {
		p.host.PublishEvent(plugin.PluginEvent{
			Type: "tarpit.intelligence_summary",
			Data: map[string]interface{}{
				"total_attackers":     len(p.intelligenceCollector.intelligence),
				"high_sophistication": highSophistication,
				"common_tools":        commonTools,
				"common_techniques":   commonTechniques,
			},
		})
	}
}

// Event handlers

func (p *TarpitPlugin) handleRateLimitViolation(event plugin.PluginEvent) error {
	data := event.Data
	if len(data) == 0 {
		return fmt.Errorf("empty event data")
	}

	_, _ = data["client_ip"].(string)

	// Mark for tarpit on next request
	// In production, would coordinate with rate limiter

	return nil
}

func (p *TarpitPlugin) handleAbuseDetected(event plugin.PluginEvent) error {
	data := event.Data
	if len(data) == 0 {
		return fmt.Errorf("empty event data")
	}

	clientIP, _ := data["client_ip"].(string)
	score, _ := data["anomaly_score"].(float64)

	// Auto-tarpit if score exceeds threshold
	if score >= p.config.AutoTarpitThreshold {
		// Will be tarpitted on next request
		p.metrics.RecordAutoTarpit(clientIP, score)
	}

	return nil
}

// HTTP handlers

func (p *TarpitPlugin) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"enabled":           p.config.Enabled,
		"active_tarpits":    len(p.connManager.connections),
		"honeypot_enabled":  p.config.HoneypotEnabled,
		"honeypot_paths":    len(p.honeypot.paths),
		"intelligence_mode": p.config.IntelligenceMode,
		"profiles_tracked":  len(p.intelligenceCollector.intelligence),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (p *TarpitPlugin) handleConnections(w http.ResponseWriter, r *http.Request) {
	p.connManager.mu.RLock()
	defer p.connManager.mu.RUnlock()

	connections := make([]map[string]interface{}, 0)

	for _, conn := range p.connManager.connections {
		connections = append(connections, map[string]interface{}{
			"client_ip":    conn.ClientIP,
			"connected_at": conn.ConnectedAt,
			"bytes_sent":   conn.BytesSent,
			"delays":       conn.DelaysApplied,
			"state":        conn.State,
			"reason":       conn.Reason,
			"intelligence": conn.Intelligence,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connections)
}

// TarpitMetrics tracks tarpit and honeypot metrics
type TarpitMetrics struct {
	tarpittedConnections int64
	honeypotAccesses     int64
	autoTarpits          int64
	intelligenceGathered int64
	bytesSent            int64
	tarpitsByReason      map[string]int64
	honeypotsByPath      map[string]int64
	mu                   sync.RWMutex
}

func NewTarpitMetrics() *TarpitMetrics {
	return &TarpitMetrics{
		tarpitsByReason: make(map[string]int64),
		honeypotsByPath: make(map[string]int64),
	}
}

func (tm *TarpitMetrics) RecordTarpit(clientIP string, reason string) {
	atomic.AddInt64(&tm.tarpittedConnections, 1)

	tm.mu.Lock()
	tm.tarpitsByReason[reason]++
	tm.mu.Unlock()
}

func (tm *TarpitMetrics) RecordHoneypotAccess(clientIP string, path string) {
	atomic.AddInt64(&tm.honeypotAccesses, 1)

	tm.mu.Lock()
	tm.honeypotsByPath[path]++
	tm.mu.Unlock()
}

func (tm *TarpitMetrics) RecordAutoTarpit(clientIP string, score float64) {
	atomic.AddInt64(&tm.autoTarpits, 1)
}

func (tm *TarpitMetrics) RecordIntelligence() {
	atomic.AddInt64(&tm.intelligenceGathered, 1)
}

func (tm *TarpitMetrics) RecordBytesSent(bytes int64) {
	atomic.AddInt64(&tm.bytesSent, bytes)
}

// Utility functions

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func generateHoneyToken() string {
	// Generate a tracking token
	return fmt.Sprintf("HT-%s-%d", generateRandomString(8), time.Now().Unix())
}

func generateFakeAdminPage() string {
	return `<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
</head>
<body>
    <h1>Administrator Login</h1>
    <form method="post" action="/admin/login">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <input type="submit" value="Login">
    </form>
    <!-- Debug: Session ID: ` + generateRandomString(32) + ` -->
</body>
</html>`
}

// GetPlugin returns a new instance of the plugin for dynamic loading
func GetPlugin() plugin.Plugin {
	return &TarpitPlugin{}
}
