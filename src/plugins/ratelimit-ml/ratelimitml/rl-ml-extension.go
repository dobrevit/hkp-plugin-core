// Package ratelimitml provides machine learning extensions for advanced rate limiting
package ratelimitml

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
)

// Plugin constants
const (
	PluginName    = "ratelimit-ml"
	PluginVersion = "1.0.0"
)

// RateLimitMLPlugin extends rate limiting with ML-based anomaly detection
type RateLimitMLPlugin struct {
	host            plugin.PluginHost
	config          *MLRateLimitConfig
	anomalyDetector *AnomalyDetector
	patternAnalyzer *PatternAnalyzer
	predictor       *TrafficPredictor
	coordinator     *RateLimitCoordinator
	metrics         *MLMetrics
	mu              sync.RWMutex
	shutdownCh      chan struct{}
	shutdownWg      sync.WaitGroup
}

// MLRateLimitConfig holds configuration
type MLRateLimitConfig struct {
	Enabled              bool    `json:"enabled"`
	ModelPath            string  `json:"modelPath"`
	AnomalyThreshold     float64 `json:"anomalyThreshold"`
	PredictionWindow     string  `json:"predictionWindow"`
	LearningEnabled      bool    `json:"learningEnabled"`
	CoordinationEnabled  bool    `json:"coordinationEnabled"`
	BlockDuration        string  `json:"blockDuration"`
	EscalationMultiplier float64 `json:"escalationMultiplier"`
}

// TrafficPattern represents analyzed traffic patterns
type TrafficPattern struct {
	ClientIP       string
	RequestRate    float64
	BurstPattern   []int
	Periodicity    float64
	Entropy        float64
	EntropyScore   float64 // Alias for Entropy
	Predictability float64
	AnomalyScore   float64
	IsAnomalous    bool
	LastUpdated    time.Time
}

// AnomalyDetector implements advanced anomaly detection
type AnomalyDetector struct {
	model          *IsolationForest
	normalProfiles map[string]*NormalProfile
	anomalyHistory map[string][]AnomalyEvent
	threshold      float64
	modelPath      string
	mu             sync.RWMutex
}

// NormalProfile represents normal traffic behavior
type NormalProfile struct {
	ClientIP         string
	AverageRate      float64
	StdDeviation     float64
	PeakHours        []int
	TypicalEndpoints map[string]float64
	UserAgent        string
	LastSeen         time.Time
}

// AnomalyEvent represents a detected anomaly
type AnomalyEvent struct {
	Timestamp   time.Time
	Score       float64
	Type        string
	Description string
	Action      string
}

// IsolationForest represents the ensemble of isolation trees
type IsolationForest struct {
	Trees         []*IsolationTree
	NumTrees      int
	SampleSize    int
	MaxDepth      int
	FeatureNames  []string
	AnomalyScores map[string]float64 // Cache for recent scores
}

// IsolationTree represents a single tree in the forest
type IsolationTree struct {
	Root       *IsolationNode
	PathLength map[string]float64
}

// IsolationNode represents a node in the isolation tree
type IsolationNode struct {
	IsLeaf       bool
	SplitFeature int
	SplitValue   float64
	Left         *IsolationNode
	Right        *IsolationNode
	Size         int // Number of samples at this node
}

// Initialize implements the Plugin interface
func (p *RateLimitMLPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	p.config = &MLRateLimitConfig{
		Enabled:              true,
		AnomalyThreshold:     0.85,
		PredictionWindow:     "5m",
		LearningEnabled:      true,
		CoordinationEnabled:  true,
		BlockDuration:        "1h",
		EscalationMultiplier: 2.0,
	}

	if err := json.Unmarshal(configBytes, p.config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	p.host = host
	p.shutdownCh = make(chan struct{})

	// Initialize components
	p.anomalyDetector = NewAnomalyDetector(p.config.ModelPath, p.config.AnomalyThreshold)
	p.patternAnalyzer = NewPatternAnalyzer()
	p.predictor = NewTrafficPredictor(p.config.PredictionWindow)
	p.coordinator = NewRateLimitCoordinator()
	p.metrics = NewMLMetrics()

	// Load ML model
	if err := p.anomalyDetector.LoadModel(); err != nil {
		return fmt.Errorf("failed to load ML model: %w", err)
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
	host.RegisterHandler("/ratelimit/ml/status", p.handleStatus)
	host.RegisterHandler("/ratelimit/ml/patterns", p.handlePatterns)

	// Start background tasks
	p.shutdownWg.Add(3)
	go func() {
		defer p.shutdownWg.Done()
		p.runAnomalyDetection(ctx)
	}()
	go func() {
		defer p.shutdownWg.Done()
		p.runPatternAnalysis()
	}()
	go func() {
		defer p.shutdownWg.Done()
		p.runModelUpdate()
	}()

	// Subscribe to rate limit events
	host.SubscribeEvent("ratelimit.request", p.handleRateLimitRequest)
	host.SubscribeEvent("ratelimit.violation", p.handleRateLimitViolation)

	return nil
}

// Name returns the plugin name
func (p *RateLimitMLPlugin) Name() string {
	return PluginName
}

// Version returns the plugin version
func (p *RateLimitMLPlugin) Version() string {
	return PluginVersion
}

// Description returns the plugin description
func (p *RateLimitMLPlugin) Description() string {
	return "Machine learning extensions for advanced rate limiting"
}

// Dependencies returns required dependencies
func (p *RateLimitMLPlugin) Dependencies() []plugin.PluginDependency {
	// No dependencies for this standalone plugin
	return []plugin.PluginDependency{}
}

// Shutdown gracefully stops the plugin
func (p *RateLimitMLPlugin) Shutdown(ctx context.Context) error {
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

	// Save model state
	if p.config.LearningEnabled && p.anomalyDetector != nil {
		if err := p.anomalyDetector.SaveModel(); err != nil {
			return fmt.Errorf("failed to save model: %w", err)
		}
	}

	return nil
}

// CreateMiddleware creates the ML rate limiting middleware
func (p *RateLimitMLPlugin) CreateMiddleware() (func(http.Handler) http.Handler, error) {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()
			clientIP := p.extractClientIP(r)

			// Analyze request pattern
			pattern := p.patternAnalyzer.AnalyzeRequest(clientIP, r)

			// Detect anomalies
			anomalyScore := p.anomalyDetector.DetectAnomaly(pattern)

			// Predict future behavior
			prediction := p.predictor.PredictBehavior(pattern)

			// Make ML-based decision
			decision := p.makeDecision(pattern, anomalyScore, prediction)

			// Record metrics
			p.metrics.RecordRequest(clientIP, anomalyScore, decision)

			// Add ML headers
			p.addMLHeaders(w, anomalyScore, prediction, decision)

			// Apply decision
			if decision.Block {
				// Coordinate with base rate limiter
				if p.config.CoordinationEnabled {
					p.coordinator.ApplyMLBlock(clientIP, decision)
				}

				// Return rate limit response
				w.Header().Set("X-RateLimit-ML-Blocked", "true")
				http.Error(w, "Rate limit exceeded: ML anomaly detected", http.StatusTooManyRequests)
				return
			}

			// Update learning data
			if p.config.LearningEnabled {
				learningData := map[string]interface{}{
					"pattern":  pattern,
					"duration": time.Since(startTime),
					"path":     r.URL.Path,
					"method":   r.Method,
				}
				go p.updateLearningData(clientIP, learningData)
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

// Decision represents an ML-based rate limiting decision
type Decision struct {
	Block      bool
	Reason     string
	Confidence float64
	Duration   time.Duration
	Escalation int
}

// makeDecision makes an ML-based rate limiting decision
func (p *RateLimitMLPlugin) makeDecision(pattern *TrafficPattern, anomalyScore float64, prediction *BehaviorPrediction) Decision {
	decision := Decision{
		Block:      false,
		Confidence: anomalyScore,
	}

	// Check anomaly threshold
	if anomalyScore >= p.config.AnomalyThreshold {
		decision.Block = true
		decision.Reason = fmt.Sprintf("Anomaly detected (score: %.2f)", anomalyScore)

		// Determine block duration based on severity
		baseDuration, _ := time.ParseDuration(p.config.BlockDuration)
		if anomalyScore >= 0.95 {
			decision.Duration = baseDuration * 3
			decision.Escalation = 3
		} else if anomalyScore >= 0.9 {
			decision.Duration = baseDuration * 2
			decision.Escalation = 2
		} else {
			decision.Duration = baseDuration
			decision.Escalation = 1
		}
	}

	// Check prediction-based blocking
	if prediction.PredictedSpike > pattern.RequestRate*3 {
		decision.Block = true
		decision.Reason = "Predicted traffic spike"
		decision.Duration, _ = time.ParseDuration(p.config.BlockDuration)
	}

	// Check pattern-based indicators
	if pattern.Entropy < 0.2 && pattern.RequestRate > 10 {
		decision.Block = true
		decision.Reason = "Bot-like behavior detected"
		decision.Duration, _ = time.ParseDuration(p.config.BlockDuration)
		decision.Duration *= 2
	}

	return decision
}

// addMLHeaders adds ML intelligence headers
func (p *RateLimitMLPlugin) addMLHeaders(w http.ResponseWriter, anomalyScore float64, prediction *BehaviorPrediction, decision Decision) {
	w.Header().Set("X-RateLimit-ML-Score", fmt.Sprintf("%.3f", anomalyScore))
	w.Header().Set("X-RateLimit-ML-Prediction", fmt.Sprintf("%.1f", prediction.PredictedSpike))

	if decision.Block {
		w.Header().Set("X-RateLimit-ML-Reason", decision.Reason)
		w.Header().Set("X-RateLimit-ML-Duration", decision.Duration.String())
		w.Header().Set("X-RateLimit-ML-Escalation", fmt.Sprintf("%d", decision.Escalation))
	}
}

// Background tasks

func (p *RateLimitMLPlugin) runAnomalyDetection(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.detectGlobalAnomalies()
		case <-p.shutdownCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (p *RateLimitMLPlugin) detectGlobalAnomalies() {
	patterns := p.patternAnalyzer.GetActivePatterns()

	// Detect coordinated attacks
	if coordinated := p.detectCoordinatedAttack(patterns); coordinated != nil {
		p.handleCoordinatedAttack(coordinated)
	}

	// Detect traffic anomalies
	if anomaly := p.detectTrafficAnomaly(patterns); anomaly != nil {
		p.handleTrafficAnomaly(anomaly)
	}
}

// PatternAnalyzer analyzes request patterns
type PatternAnalyzer struct {
	patterns    map[string]*TrafficPattern
	timeWindows map[string][]TimeWindow
	mu          sync.RWMutex
}

type TimeWindow struct {
	Start    time.Time
	End      time.Time
	Requests int
	Unique   int
}

func NewPatternAnalyzer() *PatternAnalyzer {
	return &PatternAnalyzer{
		patterns:    make(map[string]*TrafficPattern),
		timeWindows: make(map[string][]TimeWindow),
	}
}

func (pa *PatternAnalyzer) AnalyzeRequest(clientIP string, r *http.Request) *TrafficPattern {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	pattern, exists := pa.patterns[clientIP]
	if !exists {
		pattern = &TrafficPattern{
			ClientIP:    clientIP,
			LastUpdated: time.Now(),
		}
		pa.patterns[clientIP] = pattern
	}

	// Update request rate
	window := pa.getCurrentWindow(clientIP)
	window.Requests++

	// Calculate entropy
	pattern.Entropy = pa.calculateEntropy(clientIP)

	// Detect burst patterns
	pattern.BurstPattern = pa.detectBursts(clientIP)

	// Calculate periodicity
	pattern.Periodicity = pa.calculatePeriodicity(clientIP)

	// Calculate predictability
	pattern.Predictability = pa.calculatePredictability(pattern)

	pattern.LastUpdated = time.Now()

	return pattern
}

func (pa *PatternAnalyzer) getCurrentWindow(clientIP string) *TimeWindow {
	now := time.Now()
	windows := pa.timeWindows[clientIP]

	// Find or create current window
	for i := range windows {
		if now.After(windows[i].Start) && now.Before(windows[i].End) {
			return &windows[i]
		}
	}

	// Create new window
	newWindow := TimeWindow{
		Start: now.Truncate(time.Minute),
		End:   now.Truncate(time.Minute).Add(time.Minute),
	}

	pa.timeWindows[clientIP] = append(windows, newWindow)

	// Keep only recent windows
	if len(pa.timeWindows[clientIP]) > 60 {
		pa.timeWindows[clientIP] = pa.timeWindows[clientIP][1:]
	}

	return &pa.timeWindows[clientIP][len(pa.timeWindows[clientIP])-1]
}

func (pa *PatternAnalyzer) calculateEntropy(clientIP string) float64 {
	windows := pa.timeWindows[clientIP]
	if len(windows) < 2 {
		return 1.0
	}

	// Calculate Shannon entropy of request intervals
	intervals := make(map[int]int)
	for i := 1; i < len(windows); i++ {
		interval := int(windows[i].Start.Sub(windows[i-1].Start).Seconds())
		intervals[interval]++
	}

	total := len(windows) - 1
	entropy := 0.0

	for _, count := range intervals {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	// Normalize
	maxEntropy := math.Log2(float64(total))
	if maxEntropy > 0 {
		entropy /= maxEntropy
	}

	return entropy
}

func (pa *PatternAnalyzer) GetActivePatterns() map[string]*TrafficPattern {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	active := make(map[string]*TrafficPattern)
	cutoff := time.Now().Add(-5 * time.Minute)

	for ip, pattern := range pa.patterns {
		if pattern.LastUpdated.After(cutoff) {
			// Return copy
			patternCopy := *pattern
			active[ip] = &patternCopy
		}
	}

	return active
}

// TrafficPredictor predicts future traffic behavior
type TrafficPredictor struct {
	window      time.Duration
	predictions map[string]*BehaviorPrediction
	history     map[string][]HistoricalData
	mu          sync.RWMutex
}

type BehaviorPrediction struct {
	PredictedRate  float64
	PredictedSpike float64
	Confidence     float64
	TimeHorizon    time.Duration
}

type HistoricalData struct {
	Timestamp time.Time
	Rate      float64
	Pattern   string
}

func NewTrafficPredictor(window string) *TrafficPredictor {
	duration, _ := time.ParseDuration(window)
	if duration == 0 {
		duration = 5 * time.Minute
	}

	return &TrafficPredictor{
		window:      duration,
		predictions: make(map[string]*BehaviorPrediction),
		history:     make(map[string][]HistoricalData),
	}
}

func (tp *TrafficPredictor) PredictBehavior(pattern *TrafficPattern) *BehaviorPrediction {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	// Simple prediction based on recent history
	history := tp.history[pattern.ClientIP]

	if len(history) < 5 {
		// Not enough data
		return &BehaviorPrediction{
			PredictedRate:  pattern.RequestRate,
			PredictedSpike: pattern.RequestRate,
			Confidence:     0.3,
			TimeHorizon:    tp.window,
		}
	}

	// Calculate trend
	trend := tp.calculateTrend(history)

	// Predict future rate
	prediction := &BehaviorPrediction{
		PredictedRate:  pattern.RequestRate * (1 + trend),
		PredictedSpike: pattern.RequestRate * (1 + trend*2),
		Confidence:     0.7,
		TimeHorizon:    tp.window,
	}

	// Adjust confidence based on pattern predictability
	prediction.Confidence *= pattern.Predictability

	tp.predictions[pattern.ClientIP] = prediction

	// Update history
	tp.history[pattern.ClientIP] = append(history, HistoricalData{
		Timestamp: time.Now(),
		Rate:      pattern.RequestRate,
		Pattern:   "normal", // Simplified
	})

	// Keep history bounded
	if len(tp.history[pattern.ClientIP]) > 100 {
		tp.history[pattern.ClientIP] = tp.history[pattern.ClientIP][50:]
	}

	return prediction
}

func (tp *TrafficPredictor) calculateTrend(history []HistoricalData) float64 {
	if len(history) < 2 {
		return 0
	}

	// Simple linear trend
	firstRate := history[0].Rate
	lastRate := history[len(history)-1].Rate

	if firstRate == 0 {
		return 0
	}

	return (lastRate - firstRate) / firstRate
}

// RateLimitCoordinator coordinates with base rate limiter
type RateLimitCoordinator struct {
	mlBlocks map[string]MLBlock
	mu       sync.RWMutex
}

type MLBlock struct {
	ClientIP   string
	Reason     string
	Duration   time.Duration
	Escalation int
	AppliedAt  time.Time
}

func NewRateLimitCoordinator() *RateLimitCoordinator {
	return &RateLimitCoordinator{
		mlBlocks: make(map[string]MLBlock),
	}
}

func (rlc *RateLimitCoordinator) ApplyMLBlock(clientIP string, decision Decision) {
	rlc.mu.Lock()
	defer rlc.mu.Unlock()

	block := MLBlock{
		ClientIP:   clientIP,
		Reason:     decision.Reason,
		Duration:   decision.Duration,
		Escalation: decision.Escalation,
		AppliedAt:  time.Now(),
	}

	rlc.mlBlocks[clientIP] = block

	// Publish event for base rate limiter
	// In production, would use proper event system
}

// MLMetrics collects and records ML-related metrics
type MLMetrics struct {
	mu                sync.Mutex
	requestCounts     map[string]int
	anomalyScores     map[string][]float64
	decisions         map[string][]Decision
	AnomaliesDetected int64
	PredictionsMade   int64
	ModelUpdates      int64
	TruePositives     int64
	FalsePositives    int64
}

func NewMLMetrics() *MLMetrics {
	return &MLMetrics{
		requestCounts: make(map[string]int),
		anomalyScores: make(map[string][]float64),
		decisions:     make(map[string][]Decision),
	}
}

func (m *MLMetrics) RecordRequest(clientIP string, anomalyScore float64, decision Decision) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.requestCounts[clientIP]++
	m.anomalyScores[clientIP] = append(m.anomalyScores[clientIP], anomalyScore)
	m.decisions[clientIP] = append(m.decisions[clientIP], decision)
}

// Helper functions

func (p *RateLimitMLPlugin) extractClientIP(r *http.Request) string {
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

func (p *RateLimitMLPlugin) detectCoordinatedAttack(patterns map[string]*TrafficPattern) *CoordinatedAttack {
	// Simplified coordination detection
	var highAnomalyIPs []string

	for ip, pattern := range patterns {
		if pattern.AnomalyScore > 0.8 {
			highAnomalyIPs = append(highAnomalyIPs, ip)
		}
	}

	if len(highAnomalyIPs) > 10 {
		return &CoordinatedAttack{
			IPs:       highAnomalyIPs,
			StartTime: time.Now(),
			Type:      "distributed_anomaly",
		}
	}

	return nil
}

type CoordinatedAttack struct {
	IPs       []string
	StartTime time.Time
	Type      string
}

func (p *RateLimitMLPlugin) handleCoordinatedAttack(attack *CoordinatedAttack) {
	// Apply coordinated response
	for _, ip := range attack.IPs {
		decision := Decision{
			Block:      true,
			Reason:     "Coordinated attack detected",
			Duration:   24 * time.Hour,
			Escalation: 5,
		}

		p.coordinator.ApplyMLBlock(ip, decision)
	}

	// Alert administrators
	p.host.PublishEvent(plugin.PluginEvent{
		Type: "ml.coordinated_attack",
		Data: map[string]interface{}{
			"ips":   attack.IPs,
			"type":  attack.Type,
			"count": len(attack.IPs),
		},
	})
}

func (p *RateLimitMLPlugin) detectTrafficAnomaly(patterns map[string]*TrafficPattern) *TrafficAnomaly {
	// Detect global traffic anomalies
	totalRate := 0.0
	count := 0

	for _, pattern := range patterns {
		totalRate += pattern.RequestRate
		count++
	}

	if count == 0 {
		return nil
	}

	avgRate := totalRate / float64(count)

	// Check if average rate is anomalous
	// In production, would compare with historical baseline
	if avgRate > 1000 {
		return &TrafficAnomaly{
			Type:        "traffic_spike",
			Severity:    "high",
			Description: fmt.Sprintf("Global traffic spike: %.1f req/s", avgRate),
		}
	}

	return nil
}

type TrafficAnomaly struct {
	Type        string
	Severity    string
	Description string
}

func (p *RateLimitMLPlugin) handleTrafficAnomaly(anomaly *TrafficAnomaly) {
	// Log and alert
	p.host.PublishEvent(plugin.PluginEvent{
		Type: "ml.traffic_anomaly",
		Data: map[string]interface{}{
			"type":        anomaly.Type,
			"severity":    anomaly.Severity,
			"description": anomaly.Description,
		},
	})
}

// Priority returns the plugin priority (higher numbers run later)
func (p *RateLimitMLPlugin) Priority() int {
	return 125 // Run after basic rate limiting, before threat intel
}

// AnomalyDetector components

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(modelPath string, threshold float64) *AnomalyDetector {
	return &AnomalyDetector{
		modelPath: modelPath,
		threshold: threshold,
	}
}

// LoadModel loads the ML model (placeholder implementation)
func (ad *AnomalyDetector) LoadModel() error {
	// In a real implementation, this would load a trained model
	return nil
}

// SaveModel saves the ML model (placeholder implementation)
func (ad *AnomalyDetector) SaveModel() error {
	// In a real implementation, this would save the model
	return nil
}

// DetectAnomaly detects anomalies in traffic patterns
func (ad *AnomalyDetector) DetectAnomaly(pattern *TrafficPattern) float64 {
	// Placeholder anomaly detection
	// In a real implementation, this would use the ML model
	score := 0.0

	// Simple heuristics for demonstration
	if pattern.RequestRate > 100 {
		score += 0.3
	}
	if pattern.EntropyScore > 0.8 {
		score += 0.2
	}
	if pattern.IsAnomalous {
		score += 0.5
	}

	return score
}

// MLMetrics methods

// GetCurrentMetrics returns current metrics
func (m *MLMetrics) GetCurrentMetrics() map[string]interface{} {
	return map[string]interface{}{
		"anomalies_detected": m.AnomaliesDetected,
		"predictions_made":   m.PredictionsMade,
		"model_updates":      m.ModelUpdates,
		"true_positives":     m.TruePositives,
		"false_positives":    m.FalsePositives,
	}
}

// RecordAnomaly records an anomaly detection
func (m *MLMetrics) RecordAnomaly(clientIP string, score float64) {
	m.AnomaliesDetected++
}

// RecordPatternAnalysis records pattern analysis completion
func (m *MLMetrics) RecordPatternAnalysis() {
	// Update pattern analysis metrics
}

// RecordModelUpdate records a model update
func (m *MLMetrics) RecordModelUpdate() {
	m.ModelUpdates++
}

// RecordLearningData records new learning data
func (m *MLMetrics) RecordLearningData(clientIP string) {
	// Record learning data metrics
}

// GetPlugin returns a new instance of the plugin for dynamic loading
func GetPlugin() plugin.Plugin {
	return &RateLimitMLPlugin{}
}

// HTTP Handlers

func (p *RateLimitMLPlugin) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"plugin":            p.Name(),
		"version":           p.Version(),
		"enabled":           p.config.Enabled,
		"anomaly_threshold": p.config.AnomalyThreshold,
		"learning_enabled":  p.config.LearningEnabled,
		"metrics":           p.metrics.GetCurrentMetrics(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (p *RateLimitMLPlugin) handlePatterns(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	patterns := make([]TrafficPattern, 0)
	// Get recent patterns from analyzer
	if p.patternAnalyzer != nil {
		// Return analyzed patterns
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(patterns)
		p.mu.RUnlock()
		return
	}
	p.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"patterns": patterns,
		"count":    len(patterns),
	})
}

// Background Tasks

func (p *RateLimitMLPlugin) runPatternAnalysis() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.analyzeCurrentPatterns()
		case <-p.shutdownCh:
			return
		}
	}
}

func (p *RateLimitMLPlugin) runModelUpdate() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if p.config.LearningEnabled {
				p.updateModel()
			}
		case <-p.shutdownCh:
			return
		}
	}
}

func (p *RateLimitMLPlugin) analyzeCurrentPatterns() {
	// Pattern analysis logic
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.patternAnalyzer != nil {
		// Analyze patterns and detect anomalies
		p.metrics.RecordPatternAnalysis()
	}
}

func (p *RateLimitMLPlugin) updateModel() {
	// Model update logic
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.anomalyDetector != nil && p.config.LearningEnabled {
		// Update the ML model with new data
		p.metrics.RecordModelUpdate()
	}
}

// Event Handlers

func (p *RateLimitMLPlugin) handleRateLimitRequest(event plugin.PluginEvent) error {
	data := event.Data
	if len(data) == 0 {
		return fmt.Errorf("empty event data")
	}

	clientIP, ok := data["client_ip"].(string)
	if !ok {
		return fmt.Errorf("missing client_ip in event data")
	}

	// Process rate limit request with ML analysis
	if p.anomalyDetector != nil {
		// Analyze request pattern
		score := p.analyzeRequestPattern(clientIP, data)
		if score > p.config.AnomalyThreshold {
			// Anomaly detected
			p.metrics.RecordAnomaly(clientIP, score)
		}
	}

	return nil
}

func (p *RateLimitMLPlugin) handleRateLimitViolation(event plugin.PluginEvent) error {
	data := event.Data
	if len(data) == 0 {
		return fmt.Errorf("empty event data")
	}

	clientIP, ok := data["client_ip"].(string)
	if !ok {
		return fmt.Errorf("missing client_ip in event data")
	}

	// Learn from violation pattern
	if p.config.LearningEnabled {
		p.updateLearningData(clientIP, data)
	}

	return nil
}

func (p *RateLimitMLPlugin) analyzeRequestPattern(clientIP string, data map[string]interface{}) float64 {
	// Simple anomaly score calculation
	// In a real implementation, this would use the ML model
	return 0.5
}

func (p *RateLimitMLPlugin) updateLearningData(clientIP string, data map[string]interface{}) {
	// Update learning data for the ML model
	p.mu.Lock()
	defer p.mu.Unlock()

	// Store pattern data for model update
	p.metrics.RecordLearningData(clientIP)
}

// PatternAnalyzer missing methods

func (pa *PatternAnalyzer) detectBursts(clientIP string) []int {
	// Simple burst detection - returns burst pattern array
	windows := pa.timeWindows[clientIP]
	if len(windows) < 2 {
		return []int{}
	}

	// Calculate burst pattern based on request spikes
	bursts := make([]int, 0)
	for i := 1; i < len(windows); i++ {
		if windows[i].Requests > windows[i-1].Requests*2 {
			bursts = append(bursts, i)
		}
	}
	return bursts
}

func (pa *PatternAnalyzer) calculatePeriodicity(clientIP string) float64 {
	// Simple periodicity calculation
	windows := pa.timeWindows[clientIP]
	if len(windows) < 3 {
		return 0.0
	}

	// Basic periodicity detection based on request intervals
	var totalPeriod float64
	count := 0
	for i := 2; i < len(windows); i++ {
		period1 := windows[i-1].Start.Sub(windows[i-2].Start)
		period2 := windows[i].Start.Sub(windows[i-1].Start)
		if period1 > 0 && period2 > 0 {
			periodicity := 1.0 - math.Abs(period1.Seconds()-period2.Seconds())/math.Max(period1.Seconds(), period2.Seconds())
			totalPeriod += periodicity
			count++
		}
	}

	if count > 0 {
		return totalPeriod / float64(count)
	}
	return 0.0
}

func (pa *PatternAnalyzer) calculatePredictability(pattern *TrafficPattern) float64 {
	// Simple predictability calculation based on entropy and periodicity
	if pattern.Entropy == 0 {
		return 1.0 // Completely predictable
	}

	// Combine entropy and periodicity to calculate predictability
	entropyFactor := 1.0 - math.Min(pattern.Entropy, 1.0)
	periodicityFactor := pattern.Periodicity

	return (entropyFactor + periodicityFactor) / 2.0
}
