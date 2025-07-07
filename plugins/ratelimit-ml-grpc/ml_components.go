// ML components for advanced rate limiting
package main

import (
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
)

// TrafficPrediction represents predicted traffic behavior
type TrafficPrediction struct {
	ClientIP          string
	PredictedRate     float64
	RiskLevel         string // "low", "medium", "high"
	Confidence        float64
	Warning           string
	PredictionWindow  time.Duration
	NextBurstTime     *time.Time
}

// AnomalyDetector implements advanced anomaly detection
type AnomalyDetector struct {
	modelPath      string
	threshold      float64
	modelLoaded    bool
	patterns       map[string]*TrafficPattern
	threatHistory  map[string][]ThreatEvent
	mu             sync.RWMutex
}

// ThreatEvent represents a recorded threat
type ThreatEvent struct {
	Timestamp   time.Time
	ThreatType  string
	Description string
	Severity    string
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(modelPath string, threshold float64) *AnomalyDetector {
	return &AnomalyDetector{
		modelPath:     modelPath,
		threshold:     threshold,
		patterns:      make(map[string]*TrafficPattern),
		threatHistory: make(map[string][]ThreatEvent),
	}
}

// Initialize initializes the anomaly detector
func (ad *AnomalyDetector) Initialize() error {
	// Simplified model loading
	ad.mu.Lock()
	defer ad.mu.Unlock()
	
	ad.modelLoaded = true
	return nil
}

// DetectAnomaly detects anomalies in traffic patterns
func (ad *AnomalyDetector) DetectAnomaly(pattern *TrafficPattern) float64 {
	if !ad.modelLoaded {
		return 0.0
	}

	// Simplified anomaly detection algorithm
	score := 0.0

	// High request rate anomaly
	if pattern.RequestRate > 20.0 {
		score += 0.3 * math.Min(1.0, pattern.RequestRate/100.0)
	}

	// Low entropy (repetitive patterns)
	if pattern.Entropy < 0.5 {
		score += 0.4 * (0.5 - pattern.Entropy)
	}

	// High predictability (bot-like behavior)
	if pattern.Predictability > 0.8 {
		score += 0.3 * pattern.Predictability
	}

	// Check against historical patterns
	ad.mu.RLock()
	if threats, exists := ad.threatHistory[pattern.ClientIP]; exists && len(threats) > 0 {
		// Increase score if this IP has threat history
		score += 0.2
	}
	ad.mu.RUnlock()

	// Add some controlled randomness
	score += (rand.Float64() - 0.5) * 0.1

	return math.Max(0.0, math.Min(1.0, score))
}

// UpdateModel updates the ML model with new patterns
func (ad *AnomalyDetector) UpdateModel(pattern *TrafficPattern) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Store pattern for learning
	ad.patterns[pattern.ClientIP] = pattern
}

// RecordThreat records a threat for this IP
func (ad *AnomalyDetector) RecordThreat(clientIP, threatType, description string) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	threat := ThreatEvent{
		Timestamp:   time.Now(),
		ThreatType:  threatType,
		Description: description,
		Severity:    "medium",
	}

	threats := ad.threatHistory[clientIP]
	threats = append(threats, threat)

	// Keep only recent threats (last 24 hours)
	cutoff := time.Now().Add(-24 * time.Hour)
	filtered := make([]ThreatEvent, 0)
	for _, t := range threats {
		if t.Timestamp.After(cutoff) {
			filtered = append(filtered, t)
		}
	}

	ad.threatHistory[clientIP] = filtered
}

// IsModelLoaded returns whether the model is loaded
func (ad *AnomalyDetector) IsModelLoaded() bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return ad.modelLoaded
}

// SaveModel saves the current model state
func (ad *AnomalyDetector) SaveModel() error {
	// Simplified model saving
	return nil
}

// PatternAnalyzer analyzes traffic patterns
type PatternAnalyzer struct {
	patterns       map[string]*TrafficPattern
	requestHistory map[string][]RequestInfo
	mu             sync.RWMutex
}

// RequestInfo represents information about a request
type RequestInfo struct {
	Timestamp time.Time
	Path      string
	Method    string
	UserAgent string
}

// NewPatternAnalyzer creates a new pattern analyzer
func NewPatternAnalyzer() *PatternAnalyzer {
	return &PatternAnalyzer{
		patterns:       make(map[string]*TrafficPattern),
		requestHistory: make(map[string][]RequestInfo),
	}
}

// AnalyzeRequest analyzes a request and updates patterns
func (pa *PatternAnalyzer) AnalyzeRequest(clientIP string, req *proto.HTTPRequest) *TrafficPattern {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	// Get or create pattern
	pattern, exists := pa.patterns[clientIP]
	if !exists {
		pattern = &TrafficPattern{
			ClientIP:    clientIP,
			LastUpdated: time.Now(),
		}
		pa.patterns[clientIP] = pattern
	}

	// Add request to history
	requestInfo := RequestInfo{
		Timestamp: time.Now(),
		Path:      req.Path,
		Method:    req.Method,
		UserAgent: req.Headers["User-Agent"],
	}

	history := pa.requestHistory[clientIP]
	history = append(history, requestInfo)

	// Keep only recent history (last hour)
	cutoff := time.Now().Add(-1 * time.Hour)
	filtered := make([]RequestInfo, 0)
	for _, r := range history {
		if r.Timestamp.After(cutoff) {
			filtered = append(filtered, r)
		}
	}
	pa.requestHistory[clientIP] = filtered

	// Calculate metrics
	pattern.RequestRate = pa.calculateRequestRate(filtered)
	pattern.Entropy = pa.calculateEntropy(filtered)
	pattern.Predictability = pa.calculatePredictability(filtered)
	pattern.BurstPattern = pa.calculateBurstPattern(filtered)
	pattern.LastUpdated = time.Now()

	// Calculate anomaly score based on patterns
	pattern.AnomalyScore = pa.calculateAnomalyScore(pattern)
	pattern.IsAnomalous = pattern.AnomalyScore > 0.7

	return pattern
}

// GetPattern returns the current pattern for a client
func (pa *PatternAnalyzer) GetPattern(clientIP string) *TrafficPattern {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	pattern, exists := pa.patterns[clientIP]
	if !exists {
		return nil
	}

	// Return a copy
	patternCopy := *pattern
	return &patternCopy
}

// GetPatternCount returns the number of tracked patterns
func (pa *PatternAnalyzer) GetPatternCount() int {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	return len(pa.patterns)
}

func (pa *PatternAnalyzer) calculateRequestRate(history []RequestInfo) float64 {
	if len(history) == 0 {
		return 0.0
	}

	// Calculate requests per minute over the last 5 minutes
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)
	recentRequests := 0

	for _, req := range history {
		if req.Timestamp.After(fiveMinutesAgo) {
			recentRequests++
		}
	}

	return float64(recentRequests) / 5.0
}

func (pa *PatternAnalyzer) calculateEntropy(history []RequestInfo) float64 {
	if len(history) == 0 {
		return 0.0
	}

	// Calculate path entropy
	pathCounts := make(map[string]int)
	for _, req := range history {
		pathCounts[req.Path]++
	}

	entropy := 0.0
	total := float64(len(history))

	for _, count := range pathCounts {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	// Normalize to 0-1 range
	maxEntropy := math.Log2(float64(len(pathCounts)))
	if maxEntropy > 0 {
		entropy /= maxEntropy
	}

	return entropy
}

func (pa *PatternAnalyzer) calculatePredictability(history []RequestInfo) float64 {
	if len(history) < 3 {
		return 0.0
	}

	// Simple predictability based on request intervals
	intervals := make([]time.Duration, 0)
	for i := 1; i < len(history); i++ {
		interval := history[i].Timestamp.Sub(history[i-1].Timestamp)
		intervals = append(intervals, interval)
	}

	// Calculate variance in intervals
	if len(intervals) == 0 {
		return 0.0
	}

	mean := time.Duration(0)
	for _, interval := range intervals {
		mean += interval
	}
	mean /= time.Duration(len(intervals))

	variance := time.Duration(0)
	for _, interval := range intervals {
		diff := interval - mean
		variance += diff * diff / time.Duration(len(intervals))
	}

	// Lower variance = higher predictability
	if mean == 0 {
		return 1.0
	}

	cv := float64(variance) / float64(mean*mean) // Coefficient of variation
	predictability := 1.0 / (1.0 + cv)          // Inverse relationship

	return math.Max(0.0, math.Min(1.0, predictability))
}

func (pa *PatternAnalyzer) calculateBurstPattern(history []RequestInfo) []int {
	// Simplified burst pattern detection
	// Divide last hour into 5-minute buckets
	buckets := make([]int, 12) // 12 buckets of 5 minutes each
	now := time.Now()

	for _, req := range history {
		minutesAgo := int(now.Sub(req.Timestamp).Minutes())
		bucketIndex := minutesAgo / 5
		if bucketIndex >= 0 && bucketIndex < 12 {
			buckets[11-bucketIndex]++ // Reverse order (most recent first)
		}
	}

	return buckets
}

func (pa *PatternAnalyzer) calculateAnomalyScore(pattern *TrafficPattern) float64 {
	score := 0.0

	// High rate
	if pattern.RequestRate > 10.0 {
		score += 0.3
	}

	// Low entropy
	if pattern.Entropy < 0.3 {
		score += 0.4
	}

	// High predictability
	if pattern.Predictability > 0.8 {
		score += 0.3
	}

	return math.Max(0.0, math.Min(1.0, score))
}

// TrafficPredictor predicts future traffic patterns
type TrafficPredictor struct {
	predictions map[string]*TrafficPrediction
	mu          sync.RWMutex
}

// NewTrafficPredictor creates a new traffic predictor
func NewTrafficPredictor() *TrafficPredictor {
	return &TrafficPredictor{
		predictions: make(map[string]*TrafficPrediction),
	}
}

// PredictTraffic predicts future traffic for a client
func (tp *TrafficPredictor) PredictTraffic(clientIP string, pattern *TrafficPattern) *TrafficPrediction {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	prediction := &TrafficPrediction{
		ClientIP:         clientIP,
		PredictedRate:    pattern.RequestRate * 1.2, // Simple prediction
		Confidence:       0.7,
		PredictionWindow: 5 * time.Minute,
	}

	// Determine risk level
	if pattern.AnomalyScore > 0.7 || pattern.RequestRate > 20.0 {
		prediction.RiskLevel = "high"
		prediction.Warning = "High anomaly score or request rate detected"
	} else if pattern.AnomalyScore > 0.4 || pattern.RequestRate > 10.0 {
		prediction.RiskLevel = "medium"
		prediction.Warning = "Moderate anomaly indicators"
	} else {
		prediction.RiskLevel = "low"
	}

	// Predict next burst time if pattern is bursty
	if len(pattern.BurstPattern) > 0 {
		// Simple burst prediction based on recent pattern
		maxBurst := 0
		for _, burst := range pattern.BurstPattern {
			if burst > maxBurst {
				maxBurst = burst
			}
		}
		if maxBurst > 5 {
			nextBurst := time.Now().Add(5 * time.Minute)
			prediction.NextBurstTime = &nextBurst
		}
	}

	tp.predictions[clientIP] = prediction
	return prediction
}

// RateLimitCoordinator coordinates with other rate limiting systems
type RateLimitCoordinator struct {
	activeBlocks map[string]BlockInfo
	mu           sync.RWMutex
}

// BlockInfo represents information about an active block
type BlockInfo struct {
	ClientIP    string
	Reason      string
	Duration    time.Duration
	StartTime   time.Time
	Source      string
}

// NewRateLimitCoordinator creates a new coordinator
func NewRateLimitCoordinator() *RateLimitCoordinator {
	return &RateLimitCoordinator{
		activeBlocks: make(map[string]BlockInfo),
	}
}

// NotifyBlock notifies about a block decision
func (rc *RateLimitCoordinator) NotifyBlock(clientIP, reason string, duration time.Duration) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.activeBlocks[clientIP] = BlockInfo{
		ClientIP:  clientIP,
		Reason:    reason,
		Duration:  duration,
		StartTime: time.Now(),
		Source:    "ml-ratelimit",
	}
}

// MLMetrics collects ML-specific metrics
type MLMetrics struct {
	requestCount    int64
	patternCount    int64
	anomalyCount    int64
	predictionCount int64
	mu              sync.RWMutex
}

// NewMLMetrics creates a new metrics collector
func NewMLMetrics() *MLMetrics {
	return &MLMetrics{}
}

// RecordRequest records a processed request
func (m *MLMetrics) RecordRequest(clientIP string, pattern *TrafficPattern, anomalyScore float64, blocked bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.requestCount++
	
	if anomalyScore > 0.5 {
		m.anomalyCount++
	}
}

// GetRequestCount returns the total request count
func (m *MLMetrics) GetRequestCount() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.requestCount
}