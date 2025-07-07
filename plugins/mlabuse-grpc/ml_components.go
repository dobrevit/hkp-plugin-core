// ML Components for abuse detection
package main

import (
	"math"
	"math/rand"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
)

// BehaviorAnalyzer analyzes client behavioral patterns
type BehaviorAnalyzer struct {
	profiles   map[string]*BehaviorProfile
	windowSize int
	mu         sync.RWMutex
}

// NewBehaviorAnalyzer creates a new behavior analyzer
func NewBehaviorAnalyzer(windowSize int) *BehaviorAnalyzer {
	return &BehaviorAnalyzer{
		profiles:   make(map[string]*BehaviorProfile),
		windowSize: windowSize,
	}
}

// AnalyzeHTTPRequest analyzes an HTTP request and updates behavior profile
func (ba *BehaviorAnalyzer) AnalyzeHTTPRequest(clientIP string, req *proto.HTTPRequest) *BehaviorProfile {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	profile, exists := ba.profiles[clientIP]
	if !exists {
		profile = &BehaviorProfile{
			ClientIP:          clientIP,
			RequestIntervals:  make([]time.Duration, 0),
			PathSequences:     make([]string, 0),
			UserAgentRotation: make([]string, 0),
			LastUpdated:       time.Now(),
		}
		ba.profiles[clientIP] = profile
	}

	// Update path sequences
	profile.PathSequences = append(profile.PathSequences, req.Path)
	if len(profile.PathSequences) > ba.windowSize {
		profile.PathSequences = profile.PathSequences[1:]
	}

	// Update user agent tracking
	if userAgent, exists := req.Headers["User-Agent"]; exists {
		if len(profile.UserAgentRotation) == 0 || profile.UserAgentRotation[len(profile.UserAgentRotation)-1] != userAgent {
			profile.UserAgentRotation = append(profile.UserAgentRotation, userAgent)
			if len(profile.UserAgentRotation) > 10 {
				profile.UserAgentRotation = profile.UserAgentRotation[1:]
			}
		}
	}

	// Calculate entropy metrics
	profile.EntropyMetrics = ba.calculateEntropy(profile)

	// Update session behavior
	profile.SessionBehavior.RequestCount++
	profile.SessionBehavior.UniquePathsCount = ba.countUniquePaths(profile.PathSequences)

	profile.LastUpdated = time.Now()

	return profile
}

// AnalyzeKeySubmission analyzes key submission patterns
func (ba *BehaviorAnalyzer) AnalyzeKeySubmission(fingerprint string, keyData []byte) {
	// Simplified key submission analysis
	// In a real implementation, this would analyze key patterns, sizes, etc.
}

// GetProfile returns a behavior profile for a client
func (ba *BehaviorAnalyzer) GetProfile(clientIP string) *BehaviorProfile {
	ba.mu.RLock()
	defer ba.mu.RUnlock()

	return ba.profiles[clientIP]
}

// UpdateProfile updates a profile with timing information
func (ba *BehaviorAnalyzer) UpdateProfile(clientIP string, req *proto.HTTPRequest, responseTime time.Duration) {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	if profile, exists := ba.profiles[clientIP]; exists {
		profile.RequestIntervals = append(profile.RequestIntervals, responseTime)
		if len(profile.RequestIntervals) > ba.windowSize {
			profile.RequestIntervals = profile.RequestIntervals[1:]
		}
	}
}

// RecordThreat records a threat for ML learning
func (ba *BehaviorAnalyzer) RecordThreat(clientIP, threatType, description string) {
	// Record threat information for ML model training
}

// CleanupOldProfiles removes old behavior profiles
func (ba *BehaviorAnalyzer) CleanupOldProfiles() int {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	cleaned := 0

	for ip, profile := range ba.profiles {
		if profile.LastUpdated.Before(cutoff) {
			delete(ba.profiles, ip)
			cleaned++
		}
	}

	return cleaned
}

// GetRecentBehaviorData returns recent behavior data for model training
func (ba *BehaviorAnalyzer) GetRecentBehaviorData() []*BehaviorProfile {
	ba.mu.RLock()
	defer ba.mu.RUnlock()

	data := make([]*BehaviorProfile, 0, len(ba.profiles))
	for _, profile := range ba.profiles {
		data = append(data, profile)
	}
	return data
}

// RecordViolation records a rate limit violation
func (ba *BehaviorAnalyzer) RecordViolation(clientIP, reason string) {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	if profile, exists := ba.profiles[clientIP]; exists {
		profile.SessionBehavior.ErrorRate += 0.1
	}
}

// Helper methods
func (ba *BehaviorAnalyzer) calculateEntropy(profile *BehaviorProfile) EntropyMetrics {
	pathEntropy := ba.calculatePathEntropy(profile.PathSequences)
	timingEntropy := ba.calculateTimingEntropy(profile.RequestIntervals)

	return EntropyMetrics{
		PathEntropy:      pathEntropy,
		TimingEntropy:    timingEntropy,
		ParameterEntropy: 0.5, // Simplified
		OverallScore:     (pathEntropy + timingEntropy) / 2,
	}
}

func (ba *BehaviorAnalyzer) calculatePathEntropy(paths []string) float64 {
	if len(paths) == 0 {
		return 0
	}

	frequency := make(map[string]int)
	for _, path := range paths {
		frequency[path]++
	}

	entropy := 0.0
	total := float64(len(paths))

	for _, count := range frequency {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (ba *BehaviorAnalyzer) calculateTimingEntropy(intervals []time.Duration) float64 {
	if len(intervals) < 2 {
		return 0
	}

	// Simplified timing entropy calculation
	variance := 0.0
	mean := 0.0

	for _, interval := range intervals {
		mean += float64(interval.Milliseconds())
	}
	mean /= float64(len(intervals))

	for _, interval := range intervals {
		diff := float64(interval.Milliseconds()) - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	// Normalize to 0-1 range
	return math.Min(1.0, variance/1000000.0)
}

func (ba *BehaviorAnalyzer) countUniquePaths(paths []string) int {
	unique := make(map[string]bool)
	for _, path := range paths {
		unique[path] = true
	}
	return len(unique)
}

// AnomalyDetector detects anomalous behavior using ML
type AnomalyDetector struct {
	modelPath   string
	threshold   float64
	modelLoaded bool
	mu          sync.RWMutex
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(modelPath string, threshold float64) *AnomalyDetector {
	return &AnomalyDetector{
		modelPath: modelPath,
		threshold: threshold,
	}
}

// LoadModel loads the ML model
func (ad *AnomalyDetector) LoadModel() error {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Simplified model loading - in reality would load actual ML model
	ad.modelLoaded = true
	return nil
}

// SaveModel saves the current model state
func (ad *AnomalyDetector) SaveModel() error {
	// Simplified model saving
	return nil
}

// IsModelLoaded returns whether the model is loaded
func (ad *AnomalyDetector) IsModelLoaded() bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return ad.modelLoaded
}

// DetectAnomaly performs anomaly detection on a behavior profile
func (ad *AnomalyDetector) DetectAnomaly(profile *BehaviorProfile) *AnomalyScore {
	if !ad.modelLoaded {
		return &AnomalyScore{
			Score:       0.0,
			Confidence:  0.0,
			AnomalyType: "model_not_loaded",
			Reasons:     []string{"ML model not loaded"},
		}
	}

	// Simplified anomaly detection logic
	score := 0.0
	reasons := make([]string, 0)

	// Check request frequency anomalies
	if len(profile.RequestIntervals) > 10 {
		avgInterval := ad.calculateAverageInterval(profile.RequestIntervals)
		if avgInterval < 100*time.Millisecond {
			score += 0.3
			reasons = append(reasons, "extremely_high_frequency")
		}
	}

	// Check path entropy
	if profile.EntropyMetrics.PathEntropy < 0.5 {
		score += 0.2
		reasons = append(reasons, "low_path_entropy")
	}

	// Check user agent rotation (bot behavior)
	if len(profile.UserAgentRotation) > 5 {
		score += 0.4
		reasons = append(reasons, "user_agent_rotation")
	}

	// Check session behavior anomalies
	if profile.SessionBehavior.ErrorRate > 0.5 {
		score += 0.3
		reasons = append(reasons, "high_error_rate")
	}

	// Add some controlled randomness to simulate ML model uncertainty
	score += (rand.Float64() - 0.5) * 0.1

	// Ensure score is in valid range
	score = math.Max(0.0, math.Min(1.0, score))

	confidence := math.Min(1.0, score*1.2)

	anomalyType := "normal"
	if score > 0.8 {
		anomalyType = "high_risk_bot"
	} else if score > 0.6 {
		anomalyType = "suspicious_automation"
	} else if score > 0.4 {
		anomalyType = "potential_anomaly"
	}

	return &AnomalyScore{
		Score:          score,
		Confidence:     confidence,
		AnomalyType:    anomalyType,
		Reasons:        reasons,
		Recommendation: ad.getRecommendation(score),
	}
}

// UpdateModel updates the ML model with recent data
func (ad *AnomalyDetector) UpdateModel(recentData []*BehaviorProfile) error {
	// Simplified model update - in reality would retrain/update ML model
	return nil
}

func (ad *AnomalyDetector) calculateAverageInterval(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	total := time.Duration(0)
	for _, interval := range intervals {
		total += interval
	}
	return total / time.Duration(len(intervals))
}

func (ad *AnomalyDetector) getRecommendation(score float64) string {
	switch {
	case score >= 0.9:
		return "immediate_block"
	case score >= 0.7:
		return "rate_limit_strict"
	case score >= 0.5:
		return "enhanced_monitoring"
	default:
		return "continue_monitoring"
	}
}

// LLMPredictor detects AI-generated content
type LLMPredictor struct {
	threshold float64
	mu        sync.RWMutex
}

// NewLLMPredictor creates a new LLM predictor
func NewLLMPredictor(threshold float64) *LLMPredictor {
	return &LLMPredictor{
		threshold: threshold,
	}
}

// DetectLLMContentFromHTTP analyzes HTTP request for AI-generated content
func (lp *LLMPredictor) DetectLLMContentFromHTTP(req *proto.HTTPRequest) *LLMDetectionResult {
	// Simplified LLM detection based on request characteristics
	isAIGenerated := false
	syntheticScore := 0.0
	promptInjection := false
	tokenPatterns := make([]string, 0)

	// Check for common AI-generated patterns in headers and parameters
	for _, value := range req.Headers {
		if lp.containsAIPatterns(value) {
			syntheticScore += 0.3
			tokenPatterns = append(tokenPatterns, "header_ai_pattern")
		}
	}

	for _, value := range req.QueryParams {
		if lp.containsAIPatterns(value) {
			syntheticScore += 0.4
			tokenPatterns = append(tokenPatterns, "param_ai_pattern")
		}
		if lp.containsPromptInjection(value) {
			promptInjection = true
			syntheticScore += 0.6
		}
	}

	// Check request body if available
	if len(req.Body) > 0 {
		bodyStr := string(req.Body)
		if lp.containsAIPatterns(bodyStr) {
			syntheticScore += 0.5
			tokenPatterns = append(tokenPatterns, "body_ai_pattern")
		}
		if lp.containsPromptInjection(bodyStr) {
			promptInjection = true
			syntheticScore += 0.7
		}
	}

	syntheticScore = math.Min(1.0, syntheticScore)
	isAIGenerated = syntheticScore >= lp.threshold

	return &LLMDetectionResult{
		IsAIGenerated:   isAIGenerated,
		Perplexity:      lp.calculatePerplexity(string(req.Body)),
		TokenPatterns:   tokenPatterns,
		SyntheticScore:  syntheticScore,
		PromptInjection: promptInjection,
	}
}

// AnalyzeText analyzes text content for AI generation
func (lp *LLMPredictor) AnalyzeText(text string) *LLMDetectionResult {
	syntheticScore := 0.0
	tokenPatterns := make([]string, 0)

	if lp.containsAIPatterns(text) {
		syntheticScore += 0.6
		tokenPatterns = append(tokenPatterns, "ai_patterns")
	}

	promptInjection := lp.containsPromptInjection(text)
	if promptInjection {
		syntheticScore += 0.8
	}

	syntheticScore = math.Min(1.0, syntheticScore)

	return &LLMDetectionResult{
		IsAIGenerated:   syntheticScore >= lp.threshold,
		Perplexity:      lp.calculatePerplexity(text),
		TokenPatterns:   tokenPatterns,
		SyntheticScore:  syntheticScore,
		PromptInjection: promptInjection,
	}
}

func (lp *LLMPredictor) containsAIPatterns(text string) bool {
	aiPatterns := []string{
		"as an ai",
		"i'm sorry",
		"i can't",
		"i don't have the ability",
		"my training data",
		"i'm not able to",
		"as a language model",
		"i'm an artificial intelligence",
	}

	textLower := strings.ToLower(text)
	for _, pattern := range aiPatterns {
		if strings.Contains(textLower, pattern) {
			return true
		}
	}
	return false
}

func (lp *LLMPredictor) containsPromptInjection(text string) bool {
	injectionPatterns := []string{
		"ignore previous instructions",
		"new instructions:",
		"override",
		"system:",
		"<script>",
		"javascript:",
		"eval(",
		"exec(",
	}

	textLower := strings.ToLower(text)
	for _, pattern := range injectionPatterns {
		if strings.Contains(textLower, pattern) {
			return true
		}
	}
	return false
}

func (lp *LLMPredictor) calculatePerplexity(text string) float64 {
	// Simplified perplexity calculation
	if len(text) == 0 {
		return 0
	}

	// Count unique words vs total words as a proxy for perplexity
	words := strings.Fields(strings.ToLower(text))
	if len(words) == 0 {
		return 0
	}

	uniqueWords := make(map[string]bool)
	for _, word := range words {
		uniqueWords[word] = true
	}

	// Higher unique word ratio = lower perplexity (more natural)
	ratio := float64(len(uniqueWords)) / float64(len(words))
	return math.Max(0, 1.0-ratio) * 100.0
}

// MetricsCollector collects metrics for monitoring
type MetricsCollector struct {
	requestCount  int64
	anomalyCount  int64
	llmDetections int64
	memoryUsageMB float64
	mu            sync.RWMutex
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{}
}

// RecordRequest records a processed request
func (mc *MetricsCollector) RecordRequest(clientIP string, anomaly *AnomalyScore, llm *LLMDetectionResult, blocked bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.requestCount++

	if anomaly.Score > 0.5 {
		mc.anomalyCount++
	}

	if llm != nil && llm.IsAIGenerated {
		mc.llmDetections++
	}

	// Update memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	mc.memoryUsageMB = float64(m.Alloc) / 1024 / 1024
}

// GetRequestCount returns total request count
func (mc *MetricsCollector) GetRequestCount() int64 {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.requestCount
}

// GetAnomalyCount returns anomaly count
func (mc *MetricsCollector) GetAnomalyCount() int64 {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.anomalyCount
}

// GetMemoryUsageMB returns current memory usage in MB
func (mc *MetricsCollector) GetMemoryUsageMB() float64 {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.memoryUsageMB
}

// GetCurrentMetrics returns current metrics
func (mc *MetricsCollector) GetCurrentMetrics() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return map[string]interface{}{
		"requests_processed": mc.requestCount,
		"anomalies_detected": mc.anomalyCount,
		"llm_detections":     mc.llmDetections,
		"memory_usage_mb":    mc.memoryUsageMB,
	}
}

// ReportStatistics logs current statistics
func (mc *MetricsCollector) ReportStatistics() {
	// Log current statistics - simplified implementation
}
