package mlabuse

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

// BehaviorAnalyzer analyzes request patterns and builds behavioral profiles
type BehaviorAnalyzer struct {
	profiles      map[string]*BehaviorProfile
	windowSize    int
	mu            sync.RWMutex
	violationData map[string][]ViolationRecord
}

// ViolationRecord tracks rate limit violations
type ViolationRecord struct {
	Timestamp time.Time
	Reason    string
	Severity  int
}

// NewBehaviorAnalyzer creates a new behavior analyzer
func NewBehaviorAnalyzer(windowSize int) *BehaviorAnalyzer {
	return &BehaviorAnalyzer{
		profiles:      make(map[string]*BehaviorProfile),
		windowSize:    windowSize,
		violationData: make(map[string][]ViolationRecord),
	}
}

// AnalyzeRequest analyzes an incoming request and returns a behavior profile
func (ba *BehaviorAnalyzer) AnalyzeRequest(clientIP string, r *http.Request) *BehaviorProfile {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	// Get or create profile
	profile, exists := ba.profiles[clientIP]
	if !exists {
		profile = &BehaviorProfile{
			ClientIP:          clientIP,
			RequestIntervals:  make([]time.Duration, 0, ba.windowSize),
			PathSequences:     make([]string, 0, ba.windowSize),
			UserAgentRotation: make([]string, 0),
			LastUpdated:       time.Now(),
		}
		ba.profiles[clientIP] = profile
	}

	// Update timing intervals
	if exists {
		interval := time.Since(profile.LastUpdated)
		profile.RequestIntervals = append(profile.RequestIntervals, interval)
		if len(profile.RequestIntervals) > ba.windowSize {
			profile.RequestIntervals = profile.RequestIntervals[1:]
		}
	}

	// Update path sequences
	profile.PathSequences = append(profile.PathSequences, r.URL.Path)
	if len(profile.PathSequences) > ba.windowSize {
		profile.PathSequences = profile.PathSequences[1:]
	}

	// Track user agent rotation
	userAgent := r.Header.Get("User-Agent")
	if !contains(profile.UserAgentRotation, userAgent) {
		profile.UserAgentRotation = append(profile.UserAgentRotation, userAgent)
	}

	// Calculate TLS fingerprint
	if r.TLS != nil {
		profile.TLSFingerprint = calculateTLSFingerprint(r.TLS)
	}

	// Update session behavior
	ba.updateSessionBehavior(profile, r)

	// Calculate entropy metrics
	profile.EntropyMetrics = ba.calculateEntropy(profile)

	// Calculate payload similarity for POST/PUT requests
	if r.Method == "POST" || r.Method == "PUT" {
		profile.PayloadSimilarity = ba.calculatePayloadSimilarity(r)
	}

	profile.LastUpdated = time.Now()

	return profile
}

// UpdateProfile updates the behavior profile after request processing
func (ba *BehaviorAnalyzer) UpdateProfile(clientIP string, r *http.Request, processingTime time.Duration) {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	profile, exists := ba.profiles[clientIP]
	if !exists {
		return
	}

	// Update session metrics
	profile.SessionBehavior.RequestCount++

	// Track unique paths
	uniquePaths := make(map[string]bool)
	for _, path := range profile.PathSequences {
		uniquePaths[path] = true
	}
	profile.SessionBehavior.UniquePathsCount = len(uniquePaths)

	// Update session duration
	if profile.SessionBehavior.SessionDuration == 0 {
		profile.SessionBehavior.SessionDuration = time.Since(profile.LastUpdated)
	} else {
		profile.SessionBehavior.SessionDuration += time.Since(profile.LastUpdated)
	}
}

// calculateEntropy calculates various entropy metrics for the behavior
func (ba *BehaviorAnalyzer) calculateEntropy(profile *BehaviorProfile) EntropyMetrics {
	metrics := EntropyMetrics{}

	// Timing entropy
	if len(profile.RequestIntervals) > 1 {
		metrics.TimingEntropy = calculateShannonEntropy(intervalsToFrequencies(profile.RequestIntervals))
	}

	// Path entropy
	if len(profile.PathSequences) > 1 {
		metrics.PathEntropy = calculateShannonEntropy(stringsToFrequencies(profile.PathSequences))
	}

	// Parameter entropy (simplified - would need actual parameter tracking)
	metrics.ParameterEntropy = 0.5 // Placeholder

	// Overall score (weighted average)
	metrics.OverallScore = (metrics.TimingEntropy*0.4 +
		metrics.PathEntropy*0.4 +
		metrics.ParameterEntropy*0.2)

	return metrics
}

// calculateShannonEntropy calculates Shannon entropy for a frequency distribution
func calculateShannonEntropy(frequencies map[string]float64) float64 {
	if len(frequencies) == 0 {
		return 0
	}

	var entropy float64
	var total float64

	// Calculate total
	for _, freq := range frequencies {
		total += freq
	}

	// Calculate entropy
	for _, freq := range frequencies {
		if freq > 0 {
			p := freq / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// intervalsToFrequencies converts time intervals to frequency distribution
func intervalsToFrequencies(intervals []time.Duration) map[string]float64 {
	frequencies := make(map[string]float64)

	// Bucket intervals (e.g., <1s, 1-5s, 5-10s, >10s)
	for _, interval := range intervals {
		var bucket string
		switch {
		case interval < time.Second:
			bucket = "<1s"
		case interval < 5*time.Second:
			bucket = "1-5s"
		case interval < 10*time.Second:
			bucket = "5-10s"
		default:
			bucket = ">10s"
		}
		frequencies[bucket]++
	}

	return frequencies
}

// stringsToFrequencies converts string slice to frequency distribution
func stringsToFrequencies(strings []string) map[string]float64 {
	frequencies := make(map[string]float64)
	for _, s := range strings {
		frequencies[s]++
	}
	return frequencies
}

// updateSessionBehavior updates session-level behavioral metrics
func (ba *BehaviorAnalyzer) updateSessionBehavior(profile *BehaviorProfile, r *http.Request) {
	// Track key operations
	if strings.Contains(r.URL.Path, "/pks/add") ||
		strings.Contains(r.URL.Path, "/pks/lookup") {
		profile.SessionBehavior.KeyOperationRatio =
			float64(profile.SessionBehavior.RequestCount+1) /
				float64(len(profile.PathSequences)+1)
	}

	// Track bytes transferred (simplified)
	if r.ContentLength > 0 {
		profile.SessionBehavior.BytesTransferred += r.ContentLength
	}
}

// calculatePayloadSimilarity calculates similarity between current and previous payloads
func (ba *BehaviorAnalyzer) calculatePayloadSimilarity(r *http.Request) float64 {
	// Simplified implementation - in production would track actual payload hashes
	// and calculate Jaccard similarity or similar metric
	return 0.5
}

// calculateTLSFingerprint generates a TLS fingerprint from connection info
func calculateTLSFingerprint(tls *tls.ConnectionState) string {
	// Simplified TLS fingerprinting
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d-%d-%v",
		tls.Version,
		tls.CipherSuite,
		tls.NegotiatedProtocol)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// RecordViolation records a rate limit violation for the client
func (ba *BehaviorAnalyzer) RecordViolation(clientIP string, reason string) {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	violation := ViolationRecord{
		Timestamp: time.Now(),
		Reason:    reason,
		Severity:  ba.calculateViolationSeverity(reason),
	}

	ba.violationData[clientIP] = append(ba.violationData[clientIP], violation)

	// Keep only recent violations (last 24 hours)
	cutoff := time.Now().Add(-24 * time.Hour)
	filtered := make([]ViolationRecord, 0)
	for _, v := range ba.violationData[clientIP] {
		if v.Timestamp.After(cutoff) {
			filtered = append(filtered, v)
		}
	}
	ba.violationData[clientIP] = filtered
}

// calculateViolationSeverity assigns severity score to violations
func (ba *BehaviorAnalyzer) calculateViolationSeverity(reason string) int {
	// Assign severity based on violation type
	switch {
	case strings.Contains(reason, "Tor"):
		return 3
	case strings.Contains(reason, "Request rate exceeded"):
		return 2
	case strings.Contains(reason, "Connection"):
		return 2
	case strings.Contains(reason, "Error rate"):
		return 1
	default:
		return 1
	}
}

// GetProfile returns the behavior profile for a client
func (ba *BehaviorAnalyzer) GetProfile(clientIP string) *BehaviorProfile {
	ba.mu.RLock()
	defer ba.mu.RUnlock()

	profile, exists := ba.profiles[clientIP]
	if !exists {
		return nil
	}

	// Return a copy to prevent concurrent modification
	profileCopy := *profile
	return &profileCopy
}

// GetRecentBehaviorData returns recent behavior data for model updates
func (ba *BehaviorAnalyzer) GetRecentBehaviorData() []BehaviorDataPoint {
	ba.mu.RLock()
	defer ba.mu.RUnlock()

	var dataPoints []BehaviorDataPoint
	cutoff := time.Now().Add(-1 * time.Hour)

	for clientIP, profile := range ba.profiles {
		if profile.LastUpdated.After(cutoff) {
			// Check if this IP has violations
			violations := ba.violationData[clientIP]
			hasViolations := len(violations) > 0

			dataPoint := BehaviorDataPoint{
				Features: extractFeatures(profile),
				Label:    hasViolations,
				Weight:   calculateDataPointWeight(profile, violations),
			}
			dataPoints = append(dataPoints, dataPoint)
		}
	}

	return dataPoints
}

// BehaviorDataPoint represents a training data point
type BehaviorDataPoint struct {
	Features []float64
	Label    bool    // true if abusive
	Weight   float64 // importance weight
}

// extractFeatures extracts numerical features from behavior profile
func extractFeatures(profile *BehaviorProfile) []float64 {
	features := make([]float64, 0, 20)

	// Timing features
	avgInterval := calculateAverageInterval(profile.RequestIntervals)
	features = append(features, avgInterval.Seconds())
	features = append(features, calculateIntervalVariance(profile.RequestIntervals))

	// Entropy features
	features = append(features, profile.EntropyMetrics.TimingEntropy)
	features = append(features, profile.EntropyMetrics.PathEntropy)
	features = append(features, profile.EntropyMetrics.OverallScore)

	// Session features
	features = append(features, float64(profile.SessionBehavior.RequestCount))
	features = append(features, float64(profile.SessionBehavior.UniquePathsCount))
	features = append(features, profile.SessionBehavior.ErrorRate)
	features = append(features, profile.SessionBehavior.KeyOperationRatio)

	// User agent features
	features = append(features, float64(len(profile.UserAgentRotation)))

	// Payload features
	features = append(features, profile.PayloadSimilarity)

	return features
}

// calculateAverageInterval calculates average time between requests
func calculateAverageInterval(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	var total time.Duration
	for _, interval := range intervals {
		total += interval
	}
	return total / time.Duration(len(intervals))
}

// calculateIntervalVariance calculates variance in request intervals
func calculateIntervalVariance(intervals []time.Duration) float64 {
	if len(intervals) < 2 {
		return 0
	}

	avg := calculateAverageInterval(intervals)
	var variance float64

	for _, interval := range intervals {
		diff := interval.Seconds() - avg.Seconds()
		variance += diff * diff
	}

	return variance / float64(len(intervals)-1)
}

// calculateDataPointWeight calculates importance weight for training
func calculateDataPointWeight(profile *BehaviorProfile, violations []ViolationRecord) float64 {
	weight := 1.0

	// Increase weight for profiles with violations
	weight += float64(len(violations)) * 0.5

	// Increase weight for recent activity
	recency := time.Since(profile.LastUpdated).Hours()
	if recency < 1 {
		weight *= 2.0
	} else if recency < 6 {
		weight *= 1.5
	}

	return weight
}

// CleanupOldProfiles removes stale behavior profiles
func (ba *BehaviorAnalyzer) CleanupOldProfiles() int {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	var removed int

	for clientIP, profile := range ba.profiles {
		if profile.LastUpdated.Before(cutoff) {
			delete(ba.profiles, clientIP)
			delete(ba.violationData, clientIP)
			removed++
		}
	}
	return removed
}

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}
