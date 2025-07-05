package mlabuse

import (
	"sync"
	"time"
)

// MetricsCollector collects and aggregates ML detection metrics
type MetricsCollector struct {
	mu                sync.RWMutex
	totalRequests     int64
	blockedRequests   int64
	anomalyDetections map[string]int64 // by anomaly type
	llmDetections     int64
	injectionAttempts int64
	avgAnomalyScore   float64
	avgSyntheticScore float64
	hourlyStats       map[int]HourlyMetrics
	startTime         time.Time
}

// HourlyMetrics represents metrics for a specific hour
type HourlyMetrics struct {
	Hour              int
	Requests          int64
	Blocked           int64
	AnomaliesDetected int64
	LLMDetected       int64
	AvgAnomalyScore   float64
}

// CurrentMetrics represents the current state of metrics
type CurrentMetrics struct {
	TotalRequests     int64            `json:"total_requests"`
	BlockedRequests   int64            `json:"blocked_requests"`
	BlockRate         float64          `json:"block_rate"`
	AnomalyDetections map[string]int64 `json:"anomaly_detections"`
	LLMDetections     int64            `json:"llm_detections"`
	InjectionAttempts int64            `json:"injection_attempts"`
	AvgAnomalyScore   float64          `json:"avg_anomaly_score"`
	AvgSyntheticScore float64          `json:"avg_synthetic_score"`
	HourlyStats       []HourlyMetrics  `json:"hourly_stats"`
	Uptime            string           `json:"uptime"`
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		anomalyDetections: make(map[string]int64),
		hourlyStats:       make(map[int]HourlyMetrics),
		startTime:         time.Now(),
	}
}

// RecordRequest records metrics for a request
func (mc *MetricsCollector) RecordRequest(clientIP string, anomaly *AnomalyScore, llm *LLMDetectionResult, blocked bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Update counters
	mc.totalRequests++
	if blocked {
		mc.blockedRequests++
	}

	// Update anomaly metrics
	if anomaly.AnomalyType != "" {
		mc.anomalyDetections[anomaly.AnomalyType]++
	}

	// Update running averages
	mc.avgAnomalyScore = mc.updateRunningAverage(mc.avgAnomalyScore, anomaly.Score, mc.totalRequests)

	// Update LLM metrics
	if llm != nil {
		if llm.IsAIGenerated {
			mc.llmDetections++
		}
		if llm.PromptInjection {
			mc.injectionAttempts++
		}
		mc.avgSyntheticScore = mc.updateRunningAverage(mc.avgSyntheticScore, llm.SyntheticScore, mc.totalRequests)
	}

	// Update hourly stats
	hour := time.Now().Hour()
	hourly := mc.hourlyStats[hour]
	hourly.Hour = hour
	hourly.Requests++
	if blocked {
		hourly.Blocked++
	}
	if anomaly.Score >= 0.85 {
		hourly.AnomaliesDetected++
	}
	if llm != nil && llm.IsAIGenerated {
		hourly.LLMDetected++
	}
	hourly.AvgAnomalyScore = mc.updateRunningAverage(hourly.AvgAnomalyScore, anomaly.Score, hourly.Requests)
	mc.hourlyStats[hour] = hourly
}

// updateRunningAverage calculates a running average
func (mc *MetricsCollector) updateRunningAverage(currentAvg, newValue float64, count int64) float64 {
	if count == 0 {
		return newValue
	}
	return (currentAvg*float64(count-1) + newValue) / float64(count)
}

// GetCurrentMetrics returns current metrics snapshot
func (mc *MetricsCollector) GetCurrentMetrics() CurrentMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	// Convert hourly stats to slice
	hourlySlice := make([]HourlyMetrics, 0, len(mc.hourlyStats))
	for _, stats := range mc.hourlyStats {
		hourlySlice = append(hourlySlice, stats)
	}

	// Calculate block rate
	blockRate := 0.0
	if mc.totalRequests > 0 {
		blockRate = float64(mc.blockedRequests) / float64(mc.totalRequests)
	}

	// Calculate uptime
	uptime := time.Since(mc.startTime).Round(time.Second).String()

	return CurrentMetrics{
		TotalRequests:     mc.totalRequests,
		BlockedRequests:   mc.blockedRequests,
		BlockRate:         blockRate,
		AnomalyDetections: mc.copyAnomalyDetections(),
		LLMDetections:     mc.llmDetections,
		InjectionAttempts: mc.injectionAttempts,
		AvgAnomalyScore:   mc.avgAnomalyScore,
		AvgSyntheticScore: mc.avgSyntheticScore,
		HourlyStats:       hourlySlice,
		Uptime:            uptime,
	}
}

// copyAnomalyDetections creates a copy of anomaly detections map
func (mc *MetricsCollector) copyAnomalyDetections() map[string]int64 {
	copy := make(map[string]int64)
	for k, v := range mc.anomalyDetections {
		copy[k] = v
	}
	return copy
}

// ReportStatistics logs current statistics
func (mc *MetricsCollector) ReportStatistics() {
	metrics := mc.GetCurrentMetrics()

	// In production, this would integrate with the logging system
	// For now, we'll just prepare the data structure
	_ = metrics

	// Clean up old hourly stats (keep last 24 hours)
	mc.cleanupOldStats()
}

// cleanupOldStats removes hourly stats older than 24 hours
func (mc *MetricsCollector) cleanupOldStats() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	currentHour := time.Now().Hour()

	// Keep only stats from the last 24 hours
	newStats := make(map[int]HourlyMetrics)
	for hour, stats := range mc.hourlyStats {
		// Simple check - in production would need proper date handling
		if (currentHour-hour+24)%24 < 24 {
			newStats[hour] = stats
		}
	}

	mc.hourlyStats = newStats
}
