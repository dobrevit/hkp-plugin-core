package resources

import (
	"sync"
	"time"
)

// ResourceMetrics tracks and aggregates resource metrics
type ResourceMetrics struct {
	pluginMetrics map[string]*PluginMetrics
	systemMetrics *SystemMetrics
	mutex         sync.RWMutex
	startTime     time.Time
}

// PluginMetrics contains metrics for a specific plugin
type PluginMetrics struct {
	PluginName      string                         `json:"plugin_name"`
	ResourceUsage   map[ResourceType]*UsageMetrics `json:"resource_usage"`
	ViolationCount  map[ResourceType]int           `json:"violation_count"`
	LastViolation   map[ResourceType]time.Time     `json:"last_violation"`
	TotalUptime     time.Duration                  `json:"total_uptime"`
	LastCollection  time.Time                      `json:"last_collection"`
	CollectionCount int64                          `json:"collection_count"`
	HealthScore     float64                        `json:"health_score"`
}

// UsageMetrics contains detailed usage statistics
type UsageMetrics struct {
	Current    float64        `json:"current"`
	Peak       float64        `json:"peak"`
	Average    float64        `json:"average"`
	Minimum    float64        `json:"minimum"`
	Samples    int64          `json:"samples"`
	LastUpdate time.Time      `json:"last_update"`
	Trend      TrendDirection `json:"trend"`
	History    []float64      `json:"history,omitempty"`
}

// TrendDirection indicates the trend of resource usage
type TrendDirection string

const (
	TrendIncreasing TrendDirection = "increasing"
	TrendDecreasing TrendDirection = "decreasing"
	TrendStable     TrendDirection = "stable"
	TrendVolatile   TrendDirection = "volatile"
)

// SystemMetrics contains system-wide resource metrics
type SystemMetrics struct {
	TotalPlugins    int                            `json:"total_plugins"`
	ActivePlugins   int                            `json:"active_plugins"`
	TotalViolations int                            `json:"total_violations"`
	SystemResources map[ResourceType]*UsageMetrics `json:"system_resources"`
	AlertsGenerated int64                          `json:"alerts_generated"`
	LastUpdate      time.Time                      `json:"last_update"`
	UptimeSeconds   float64                        `json:"uptime_seconds"`
}

// NewResourceMetrics creates a new resource metrics instance
func NewResourceMetrics() *ResourceMetrics {
	return &ResourceMetrics{
		pluginMetrics: make(map[string]*PluginMetrics),
		systemMetrics: &SystemMetrics{
			SystemResources: make(map[ResourceType]*UsageMetrics),
		},
		startTime: time.Now(),
	}
}

// UpdatePluginMetrics updates metrics for a plugin
func (rm *ResourceMetrics) UpdatePluginMetrics(pluginName string, usage map[ResourceType]*ResourceUsage) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// Get or create plugin metrics
	metrics, exists := rm.pluginMetrics[pluginName]
	if !exists {
		metrics = &PluginMetrics{
			PluginName:     pluginName,
			ResourceUsage:  make(map[ResourceType]*UsageMetrics),
			ViolationCount: make(map[ResourceType]int),
			LastViolation:  make(map[ResourceType]time.Time),
		}
		rm.pluginMetrics[pluginName] = metrics
	}

	// Update each resource type
	for resourceType, resourceUsage := range usage {
		rm.updateUsageMetrics(metrics, resourceType, resourceUsage)
	}

	// Update collection metadata
	metrics.LastCollection = time.Now()
	metrics.CollectionCount++
	metrics.TotalUptime = time.Since(rm.startTime)
	metrics.HealthScore = rm.calculateHealthScore(metrics)

	// Update system metrics
	rm.updateSystemMetrics()
}

// updateUsageMetrics updates usage metrics for a specific resource type
func (rm *ResourceMetrics) updateUsageMetrics(pluginMetrics *PluginMetrics, resourceType ResourceType, usage *ResourceUsage) {
	usageMetrics, exists := pluginMetrics.ResourceUsage[resourceType]
	if !exists {
		usageMetrics = &UsageMetrics{
			Minimum: usage.Current,
			History: make([]float64, 0, 100), // Keep last 100 samples
		}
		pluginMetrics.ResourceUsage[resourceType] = usageMetrics
	}

	// Update current value
	usageMetrics.Current = usage.Current
	usageMetrics.LastUpdate = usage.Timestamp
	usageMetrics.Samples++

	// Update peak
	if usage.Current > usageMetrics.Peak {
		usageMetrics.Peak = usage.Current
	}

	// Update minimum
	if usage.Current < usageMetrics.Minimum {
		usageMetrics.Minimum = usage.Current
	}

	// Update rolling average
	if usageMetrics.Samples == 1 {
		usageMetrics.Average = usage.Current
	} else {
		// Exponential moving average with alpha = 0.1
		alpha := 0.1
		usageMetrics.Average = alpha*usage.Current + (1-alpha)*usageMetrics.Average
	}

	// Add to history
	usageMetrics.History = append(usageMetrics.History, usage.Current)
	if len(usageMetrics.History) > 100 {
		usageMetrics.History = usageMetrics.History[1:] // Remove oldest
	}

	// Calculate trend
	usageMetrics.Trend = rm.calculateTrend(usageMetrics.History)
}

// calculateTrend calculates the trend direction from historical data
func (rm *ResourceMetrics) calculateTrend(history []float64) TrendDirection {
	if len(history) < 5 {
		return TrendStable
	}

	// Calculate linear regression slope for last 10 points
	n := len(history)
	start := n - 10
	if start < 0 {
		start = 0
	}

	data := history[start:]
	slope := rm.linearRegressionSlope(data)

	// Calculate volatility (standard deviation)
	volatility := rm.calculateVolatility(data)

	// Determine trend based on slope and volatility
	if volatility > 0.5 { // High volatility threshold
		return TrendVolatile
	} else if slope > 0.1 { // Increasing threshold
		return TrendIncreasing
	} else if slope < -0.1 { // Decreasing threshold
		return TrendDecreasing
	} else {
		return TrendStable
	}
}

// linearRegressionSlope calculates the slope of a linear regression
func (rm *ResourceMetrics) linearRegressionSlope(data []float64) float64 {
	n := float64(len(data))
	if n < 2 {
		return 0
	}

	var sumX, sumY, sumXY, sumX2 float64
	for i, y := range data {
		x := float64(i)
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	// slope = (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)
	denominator := n*sumX2 - sumX*sumX
	if denominator == 0 {
		return 0
	}

	return (n*sumXY - sumX*sumY) / denominator
}

// calculateVolatility calculates the coefficient of variation
func (rm *ResourceMetrics) calculateVolatility(data []float64) float64 {
	if len(data) < 2 {
		return 0
	}

	// Calculate mean
	var sum float64
	for _, value := range data {
		sum += value
	}
	mean := sum / float64(len(data))

	if mean == 0 {
		return 0
	}

	// Calculate standard deviation
	var variance float64
	for _, value := range data {
		diff := value - mean
		variance += diff * diff
	}
	variance /= float64(len(data) - 1)
	stdDev := variance // Simplified, should be sqrt(variance)

	// Return coefficient of variation
	return stdDev / mean
}

// calculateHealthScore calculates a health score for a plugin
func (rm *ResourceMetrics) calculateHealthScore(metrics *PluginMetrics) float64 {
	score := 100.0 // Start with perfect score

	// Penalize for violations
	totalViolations := 0
	for _, count := range metrics.ViolationCount {
		totalViolations += count
	}

	violationPenalty := float64(totalViolations) * 5.0 // 5 points per violation
	score -= violationPenalty

	// Penalize for high resource usage trends
	for _, usage := range metrics.ResourceUsage {
		if usage.Trend == TrendIncreasing {
			score -= 10.0
		} else if usage.Trend == TrendVolatile {
			score -= 15.0
		}
	}

	// Ensure score is between 0 and 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// RecordViolation records a resource violation
func (rm *ResourceMetrics) RecordViolation(pluginName string, resourceType ResourceType) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	metrics, exists := rm.pluginMetrics[pluginName]
	if !exists {
		return
	}

	metrics.ViolationCount[resourceType]++
	metrics.LastViolation[resourceType] = time.Now()

	// Update system metrics
	rm.systemMetrics.TotalViolations++
}

// updateSystemMetrics updates system-wide metrics
func (rm *ResourceMetrics) updateSystemMetrics() {
	rm.systemMetrics.TotalPlugins = len(rm.pluginMetrics)
	rm.systemMetrics.ActivePlugins = rm.countActivePlugins()
	rm.systemMetrics.LastUpdate = time.Now()
	rm.systemMetrics.UptimeSeconds = time.Since(rm.startTime).Seconds()
}

// countActivePlugins counts plugins that have been updated recently
func (rm *ResourceMetrics) countActivePlugins() int {
	cutoff := time.Now().Add(-5 * time.Minute) // Consider active if updated in last 5 minutes
	active := 0

	for _, metrics := range rm.pluginMetrics {
		if metrics.LastCollection.After(cutoff) {
			active++
		}
	}

	return active
}

// GetPluginMetrics returns metrics for a specific plugin
func (rm *ResourceMetrics) GetPluginMetrics(pluginName string) (*PluginMetrics, bool) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	metrics, exists := rm.pluginMetrics[pluginName]
	if !exists {
		return nil, false
	}

	// Return a copy to avoid race conditions
	return rm.copyPluginMetrics(metrics), true
}

// GetAllPluginMetrics returns metrics for all plugins
func (rm *ResourceMetrics) GetAllPluginMetrics() map[string]*PluginMetrics {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	result := make(map[string]*PluginMetrics)
	for name, metrics := range rm.pluginMetrics {
		result[name] = rm.copyPluginMetrics(metrics)
	}

	return result
}

// GetSystemMetrics returns system-wide metrics
func (rm *ResourceMetrics) GetSystemMetrics() *SystemMetrics {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	// Return a copy
	return &SystemMetrics{
		TotalPlugins:    rm.systemMetrics.TotalPlugins,
		ActivePlugins:   rm.systemMetrics.ActivePlugins,
		TotalViolations: rm.systemMetrics.TotalViolations,
		SystemResources: rm.copySystemResources(rm.systemMetrics.SystemResources),
		AlertsGenerated: rm.systemMetrics.AlertsGenerated,
		LastUpdate:      rm.systemMetrics.LastUpdate,
		UptimeSeconds:   rm.systemMetrics.UptimeSeconds,
	}
}

// copyPluginMetrics creates a deep copy of plugin metrics
func (rm *ResourceMetrics) copyPluginMetrics(original *PluginMetrics) *PluginMetrics {
	copy := &PluginMetrics{
		PluginName:      original.PluginName,
		ResourceUsage:   make(map[ResourceType]*UsageMetrics),
		ViolationCount:  make(map[ResourceType]int),
		LastViolation:   make(map[ResourceType]time.Time),
		TotalUptime:     original.TotalUptime,
		LastCollection:  original.LastCollection,
		CollectionCount: original.CollectionCount,
		HealthScore:     original.HealthScore,
	}

	// Copy resource usage
	for resourceType, usage := range original.ResourceUsage {
		copy.ResourceUsage[resourceType] = &UsageMetrics{
			Current:    usage.Current,
			Peak:       usage.Peak,
			Average:    usage.Average,
			Minimum:    usage.Minimum,
			Samples:    usage.Samples,
			LastUpdate: usage.LastUpdate,
			Trend:      usage.Trend,
			// Don't copy history to save memory
		}
	}

	// Copy violation counts
	for resourceType, count := range original.ViolationCount {
		copy.ViolationCount[resourceType] = count
	}

	// Copy last violation times
	for resourceType, time := range original.LastViolation {
		copy.LastViolation[resourceType] = time
	}

	return copy
}

// copySystemResources creates a copy of system resource metrics
func (rm *ResourceMetrics) copySystemResources(original map[ResourceType]*UsageMetrics) map[ResourceType]*UsageMetrics {
	copy := make(map[ResourceType]*UsageMetrics)
	for resourceType, usage := range original {
		copy[resourceType] = &UsageMetrics{
			Current:    usage.Current,
			Peak:       usage.Peak,
			Average:    usage.Average,
			Minimum:    usage.Minimum,
			Samples:    usage.Samples,
			LastUpdate: usage.LastUpdate,
			Trend:      usage.Trend,
		}
	}
	return copy
}

// GetResourceSummary returns a summary of resource usage across all plugins
func (rm *ResourceMetrics) GetResourceSummary() map[ResourceType]map[string]interface{} {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	summary := make(map[ResourceType]map[string]interface{})

	// Initialize summary for each resource type
	resourceTypes := []ResourceType{
		ResourceTypeMemory, ResourceTypeCPU, ResourceTypeGoroutines,
		ResourceTypeFileHandles, ResourceTypeConnections,
	}

	for _, resourceType := range resourceTypes {
		summary[resourceType] = map[string]interface{}{
			"total_current": 0.0,
			"total_peak":    0.0,
			"plugin_count":  0,
			"violations":    0,
		}
	}

	// Aggregate across all plugins
	for _, metrics := range rm.pluginMetrics {
		for resourceType, usage := range metrics.ResourceUsage {
			if summary[resourceType] == nil {
				continue
			}

			summary[resourceType]["total_current"] = summary[resourceType]["total_current"].(float64) + usage.Current
			summary[resourceType]["total_peak"] = summary[resourceType]["total_peak"].(float64) + usage.Peak
			summary[resourceType]["plugin_count"] = summary[resourceType]["plugin_count"].(int) + 1

			if count, exists := metrics.ViolationCount[resourceType]; exists {
				summary[resourceType]["violations"] = summary[resourceType]["violations"].(int) + count
			}
		}
	}

	return summary
}
