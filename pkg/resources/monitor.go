// Package resources provides resource monitoring and limiting for plugins
package resources

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// ResourceMonitor tracks and limits plugin resource usage
type ResourceMonitor struct {
	collectors     map[string]ResourceCollector
	limitManager   *ResourceLimitManager
	alertManager   *AlertManager
	metrics        *ResourceMetrics
	config         *MonitorConfig
	pluginTrackers map[string]*PluginResourceTracker
	mutex          sync.RWMutex
	stopChan       chan struct{}
	running        int32
}

// ResourceCollector defines interface for collecting resource metrics
type ResourceCollector interface {
	Collect(pluginName string) (*ResourceUsage, error)
	GetResourceType() ResourceType
}

// ResourceType represents different types of resources
type ResourceType string

const (
	ResourceTypeCPU         ResourceType = "cpu"
	ResourceTypeMemory      ResourceType = "memory"
	ResourceTypeGoroutines  ResourceType = "goroutines"
	ResourceTypeFileHandles ResourceType = "file_handles"
	ResourceTypeConnections ResourceType = "connections"
	ResourceTypeDiskIO      ResourceType = "disk_io"
	ResourceTypeNetworkIO   ResourceType = "network_io"
)

// ResourceUsage represents current resource usage
type ResourceUsage struct {
	PluginName   string                 `json:"plugin_name"`
	ResourceType ResourceType           `json:"resource_type"`
	Current      float64                `json:"current"`
	Peak         float64                `json:"peak"`
	Average      float64                `json:"average"`
	Unit         string                 `json:"unit"`
	Timestamp    time.Time              `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ResourceLimits defines resource limits for a plugin
type ResourceLimits struct {
	MaxMemoryMB     int64   `json:"max_memory_mb"`
	MaxCPUPercent   float64 `json:"max_cpu_percent"`
	MaxGoroutines   int32   `json:"max_goroutines"`
	MaxFileHandles  int32   `json:"max_file_handles"`
	MaxConnections  int32   `json:"max_connections"`
	MaxDiskIOBPS    int64   `json:"max_disk_io_bps"`
	MaxNetworkIOBPS int64   `json:"max_network_io_bps"`
}

// MonitorConfig contains monitoring configuration
type MonitorConfig struct {
	CollectionInterval time.Duration            `json:"collection_interval"`
	AlertThresholds    map[ResourceType]float64 `json:"alert_thresholds"`
	RetentionPeriod    time.Duration            `json:"retention_period"`
	EnabledCollectors  []ResourceType           `json:"enabled_collectors"`
	AlertingEnabled    bool                     `json:"alerting_enabled"`
}

// PluginResourceTracker tracks resources for a specific plugin
type PluginResourceTracker struct {
	PluginName     string
	Limits         *ResourceLimits
	CurrentUsage   map[ResourceType]*ResourceUsage
	History        []*ResourceSnapshot
	Violations     []*ResourceViolation
	LastCollection time.Time
	mutex          sync.RWMutex
}

// ResourceSnapshot captures resource state at a point in time
type ResourceSnapshot struct {
	Timestamp time.Time                       `json:"timestamp"`
	Usage     map[ResourceType]*ResourceUsage `json:"usage"`
}

// ResourceViolation represents a resource limit violation
type ResourceViolation struct {
	PluginName   string       `json:"plugin_name"`
	ResourceType ResourceType `json:"resource_type"`
	Limit        float64      `json:"limit"`
	Actual       float64      `json:"actual"`
	Timestamp    time.Time    `json:"timestamp"`
	Severity     Severity     `json:"severity"`
	Action       string       `json:"action"`
}

// Severity levels for violations
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor(config *MonitorConfig) *ResourceMonitor {
	rm := &ResourceMonitor{
		collectors:     make(map[string]ResourceCollector),
		limitManager:   NewResourceLimitManager(),
		alertManager:   NewAlertManager(),
		metrics:        NewResourceMetrics(),
		config:         config,
		pluginTrackers: make(map[string]*PluginResourceTracker),
		stopChan:       make(chan struct{}),
	}

	// Register default collectors
	rm.registerDefaultCollectors()

	return rm
}

// Start begins resource monitoring
func (rm *ResourceMonitor) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&rm.running, 0, 1) {
		return fmt.Errorf("resource monitor already running")
	}

	go rm.monitoringLoop(ctx)
	return nil
}

// Stop stops resource monitoring
func (rm *ResourceMonitor) Stop() error {
	if !atomic.CompareAndSwapInt32(&rm.running, 1, 0) {
		return fmt.Errorf("resource monitor not running")
	}

	close(rm.stopChan)
	return nil
}

// TrackPlugin starts tracking resources for a plugin
func (rm *ResourceMonitor) TrackPlugin(pluginName string, limits *ResourceLimits) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if _, exists := rm.pluginTrackers[pluginName]; exists {
		return fmt.Errorf("plugin %s is already being tracked", pluginName)
	}

	tracker := &PluginResourceTracker{
		PluginName:   pluginName,
		Limits:       limits,
		CurrentUsage: make(map[ResourceType]*ResourceUsage),
		History:      make([]*ResourceSnapshot, 0),
		Violations:   make([]*ResourceViolation, 0),
	}

	rm.pluginTrackers[pluginName] = tracker
	return nil
}

// UntrackPlugin stops tracking a plugin
func (rm *ResourceMonitor) UntrackPlugin(pluginName string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	delete(rm.pluginTrackers, pluginName)
	return nil
}

// GetPluginUsage returns current resource usage for a plugin
func (rm *ResourceMonitor) GetPluginUsage(pluginName string) (map[ResourceType]*ResourceUsage, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	tracker, exists := rm.pluginTrackers[pluginName]
	if !exists {
		return nil, fmt.Errorf("plugin %s not tracked", pluginName)
	}

	tracker.mutex.RLock()
	defer tracker.mutex.RUnlock()

	// Return copy of current usage
	usage := make(map[ResourceType]*ResourceUsage)
	for resourceType, u := range tracker.CurrentUsage {
		usage[resourceType] = &ResourceUsage{
			PluginName:   u.PluginName,
			ResourceType: u.ResourceType,
			Current:      u.Current,
			Peak:         u.Peak,
			Average:      u.Average,
			Unit:         u.Unit,
			Timestamp:    u.Timestamp,
			Metadata:     u.Metadata,
		}
	}

	return usage, nil
}

// GetPluginViolations returns resource violations for a plugin
func (rm *ResourceMonitor) GetPluginViolations(pluginName string) ([]*ResourceViolation, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	tracker, exists := rm.pluginTrackers[pluginName]
	if !exists {
		return nil, fmt.Errorf("plugin %s not tracked", pluginName)
	}

	tracker.mutex.RLock()
	defer tracker.mutex.RUnlock()

	// Return copy of violations
	violations := make([]*ResourceViolation, len(tracker.Violations))
	copy(violations, tracker.Violations)

	return violations, nil
}

// UpdatePluginLimits updates resource limits for a plugin
func (rm *ResourceMonitor) UpdatePluginLimits(pluginName string, limits *ResourceLimits) error {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	tracker, exists := rm.pluginTrackers[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not tracked", pluginName)
	}

	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	tracker.Limits = limits
	return nil
}

// GetSystemSummary returns overall system resource summary
func (rm *ResourceMonitor) GetSystemSummary() map[string]interface{} {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	summary := map[string]interface{}{
		"plugins_tracked":     len(rm.pluginTrackers),
		"collection_interval": rm.config.CollectionInterval.String(),
		"alerting_enabled":    rm.config.AlertingEnabled,
		"total_violations":    0,
		"system_resources":    rm.getSystemResources(),
	}

	totalViolations := 0
	for _, tracker := range rm.pluginTrackers {
		tracker.mutex.RLock()
		totalViolations += len(tracker.Violations)
		tracker.mutex.RUnlock()
	}
	summary["total_violations"] = totalViolations

	return summary
}

// monitoringLoop is the main monitoring loop
func (rm *ResourceMonitor) monitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(rm.config.CollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.collectAllResources()
		case <-rm.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// collectAllResources collects resources for all tracked plugins
func (rm *ResourceMonitor) collectAllResources() {
	rm.mutex.RLock()
	trackers := make([]*PluginResourceTracker, 0, len(rm.pluginTrackers))
	for _, tracker := range rm.pluginTrackers {
		trackers = append(trackers, tracker)
	}
	rm.mutex.RUnlock()

	for _, tracker := range trackers {
		rm.collectPluginResources(tracker)
	}
}

// collectPluginResources collects resources for a specific plugin
func (rm *ResourceMonitor) collectPluginResources(tracker *PluginResourceTracker) {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	snapshot := &ResourceSnapshot{
		Timestamp: time.Now(),
		Usage:     make(map[ResourceType]*ResourceUsage),
	}

	for _, collector := range rm.collectors {
		usage, err := collector.Collect(tracker.PluginName)
		if err != nil {
			continue // Skip failed collections
		}

		resourceType := collector.GetResourceType()
		tracker.CurrentUsage[resourceType] = usage
		snapshot.Usage[resourceType] = usage

		// Check for violations
		rm.checkResourceViolation(tracker, usage)
	}

	// Add snapshot to history
	tracker.History = append(tracker.History, snapshot)
	tracker.LastCollection = time.Now()

	// Trim history if needed
	rm.trimHistory(tracker)
}

// checkResourceViolation checks if resource usage violates limits
func (rm *ResourceMonitor) checkResourceViolation(tracker *PluginResourceTracker, usage *ResourceUsage) {
	var limit float64
	var violated bool

	switch usage.ResourceType {
	case ResourceTypeMemory:
		limit = float64(tracker.Limits.MaxMemoryMB)
		violated = usage.Current > limit
	case ResourceTypeCPU:
		limit = tracker.Limits.MaxCPUPercent
		violated = usage.Current > limit
	case ResourceTypeGoroutines:
		limit = float64(tracker.Limits.MaxGoroutines)
		violated = usage.Current > limit
	case ResourceTypeFileHandles:
		limit = float64(tracker.Limits.MaxFileHandles)
		violated = usage.Current > limit
	case ResourceTypeConnections:
		limit = float64(tracker.Limits.MaxConnections)
		violated = usage.Current > limit
	}

	if violated {
		violation := &ResourceViolation{
			PluginName:   tracker.PluginName,
			ResourceType: usage.ResourceType,
			Limit:        limit,
			Actual:       usage.Current,
			Timestamp:    time.Now(),
			Severity:     rm.determineSeverity(usage.ResourceType, usage.Current, limit),
			Action:       "logged",
		}

		tracker.Violations = append(tracker.Violations, violation)

		// Send alert if enabled
		if rm.config.AlertingEnabled {
			rm.alertManager.SendAlert(violation)
		}
	}
}

// determineSeverity determines violation severity based on resource type and values
func (rm *ResourceMonitor) determineSeverity(resourceType ResourceType, actual, limit float64) Severity {
	ratio := actual / limit

	switch {
	case ratio >= 2.0:
		return SeverityCritical
	case ratio >= 1.5:
		return SeverityError
	case ratio >= 1.2:
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

// trimHistory removes old history entries based on retention period
func (rm *ResourceMonitor) trimHistory(tracker *PluginResourceTracker) {
	cutoff := time.Now().Add(-rm.config.RetentionPeriod)

	var kept []*ResourceSnapshot
	for _, snapshot := range tracker.History {
		if snapshot.Timestamp.After(cutoff) {
			kept = append(kept, snapshot)
		}
	}

	tracker.History = kept
}

// getSystemResources returns current system resource information
func (rm *ResourceMonitor) getSystemResources() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"goroutines":   runtime.NumGoroutine(),
		"memory_alloc": m.Alloc,
		"memory_sys":   m.Sys,
		"memory_heap":  m.HeapAlloc,
		"gc_cycles":    m.NumGC,
		"cpu_cores":    runtime.NumCPU(),
	}
}

// registerDefaultCollectors registers built-in resource collectors
func (rm *ResourceMonitor) registerDefaultCollectors() {
	for _, resourceType := range rm.config.EnabledCollectors {
		switch resourceType {
		case ResourceTypeMemory:
			rm.collectors["memory"] = NewMemoryCollector()
		case ResourceTypeCPU:
			rm.collectors["cpu"] = NewCPUCollector()
		case ResourceTypeGoroutines:
			rm.collectors["goroutines"] = NewGoroutineCollector()
		case ResourceTypeFileHandles:
			rm.collectors["file_handles"] = NewFileHandleCollector()
		case ResourceTypeConnections:
			rm.collectors["connections"] = NewConnectionCollector()
		}
	}
}

// DefaultMonitorConfig returns a default monitoring configuration
func DefaultMonitorConfig() *MonitorConfig {
	return &MonitorConfig{
		CollectionInterval: 5 * time.Second,
		AlertThresholds: map[ResourceType]float64{
			ResourceTypeMemory:      80.0, // 80% of limit
			ResourceTypeCPU:         90.0, // 90% of limit
			ResourceTypeGoroutines:  75.0, // 75% of limit
			ResourceTypeFileHandles: 80.0, // 80% of limit
			ResourceTypeConnections: 80.0, // 80% of limit
		},
		RetentionPeriod: 24 * time.Hour,
		EnabledCollectors: []ResourceType{
			ResourceTypeMemory,
			ResourceTypeCPU,
			ResourceTypeGoroutines,
			ResourceTypeFileHandles,
		},
		AlertingEnabled: true,
	}
}
