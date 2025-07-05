package resources

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// MemoryCollector collects memory usage statistics
type MemoryCollector struct {
	lastGC uint32
}

// NewMemoryCollector creates a new memory collector
func NewMemoryCollector() *MemoryCollector {
	return &MemoryCollector{}
}

// Collect collects memory usage for a plugin
func (mc *MemoryCollector) Collect(pluginName string) (*ResourceUsage, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// For plugin-specific memory tracking, we would need to implement
	// more sophisticated tracking. For now, we'll use system-wide stats
	// divided by the number of goroutines as an approximation

	goroutines := float64(runtime.NumGoroutine())
	pluginGoroutines := mc.estimatePluginGoroutines(pluginName)

	ratio := pluginGoroutines / goroutines
	if ratio > 1.0 {
		ratio = 1.0
	}

	currentMB := float64(m.Alloc) * ratio / 1024 / 1024
	peakMB := float64(m.Sys) * ratio / 1024 / 1024

	return &ResourceUsage{
		PluginName:   pluginName,
		ResourceType: ResourceTypeMemory,
		Current:      currentMB,
		Peak:         peakMB,
		Average:      currentMB, // Simplified - would need historical data
		Unit:         "MB",
		Timestamp:    time.Now(),
		Metadata: map[string]interface{}{
			"heap_alloc": m.HeapAlloc,
			"heap_sys":   m.HeapSys,
			"gc_cycles":  m.NumGC,
			"last_gc":    time.Unix(0, int64(m.LastGC)),
			"goroutines": pluginGoroutines,
		},
	}, nil
}

// GetResourceType returns the resource type
func (mc *MemoryCollector) GetResourceType() ResourceType {
	return ResourceTypeMemory
}

// estimatePluginGoroutines estimates goroutines for a plugin
func (mc *MemoryCollector) estimatePluginGoroutines(pluginName string) float64 {
	// This is a simplified estimation. In a real implementation,
	// you would track goroutines by plugin using runtime debug info
	// or custom tracking mechanisms
	total := float64(runtime.NumGoroutine())

	// Estimate based on plugin name heuristics
	// This would be replaced with actual tracking
	return total * 0.1 // Assume 10% of goroutines per plugin
}

// CPUCollector collects CPU usage statistics
type CPUCollector struct {
	lastCPUTime time.Duration
	lastCheck   time.Time
}

// NewCPUCollector creates a new CPU collector
func NewCPUCollector() *CPUCollector {
	return &CPUCollector{
		lastCheck: time.Now(),
	}
}

// Collect collects CPU usage for a plugin
func (cc *CPUCollector) Collect(pluginName string) (*ResourceUsage, error) {
	// Get current CPU time from /proc/stat
	cpuPercent, err := cc.getCurrentCPUUsage()
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU usage: %w", err)
	}

	// Estimate plugin CPU usage (simplified)
	pluginCPUPercent := cpuPercent * cc.estimatePluginCPUShare(pluginName)

	return &ResourceUsage{
		PluginName:   pluginName,
		ResourceType: ResourceTypeCPU,
		Current:      pluginCPUPercent,
		Peak:         pluginCPUPercent, // Would track peak over time
		Average:      pluginCPUPercent, // Would calculate moving average
		Unit:         "percent",
		Timestamp:    time.Now(),
		Metadata: map[string]interface{}{
			"system_cpu_percent":  cpuPercent,
			"collection_interval": time.Since(cc.lastCheck).String(),
		},
	}, nil
}

// GetResourceType returns the resource type
func (cc *CPUCollector) GetResourceType() ResourceType {
	return ResourceTypeCPU
}

// getCurrentCPUUsage gets current system CPU usage
func (cc *CPUCollector) getCurrentCPUUsage() (float64, error) {
	// Read /proc/stat for system CPU usage
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return 0, fmt.Errorf("failed to read /proc/stat")
	}

	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return 0, fmt.Errorf("invalid /proc/stat format")
	}

	// Parse CPU times
	var user, nice, system, idle, iowait, irq, softirq, steal uint64
	user, _ = strconv.ParseUint(fields[1], 10, 64)
	nice, _ = strconv.ParseUint(fields[2], 10, 64)
	system, _ = strconv.ParseUint(fields[3], 10, 64)
	idle, _ = strconv.ParseUint(fields[4], 10, 64)
	iowait, _ = strconv.ParseUint(fields[5], 10, 64)
	irq, _ = strconv.ParseUint(fields[6], 10, 64)
	softirq, _ = strconv.ParseUint(fields[7], 10, 64)
	if len(fields) > 8 {
		steal, _ = strconv.ParseUint(fields[8], 10, 64)
	}

	totalIdle := idle + iowait
	totalNonIdle := user + nice + system + irq + softirq + steal
	total := totalIdle + totalNonIdle

	if total == 0 {
		return 0, nil
	}

	return float64(totalNonIdle) / float64(total) * 100, nil
}

// estimatePluginCPUShare estimates CPU share for a plugin
func (cc *CPUCollector) estimatePluginCPUShare(pluginName string) float64 {
	// Simplified estimation - in reality, would track by goroutine
	// or use cgroups for more accurate measurement
	return 0.15 // Assume 15% CPU share per plugin
}

// GoroutineCollector collects goroutine count statistics
type GoroutineCollector struct {
	pluginGoroutines map[string]int
}

// NewGoroutineCollector creates a new goroutine collector
func NewGoroutineCollector() *GoroutineCollector {
	return &GoroutineCollector{
		pluginGoroutines: make(map[string]int),
	}
}

// Collect collects goroutine count for a plugin
func (gc *GoroutineCollector) Collect(pluginName string) (*ResourceUsage, error) {
	total := runtime.NumGoroutine()

	// Estimate plugin goroutines (simplified)
	// In a real implementation, you would track goroutines by plugin
	pluginGoroutines := gc.estimatePluginGoroutines(pluginName, total)

	gc.pluginGoroutines[pluginName] = pluginGoroutines

	return &ResourceUsage{
		PluginName:   pluginName,
		ResourceType: ResourceTypeGoroutines,
		Current:      float64(pluginGoroutines),
		Peak:         float64(pluginGoroutines), // Would track peak
		Average:      float64(pluginGoroutines), // Would calculate average
		Unit:         "count",
		Timestamp:    time.Now(),
		Metadata: map[string]interface{}{
			"total_goroutines": total,
			"plugin_share":     fmt.Sprintf("%.2f%%", float64(pluginGoroutines)/float64(total)*100),
		},
	}, nil
}

// GetResourceType returns the resource type
func (gc *GoroutineCollector) GetResourceType() ResourceType {
	return ResourceTypeGoroutines
}

// estimatePluginGoroutines estimates goroutines for a plugin
func (gc *GoroutineCollector) estimatePluginGoroutines(pluginName string, total int) int {
	// Simplified estimation based on plugin type
	// In reality, would use runtime/pprof or custom tracking
	baseEstimate := total / 10 // Assume 10% base allocation

	// Adjust based on plugin type (heuristic)
	switch {
	case strings.Contains(pluginName, "threat"):
		return baseEstimate + 5 // Threat plugins use more goroutines
	case strings.Contains(pluginName, "ml"):
		return baseEstimate + 10 // ML plugins use more
	case strings.Contains(pluginName, "zero-trust"):
		return baseEstimate + 3 // Auth plugins moderate usage
	default:
		return baseEstimate
	}
}

// FileHandleCollector collects file handle usage statistics
type FileHandleCollector struct{}

// NewFileHandleCollector creates a new file handle collector
func NewFileHandleCollector() *FileHandleCollector {
	return &FileHandleCollector{}
}

// Collect collects file handle count for a plugin
func (fhc *FileHandleCollector) Collect(pluginName string) (*ResourceUsage, error) {
	// Get current process file descriptor count
	fdCount, err := fhc.getCurrentFDCount()
	if err != nil {
		return nil, fmt.Errorf("failed to get file descriptor count: %w", err)
	}

	// Estimate plugin file handles (simplified)
	pluginFDs := fhc.estimatePluginFileHandles(pluginName, fdCount)

	return &ResourceUsage{
		PluginName:   pluginName,
		ResourceType: ResourceTypeFileHandles,
		Current:      float64(pluginFDs),
		Peak:         float64(pluginFDs), // Would track peak
		Average:      float64(pluginFDs), // Would calculate average
		Unit:         "count",
		Timestamp:    time.Now(),
		Metadata: map[string]interface{}{
			"total_fds": fdCount,
		},
	}, nil
}

// GetResourceType returns the resource type
func (fhc *FileHandleCollector) GetResourceType() ResourceType {
	return ResourceTypeFileHandles
}

// getCurrentFDCount gets current file descriptor count
func (fhc *FileHandleCollector) getCurrentFDCount() (int, error) {
	// Count files in /proc/self/fd
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// estimatePluginFileHandles estimates file handles for a plugin
func (fhc *FileHandleCollector) estimatePluginFileHandles(pluginName string, total int) int {
	// Simplified estimation
	baseEstimate := total / 15 // Assume plugins use small portion

	// Adjust based on plugin type
	switch {
	case strings.Contains(pluginName, "threat"):
		return baseEstimate + 5 // Threat plugins may open more files
	case strings.Contains(pluginName, "geo"):
		return baseEstimate + 2 // GeoIP database files
	default:
		return baseEstimate
	}
}

// ConnectionCollector collects network connection statistics
type ConnectionCollector struct{}

// NewConnectionCollector creates a new connection collector
func NewConnectionCollector() *ConnectionCollector {
	return &ConnectionCollector{}
}

// Collect collects connection count for a plugin
func (cc *ConnectionCollector) Collect(pluginName string) (*ResourceUsage, error) {
	// Get current connection count
	connCount, err := cc.getCurrentConnectionCount()
	if err != nil {
		return nil, fmt.Errorf("failed to get connection count: %w", err)
	}

	// Estimate plugin connections (simplified)
	pluginConns := cc.estimatePluginConnections(pluginName, connCount)

	return &ResourceUsage{
		PluginName:   pluginName,
		ResourceType: ResourceTypeConnections,
		Current:      float64(pluginConns),
		Peak:         float64(pluginConns), // Would track peak
		Average:      float64(pluginConns), // Would calculate average
		Unit:         "count",
		Timestamp:    time.Now(),
		Metadata: map[string]interface{}{
			"total_connections": connCount,
		},
	}, nil
}

// GetResourceType returns the resource type
func (cc *ConnectionCollector) GetResourceType() ResourceType {
	return ResourceTypeConnections
}

// getCurrentConnectionCount gets current network connection count
func (cc *ConnectionCollector) getCurrentConnectionCount() (int, error) {
	// Count entries in /proc/net/tcp and /proc/net/tcp6
	tcpCount, err := cc.countConnections("/proc/net/tcp")
	if err != nil {
		return 0, err
	}

	tcp6Count, err := cc.countConnections("/proc/net/tcp6")
	if err != nil {
		return tcpCount, nil // Continue with just IPv4 if IPv6 fails
	}

	return tcpCount + tcp6Count, nil
}

// countConnections counts connections in a proc file
func (cc *ConnectionCollector) countConnections(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)

	// Skip header line
	if scanner.Scan() {
		// Count remaining lines
		for scanner.Scan() {
			count++
		}
	}

	return count, scanner.Err()
}

// estimatePluginConnections estimates connections for a plugin
func (cc *ConnectionCollector) estimatePluginConnections(pluginName string, total int) int {
	// Simplified estimation
	baseEstimate := total / 20 // Assume plugins use small portion

	// Adjust based on plugin type
	switch {
	case strings.Contains(pluginName, "threat"):
		return baseEstimate + 10 // Threat plugins make external connections
	case strings.Contains(pluginName, "zero-trust"):
		return baseEstimate + 5 // Auth plugins have connections
	default:
		return baseEstimate
	}
}
