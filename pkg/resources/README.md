# Resources Package

The resources package provides comprehensive resource monitoring, tracking, and alerting for plugin resource usage including CPU, memory, goroutines, file handles, and network connections.

## Overview

This package implements real-time resource monitoring with trend analysis, violation detection, and automated alerting to ensure plugins operate within defined resource boundaries and maintain system stability.

## Components

### Core Files

- **`monitor.go`** - Central resource monitoring system
- **`collectors.go`** - Resource data collectors for different metrics
- **`metrics.go`** - Resource metrics aggregation and analysis
- **`alerts.go`** - Resource violation alerting system
- **`trends.go`** - Resource usage trend analysis
- **`integration_test.go`** - Comprehensive monitoring tests

## Key Features

### Real-time Resource Monitoring

```go
monitor := resources.NewResourceMonitor(&resources.MonitorConfig{
    CollectionInterval: 30 * time.Second,
    AlertThresholds: map[resources.ResourceType]float64{
        resources.ResourceTypeMemory:     80.0,  // 80% of limit
        resources.ResourceTypeCPU:        70.0,  // 70% of limit
        resources.ResourceTypeGoroutines: 90.0,  // 90% of limit
    },
    RetentionPeriod: 24 * time.Hour,
    EnabledCollectors: []resources.ResourceType{
        resources.ResourceTypeMemory,
        resources.ResourceTypeCPU,
        resources.ResourceTypeGoroutines,
        resources.ResourceTypeFileHandles,
        resources.ResourceTypeConnections,
    },
})

err := monitor.Start(context.Background())
```

### Plugin Resource Tracking

```go
limits := &resources.ResourceLimits{
    MaxMemoryMB:      512,
    MaxCPUPercent:    25.0,
    MaxGoroutines:    100,
    MaxFileHandles:   50,
    MaxConnections:   20,
}

err := monitor.TrackPlugin("my-plugin", limits)
```

### Resource Metrics Collection

```go
usage, err := monitor.GetPluginUsage("my-plugin")
systemSummary := monitor.GetSystemSummary()
trends := monitor.GetResourceTrends("my-plugin", time.Hour)
```

## Resource Types

### Monitored Resources

- **Memory** - RAM usage in MB with RSS and virtual memory
- **CPU** - CPU utilization percentage and time
- **Goroutines** - Active goroutine count per plugin
- **File Handles** - Open file descriptor count
- **Network Connections** - Active network connection count
- **Disk I/O** - Read/write operations and bandwidth
- **Custom Metrics** - Plugin-specific resource metrics

### Resource Usage Structure

```go
type ResourceUsage struct {
    PluginName   string
    ResourceType ResourceType
    Current      float64
    Peak         float64
    Average      float64
    Minimum      float64
    Unit         string
    Timestamp    time.Time
    Trend        TrendDirection
    Metadata     map[string]interface{}
}
```

## Configuration

### Monitor Configuration

```go
type MonitorConfig struct {
    CollectionInterval    time.Duration
    AlertThresholds       map[ResourceType]float64
    RetentionPeriod      time.Duration
    EnabledCollectors    []ResourceType
    AlertingEnabled      bool
    TrendAnalysisEnabled bool
    MetricsExportEnabled bool
    ExportInterval       time.Duration
    AlertCooldownPeriod  time.Duration
    BatchSize           int
    MaxConcurrentCollections int
}
```

### Resource Limits

```go
type ResourceLimits struct {
    MaxMemoryMB      int64
    MaxCPUPercent    float64
    MaxGoroutines    int64
    MaxFileHandles   int64
    MaxConnections   int64
    MaxDiskReadMB    int64
    MaxDiskWriteMB   int64
    CustomLimits     map[string]float64
}
```

## Resource Collectors

### Memory Collector

Tracks memory usage patterns:
- Resident Set Size (RSS)
- Virtual Memory Size (VMS)
- Heap allocation statistics
- Garbage collection metrics

### CPU Collector

Monitors CPU utilization:
- User CPU time
- System CPU time
- CPU percentage utilization
- Context switches

### Goroutine Collector

Tracks goroutine lifecycle:
- Active goroutine count
- Goroutine creation rate
- Blocked goroutine detection
- Stack size monitoring

### File Handle Collector

Monitors file descriptor usage:
- Open file count
- File type distribution
- Socket connections
- Pipe and device files

### Network Collector

Tracks network resource usage:
- TCP connection count
- UDP socket count
- Network I/O statistics
- Connection state distribution

## Metrics and Analysis

### Resource Metrics

```go
type ResourceMetrics struct {
    PluginName          string
    TotalResourceTypes  int
    HealthScore         float64
    ResourceUsage       map[ResourceType]*ResourceUsage
    ViolationCount      int64
    LastViolation       time.Time
    TrendAnalysis       map[ResourceType]*TrendAnalysis
    PredictedUsage      map[ResourceType]*UsagePrediction
}
```

### Trend Analysis

```go
type TrendAnalysis struct {
    Direction     TrendDirection
    Confidence    float64
    Slope         float64
    RSquared     float64
    PredictedPeak time.Time
    TimeToLimit   time.Duration
    Seasonality   []SeasonalPattern
}
```

## Alerting System

### Violation Detection

```go
type ResourceViolation struct {
    PluginName   string
    ResourceType ResourceType
    Limit        float64
    Actual       float64
    Threshold    float64
    Timestamp    time.Time
    Severity     Severity
    Action       string
    Context      map[string]interface{}
}
```

### Alert Manager

```go
alertManager := resources.NewAlertManager()
alertManager.RegisterHandler(resources.SeverityCritical, criticalHandler)
alertManager.RegisterHandler(resources.SeverityWarning, warningHandler)
```

## Integration Examples

### Basic Plugin Monitoring

```go
// Initialize monitor
monitor := resources.NewResourceMonitor(nil) // Use defaults
ctx := context.Background()
monitor.Start(ctx)
defer monitor.Stop()

// Track plugin with limits
limits := &resources.ResourceLimits{
    MaxMemoryMB:   256,
    MaxCPUPercent: 50.0,
    MaxGoroutines: 50,
}
monitor.TrackPlugin("my-plugin", limits)

// Check usage periodically
ticker := time.NewTicker(time.Minute)
for range ticker.C {
    usage, _ := monitor.GetPluginUsage("my-plugin")
    for resourceType, resource := range usage {
        if resource.Current > limits.GetLimit(resourceType) * 0.8 {
            log.Printf("Plugin %s approaching %s limit: %.2f%%",
                "my-plugin", resourceType, resource.Current)
        }
    }
}
```

### Custom Resource Collector

```go
type CustomCollector struct {
    pluginName string
}

func (c *CustomCollector) Collect() (*resources.ResourceUsage, error) {
    // Collect custom metrics
    customValue := getCustomMetric(c.pluginName)
    
    return &resources.ResourceUsage{
        PluginName:   c.pluginName,
        ResourceType: "custom_metric",
        Current:      customValue,
        Unit:         "units",
        Timestamp:    time.Now(),
    }, nil
}

// Register custom collector
monitor.RegisterCollector("my-plugin", "custom_metric", &CustomCollector{
    pluginName: "my-plugin",
})
```

## Performance Considerations

- **Collection Frequency** - Balance monitoring accuracy with overhead
- **Data Retention** - Configure appropriate retention periods
- **Batch Processing** - Use batching for high-frequency metrics
- **Memory Management** - Monitor the monitor's own resource usage
- **Concurrent Collections** - Limit concurrent collection operations

## Testing

```bash
go test ./pkg/resources -v
```

Test coverage includes:
- Resource collection accuracy
- Trend analysis algorithms
- Alert triggering and handling
- Performance under load
- Memory leak detection

## Dependencies

- `runtime` - Go runtime metrics
- `os` - Process and system information
- `syscall` - System call interfaces
- `time` - Time-based operations
- `sync` - Concurrency primitives

## Monitoring Dashboard Integration

The package supports exporting metrics to popular monitoring systems:

- **Prometheus** - Native metrics export
- **Grafana** - Dashboard templates
- **DataDog** - Custom metric integration
- **New Relic** - APM integration
- **CloudWatch** - AWS metrics export

## Future Enhancements

- Machine learning-based anomaly detection
- Predictive resource scaling recommendations
- Integration with container orchestration platforms
- Real-time resource optimization suggestions
- Advanced correlation analysis between resources