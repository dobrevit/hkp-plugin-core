# Versioning Package

The versioning package provides comprehensive multi-version plugin support with canary deployments, blue-green deployments, A/B testing, and intelligent traffic management for zero-downtime plugin updates.

## Overview

This package implements enterprise-grade plugin versioning capabilities with multiple deployment strategies, automated canary analysis, and intelligent traffic routing to ensure safe and reliable plugin updates with minimal risk.

## Components

### Core Files

- **`version_manager.go`** - Central version management and canary deployments
- **`deployment_strategies.go`** - Multiple deployment strategy implementations
- **`integration_test.go`** - Comprehensive versioning and deployment testing

## Key Features

### Multi-Version Plugin Support

```go
versionManager := versioning.NewVersionManager(auditLogger, config, logger)

// Register multiple versions
plugin1 := NewPlugin("my-plugin", "1.0.0")
plugin2 := NewPlugin("my-plugin", "2.0.0")

versionManager.RegisterPluginVersion("my-plugin", "1.0.0", plugin1, config1)
versionManager.RegisterPluginVersion("my-plugin", "2.0.0", plugin2, config2)
```

### Canary Deployments

```go
canaryConfig := &versioning.CanaryConfig{
    InitialPercent:    5.0,   // Start with 5% traffic
    IncrementPercent:  5.0,   // Increase by 5% each step
    IncrementInterval: 10 * time.Minute,
    MaxPercent:        50.0,  // Maximum canary traffic
    SuccessThreshold:  0.99,  // 99% success rate required
    ErrorThreshold:    0.01,  // 1% error rate triggers rollback
    AutoPromote:       true,
    AutoRollback:      true,
}

err := versionManager.StartCanaryDeployment("my-plugin", "2.0.0", canaryConfig)
```

### Intelligent Traffic Splitting

```go
// Automatic traffic routing based on canary configuration
version, err := versionManager.GetPluginVersion("my-plugin", 
    versionManager.ShouldUseCanary("my-plugin", requestID))

// Hash-based consistent routing ensures user session consistency
```

## Version Management

### Plugin Version Structure

```go
type PluginVersion struct {
    Plugin       plugin.Plugin             // The actual plugin instance
    Version      string                    // Semantic version string
    Status       VersionStatus             // Current version status
    LoadTime     time.Time                 // When version was loaded
    LastAccessed time.Time                 // Last request timestamp
    RequestCount int64                     // Total request count
    ErrorCount   int64                     // Total error count
    HealthScore  float64                   // Calculated health score (0-100)
    Metadata     map[string]interface{}    // Version-specific metadata
    Dependencies []plugin.PluginDependency // Plugin dependencies
    Config       map[string]interface{}    // Version configuration
}
```

### Version Status Types

```go
const (
    VersionStatusLoading    VersionStatus = "loading"    // Being loaded
    VersionStatusActive     VersionStatus = "active"     // Current production
    VersionStatusCanary     VersionStatus = "canary"     // Canary testing
    VersionStatusDeprecated VersionStatus = "deprecated" // Being phased out
    VersionStatusFailed     VersionStatus = "failed"     // Failed deployment
    VersionStatusRetired    VersionStatus = "retired"    // No longer used
)
```

### Version History Tracking

```go
type VersionHistoryEntry struct {
    Version       string        // Version identifier
    Action        string        // Action performed (registered, promoted, etc.)
    Timestamp     time.Time     // When action occurred
    Success       bool          // Whether action succeeded
    ErrorMessage  string        // Error details if failed
    CanaryPercent float64       // Canary percentage if applicable
    Duration      time.Duration // How long action took
}
```

## Canary Deployments

### Canary Configuration

```go
type CanaryConfig struct {
    InitialPercent     float64             // Starting traffic percentage
    IncrementPercent   float64             // Traffic increase per step
    IncrementInterval  time.Duration       // Time between increments
    MaxPercent         float64             // Maximum canary traffic
    SuccessThreshold   float64             // Success rate threshold
    ErrorThreshold     float64             // Error rate threshold
    MinRequests        int64               // Minimum requests before decisions
    ObservationPeriod  time.Duration       // Observation time before auto-decisions
    AutoPromote        bool                // Automatic promotion on success
    AutoRollback       bool                // Automatic rollback on failure
    NotificationConfig *NotificationConfig // Alert configuration
}
```

### Canary Metrics Tracking

```go
type CanaryMetrics struct {
    TotalRequests         int64         // Total requests processed
    CanaryRequests        int64         // Requests to canary version
    CanaryErrors          int64         // Errors in canary version
    CanarySuccesses       int64         // Successful canary requests
    CanaryErrorRate       float64       // Calculated error rate
    CanarySuccessRate     float64       // Calculated success rate
    CanaryResponseTime    time.Duration // Average response time
    ProductionErrorRate   float64       // Production version error rate
    ProductionSuccessRate float64       // Production version success rate
    HealthScore           float64       // Overall health score
    LastUpdated           time.Time     // Last metrics update
}
```

### Canary Status Management

```go
const (
    CanaryStatusPending     CanaryStatus = "pending"      // Queued for deployment
    CanaryStatusActive      CanaryStatus = "active"       // Currently running
    CanaryStatusPromoting   CanaryStatus = "promoting"    // Being promoted
    CanaryStatusRollingBack CanaryStatus = "rolling_back" // Being rolled back
    CanaryStatusCompleted   CanaryStatus = "completed"    // Successfully completed
    CanaryStatusFailed      CanaryStatus = "failed"       // Failed deployment
)
```

## Deployment Strategies

### Blue-Green Deployment

Instant traffic switching between two identical environments:

```go
blueGreenStrategy := versioning.NewBlueGreenDeploymentStrategy(versionManager, logger)

deploymentSpec := &versioning.DeploymentSpec{
    PluginName:       "my-plugin",
    OldVersion:       "1.0.0",
    NewVersion:       "2.0.0",
    Strategy:         "blue-green",
    HealthCheckURL:   "/health",
    RollbackOnError:  true,
    NotifyOnComplete: true,
}

err := blueGreenStrategy.Deploy(context.Background(), deploymentSpec)
```

### Rolling Deployment

Gradual traffic shifting with automatic progression:

```go
rollingStrategy := versioning.NewRollingDeploymentStrategy(versionManager, logger)

deploymentSpec := &versioning.DeploymentSpec{
    PluginName: "my-plugin",
    OldVersion: "1.0.0",
    NewVersion: "2.0.0",
    Strategy:   "rolling",
    Config: map[string]interface{}{
        "initial_percent":   10.0,
        "increment_percent": 10.0,
        "success_threshold": 0.95,
        "error_threshold":   0.05,
        "auto_promote":      true,
        "auto_rollback":     true,
    },
}

err := rollingStrategy.Deploy(context.Background(), deploymentSpec)
```

### A/B Testing Deployment

Fixed traffic split for controlled experimentation:

```go
abTestingStrategy := versioning.NewABTestingStrategy(versionManager, logger)

deploymentSpec := &versioning.DeploymentSpec{
    PluginName: "my-plugin",
    OldVersion: "1.0.0",
    NewVersion: "2.0.0",
    Strategy:   "ab-testing",
    Config: map[string]interface{}{
        "test_percent":      50.0,                // 50-50 split
        "test_duration":     "24h",               // Run for 24 hours
        "min_requests":      1000,                // Minimum sample size
        "success_threshold": 0.95,
        "auto_rollback":     true,
    },
}

err := abTestingStrategy.Deploy(context.Background(), deploymentSpec)
```

## Deployment Orchestration

### Deployment Orchestrator

```go
orchestrator := versioning.NewDeploymentOrchestrator(versionManager, logger)

// Get available strategies
strategies := orchestrator.GetAvailableStrategies()
// Returns: {"blue-green": "Instant traffic switching", "rolling": "Gradual traffic shifting", ...}

// Execute deployment
err := orchestrator.Deploy(context.Background(), deploymentSpec)

// Rollback if needed
err := orchestrator.Rollback(context.Background(), deploymentSpec)
```

### Custom Deployment Strategies

```go
type CustomStrategy struct {
    name        string
    description string
    deployFunc  func(context.Context, *DeploymentSpec) error
    rollbackFunc func(context.Context, *DeploymentSpec) error
}

func (cs *CustomStrategy) Deploy(ctx context.Context, spec *DeploymentSpec) error {
    return cs.deployFunc(ctx, spec)
}

func (cs *CustomStrategy) Rollback(ctx context.Context, spec *DeploymentSpec) error {
    return cs.rollbackFunc(ctx, spec)
}

// Register custom strategy
orchestrator.RegisterStrategy("custom", &CustomStrategy{...})
```

## Configuration Management

### Version Manager Configuration

```go
type VersionConfig struct {
    MaxVersionsPerPlugin   int           // Maximum concurrent versions
    DefaultCanaryConfig    *CanaryConfig // Default canary settings
    AutoCleanupOldVersions bool          // Automatic version cleanup
    CleanupThreshold       time.Duration // Age threshold for cleanup
    HealthCheckInterval    time.Duration // Version health check frequency
    MetricsRetentionPeriod time.Duration // How long to keep metrics
    EnableVersionHistory   bool          // Track version history
    HistoryRetentionPeriod time.Duration // History retention period
}
```

### Notification Configuration

```go
type NotificationConfig struct {
    EnableNotifications bool     // Enable notification system
    WebhookURL          string   // Webhook for notifications
    EmailRecipients     []string // Email notification list
    SlackChannel        string   // Slack channel for alerts
    NotifyOnStart       bool     // Notify when deployment starts
    NotifyOnComplete    bool     // Notify when deployment completes
    NotifyOnFailure     bool     // Notify on deployment failures
}
```

## Usage Examples

### Basic Version Management

```go
// Initialize version manager
vm := versioning.NewVersionManager(auditLogger, nil, logger)
vm.Start(context.Background())
defer vm.Stop()

// Register initial version
plugin1 := loadPlugin("my-plugin-v1.0.0.so")
vm.RegisterPluginVersion("my-plugin", "1.0.0", plugin1, config)

// Register new version
plugin2 := loadPlugin("my-plugin-v2.0.0.so")
vm.RegisterPluginVersion("my-plugin", "2.0.0", plugin2, config)

// Start canary deployment
canaryConfig := &versioning.CanaryConfig{
    InitialPercent:   10.0,
    SuccessThreshold: 0.99,
    ErrorThreshold:   0.01,
    AutoPromote:      true,
    AutoRollback:     true,
}

vm.StartCanaryDeployment("my-plugin", "2.0.0", canaryConfig)
```

### Request Routing

```go
// In your request handler
func handleRequest(w http.ResponseWriter, r *http.Request) {
    requestID := generateRequestID(r)
    
    // Determine which version to use
    useCanary := versionManager.ShouldUseCanary("my-plugin", requestID)
    pluginVersion, err := versionManager.GetPluginVersion("my-plugin", useCanary)
    
    if err != nil {
        http.Error(w, "Plugin unavailable", http.StatusServiceUnavailable)
        return
    }
    
    // Record metrics
    start := time.Now()
    err = pluginVersion.Plugin.HandleRequest(w, r)
    duration := time.Since(start)
    
    success := err == nil
    versionManager.RecordCanaryMetrics("my-plugin", success, duration)
}
```

### Monitoring Deployments

```go
// Check deployment status
status, err := versionManager.GetVersionStatus("my-plugin")
if err != nil {
    log.Printf("Failed to get status: %v", err)
    return
}

fmt.Printf("Current version: %s\n", status["current_version"])
fmt.Printf("Canary version: %s\n", status["canary_version"])
fmt.Printf("Canary traffic: %.1f%%\n", status["canary_percent"])

if deployment, ok := status["canary_deployment"]; ok {
    deploymentInfo := deployment.(map[string]interface{})
    fmt.Printf("Deployment status: %s\n", deploymentInfo["status"])
    
    if metrics, ok := deploymentInfo["metrics"]; ok {
        metricsInfo := metrics.(*versioning.CanaryMetrics)
        fmt.Printf("Success rate: %.2f%%\n", metricsInfo.CanarySuccessRate*100)
        fmt.Printf("Error rate: %.2f%%\n", metricsInfo.CanaryErrorRate*100)
    }
}
```

## Traffic Splitting Algorithm

### Hash-Based Routing

The system uses consistent hash-based routing to ensure user session consistency:

```go
func (vm *VersionManager) ShouldUseCanary(pluginName string, requestID string) bool {
    deployment, exists := vm.deployments[pluginName]
    if !exists || deployment.Status != CanaryStatusActive {
        return false
    }
    
    // Hash-based consistent routing
    hash := simpleHash(requestID)
    return float64(hash%100) < deployment.CanaryPercent
}
```

### Session Consistency

- Same user/session always routes to same version during canary
- Gradual user migration as canary percentage increases
- No mid-session version switching

## Monitoring and Observability

### Health Scoring

```go
func calculateHealthScore(metrics *CanaryMetrics) float64 {
    if metrics.CanaryRequests == 0 {
        return 100.0 // No data, assume healthy
    }
    
    // Base score on success rate
    score := metrics.CanarySuccessRate * 100
    
    // Penalize high error rates
    if metrics.CanaryErrorRate > 0.05 {
        score *= 0.5
    } else if metrics.CanaryErrorRate > 0.01 {
        score *= 0.8
    }
    
    return math.Max(0, math.Min(100, score))
}
```

### Automatic Decision Making

The system automatically makes promotion/rollback decisions based on:

- **Success Rate** - Must meet threshold for promotion
- **Error Rate** - Triggers rollback if exceeded
- **Request Volume** - Minimum sample size required
- **Observation Period** - Time-based decision windows
- **Health Score** - Overall version health assessment

## Testing

```bash
go test ./pkg/versioning -v
```

Test coverage includes:
- Version registration and management
- Canary deployment lifecycle
- Traffic splitting accuracy
- Automatic promotion/rollback
- Deployment strategy execution
- Metrics collection and analysis
- Error handling and edge cases

## Performance Considerations

- **Version Storage** - Limit concurrent versions per plugin
- **Metrics Collection** - Efficient aggregation of canary metrics
- **Traffic Routing** - Fast hash-based routing decisions
- **Memory Management** - Automatic cleanup of old versions
- **Concurrent Access** - Thread-safe version management

## Dependencies

- `context` - Context-based operations
- `sync` - Concurrency control
- `time` - Time-based operations
- `log/slog` - Structured logging
- Plugin and security packages

## Integration Points

### Plugin Manager Integration

The version manager integrates with the existing plugin system:

```go
type PluginManagerInterface interface {
    GetPlugin(name string) (plugin.Plugin, bool)
    ListPlugins() []plugin.Plugin
    LoadPlugin(ctx context.Context, plugin plugin.Plugin, config map[string]interface{}) error
}
```

### Security Integration

All version operations are audited through the security system:

```go
auditLogger.LogSecurityEvent("plugin_version_registered", map[string]interface{}{
    "plugin_name": pluginName,
    "version":     version,
    "timestamp":   time.Now(),
})
```

## Future Enhancements

- Machine learning-based canary success prediction
- Advanced traffic shaping algorithms
- Integration with service mesh technologies
- Multi-region canary deployments
- Automated performance regression detection
- Real-time deployment dashboards
- Integration with CI/CD pipelines