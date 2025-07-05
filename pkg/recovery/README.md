# Recovery Package

The recovery package provides automatic failure recovery with circuit breaker patterns, health checking, and intelligent recovery strategies for plugin failure management.

## Overview

This package implements enterprise-grade failure recovery mechanisms using circuit breaker patterns, multiple recovery strategies, and automated health monitoring to ensure system resilience and minimize downtime.

## Components

### Core Files

- **`circuit_breaker.go`** - Circuit breaker implementation with state management
- **`recovery_manager.go`** - Central recovery orchestration and management
- **`strategies.go`** - Multiple recovery strategy implementations
- **`integration_test.go`** - Comprehensive recovery testing

## Key Features

### Circuit Breaker Pattern

```go
cb := recovery.NewCircuitBreaker("my-plugin", &recovery.CircuitBreakerConfig{
    FailureThreshold: 5,
    SuccessThreshold: 3,
    Timeout:          30 * time.Second,
    MinimumRequests:  10,
})

err := cb.Execute(context.Background(), func(ctx context.Context) error {
    return pluginOperation()
})
```

### Recovery Manager

```go
recoveryManager := recovery.NewRecoveryManager(
    pluginManager,
    auditLogger,
    &recovery.RecoveryConfig{
        EnableAutoRecovery:   true,
        EnableHealthChecking: true,
        HealthCheckInterval:  30 * time.Second,
        MaxRecoveryAttempts:  3,
    },
    logger,
)

err := recoveryManager.Start(context.Background())
```

### Multiple Recovery Strategies

```go
// Automatic strategy selection based on failure type
failure := &recovery.FailureInfo{
    Type:        recovery.FailureTypeTimeout,
    Recoverable: true,
    Severity:    "warning",
}

recoveryManager.RecordFailure("my-plugin", failure)
```

## Circuit Breaker States

### State Transitions

- **Closed** - Normal operation, requests allowed
- **Open** - Failing state, requests rejected immediately
- **Half-Open** - Testing recovery, limited requests allowed
- **Repairing** - Actively attempting repair operations

### Circuit Breaker Configuration

```go
type CircuitBreakerConfig struct {
    FailureThreshold    int64         // Failures before opening
    SuccessThreshold    int64         // Successes to close from half-open
    Timeout            time.Duration  // Time before half-open attempt
    HealthCheckInterval time.Duration // Active health check frequency
    HealthCheckTimeout  time.Duration // Health check operation timeout
    MaxHealthChecks     int64         // Max consecutive health failures
    RetryBackoffFactor  float64       // Exponential backoff multiplier
    MaxRetryInterval    time.Duration // Maximum retry interval
    EnableFastFail      bool          // Fail fast when circuit open
    SlidingWindowSize   int64         // Metrics sliding window size
    MinimumRequests     int64         // Min requests before circuit can open
}
```

## Recovery Strategies

### Restart Strategy

Complete plugin restart with graceful shutdown:

```go
type RestartStrategy struct {
    pluginManager PluginManagerInterface
    logger        *slog.Logger
}

// Handles: timeouts, errors, panics, health check failures
// Priority: 100 (High)
```

### Reload Strategy

Gentle plugin reinitialization without full restart:

```go
type ReloadStrategy struct {
    pluginManager PluginManagerInterface
    logger        *slog.Logger
}

// Handles: timeouts, errors, health checks (non-critical)
// Priority: 80 (Medium-High)
```

### Reset Strategy

Circuit breaker reset for minor issues:

```go
type ResetStrategy struct {
    recoveryManager *RecoveryManager
    logger          *slog.Logger
}

// Handles: health check failures, warning-level timeouts
// Priority: 60 (Medium)
```

### Graceful Degradation Strategy

Reduces functionality to maintain basic operation:

```go
type GracefulDegradationStrategy struct {
    pluginManager PluginManagerInterface
    logger        *slog.Logger
}

// Handles: resource limits, non-critical timeouts
// Priority: 40 (Medium-Low)
```

### Backoff Strategy

Exponential backoff with temporary suspension:

```go
type BackoffStrategy struct {
    pluginManager   PluginManagerInterface
    logger          *slog.Logger
    backoffAttempts map[string]int
    lastAttempt     map[string]time.Time
}

// Handles: temporary failures, last resort recovery
// Priority: 20 (Low)
```

## Failure Types

### Supported Failure Types

```go
const (
    FailureTypeTimeout        FailureType = "timeout"
    FailureTypeError          FailureType = "error"
    FailureTypeResourceLimit  FailureType = "resource_limit"
    FailureTypePanic          FailureType = "panic"
    FailureTypeHealthCheck    FailureType = "health_check"
    FailureTypeInitialization FailureType = "initialization"
)
```

### Failure Information

```go
type FailureInfo struct {
    Type        FailureType
    Timestamp   time.Time
    Message     string
    Stack       string                 // For panic recovery
    Context     map[string]interface{} // Additional context
    Recoverable bool                   // Can this failure be recovered?
    Severity    string                 // "critical", "warning", "info"
}
```

## Health Checking

### Health Check Configuration

```go
type HealthCheckConfig struct {
    Interval     time.Duration          // Check frequency
    Timeout      time.Duration          // Check timeout
    MaxFailures  int                    // Failures before action
    CheckType    string                 // Type of health check
    CustomChecks map[string]interface{} // Plugin-specific checks
}
```

### Health Check Results

```go
type HealthCheckResult struct {
    Healthy   bool
    Timestamp time.Time
    Duration  time.Duration
    Message   string
    Details   map[string]interface{}
    CheckType string
}
```

## Recovery Configuration

### Recovery Manager Configuration

```go
type RecoveryConfig struct {
    EnableAutoRecovery       bool
    HealthCheckInterval      time.Duration
    MaxRecoveryAttempts      int
    RecoveryBackoffFactor    float64
    DefaultCircuitBreaker    *CircuitBreakerConfig
    DefaultRecoveryStrategy  string
    PluginRecoveryStrategies map[string]string
    RecoveryStrategyConfigs  map[string]map[string]interface{}
    EnableHealthChecking     bool
    HealthCheckTimeout       time.Duration
    HealthCheckConcurrency   int
    EnableAlerting           bool
    AlertThresholds          *AlertThresholds
}
```

### Alert Thresholds

```go
type AlertThresholds struct {
    ConsecutiveFailures int           // Alert after N failures
    FailureRate         float64       // Alert at failure rate %
    RecoveryTime        time.Duration // Alert if recovery takes too long
}
```

## Usage Examples

### Basic Recovery Setup

```go
// Create recovery manager
config := recovery.DefaultRecoveryConfig()
config.EnableAutoRecovery = true
config.HealthCheckInterval = 30 * time.Second

rm := recovery.NewRecoveryManager(pluginManager, auditLogger, config, logger)

// Start recovery monitoring
ctx := context.Background()
rm.Start(ctx)
defer rm.Stop()

// Register plugins for recovery
rm.RegisterPlugin("critical-plugin")
rm.RegisterPlugin("secondary-plugin")
```

### Executing with Circuit Breaker Protection

```go
err := rm.ExecuteWithRecovery(ctx, "my-plugin", func(ctx context.Context) error {
    return performPluginOperation()
})

if err != nil {
    // Circuit breaker may be open, or operation failed
    log.Printf("Plugin operation failed: %v", err)
}
```

### Manual Failure Recording

```go
failure := &recovery.FailureInfo{
    Type:        recovery.FailureTypeTimeout,
    Timestamp:   time.Now(),
    Message:     "Plugin response timeout",
    Recoverable: true,
    Severity:    "warning",
    Context: map[string]interface{}{
        "timeout_duration": "30s",
        "operation":       "data_processing",
    },
}

rm.RecordFailure("my-plugin", failure)
```

### Custom Recovery Strategy

```go
customStrategy := recovery.NewCustomStrategy(
    "custom-recovery",
    150, // High priority
    func(failure *recovery.FailureInfo) bool {
        return failure.Type == recovery.FailureTypeError &&
               failure.Severity == "custom"
    },
    func(ctx context.Context, pluginName string, failure *recovery.FailureInfo) error {
        // Custom recovery logic
        return performCustomRecovery(pluginName)
    },
    logger,
)

// Register custom strategy
rm.RegisterStrategy("custom-recovery", customStrategy)
```

## Monitoring and Metrics

### Recovery Status

```go
status := rm.GetRecoveryStatus()

// Example status structure:
{
    "running": true,
    "auto_recovery": true,
    "health_checking": true,
    "plugins": {
        "my-plugin": {
            "circuit_breaker": {
                "state": "closed",
                "total_requests": 1000,
                "total_failures": 5,
                "failure_rate": 0.005
            },
            "health_check": {
                "last_check": "2024-01-01T12:00:00Z",
                "last_result": {
                    "healthy": true,
                    "duration": "50ms"
                },
                "consecutive_fails": 0
            }
        }
    }
}
```

### Circuit Breaker Metrics

```go
metrics := cb.GetMetrics()

type CircuitBreakerMetrics struct {
    Name               string
    State              CircuitBreakerState
    TotalRequests      int64
    TotalFailures      int64
    TotalSuccesses     int64
    FailureRate        float64
    LastFailure        time.Time
    LastSuccess        time.Time
    StateChangeTime    time.Time
    CircuitOpenTime    time.Duration
    HealthCheckSuccess bool
    NextRetryTime      time.Time
}
```

## Integration with Other Systems

### Plugin Manager Integration

```go
type PluginManagerInterface interface {
    GetPlugin(name string) (plugin.Plugin, bool)
    ListPlugins() []plugin.Plugin
    LoadPlugin(ctx context.Context, plugin plugin.Plugin, config map[string]interface{}) error
}
```

### Audit Logger Integration

```go
// Recovery events are automatically logged
auditLogger.LogFailureRecovery(pluginName, failureType, recoveryAction, success)
```

## Testing

```bash
go test ./pkg/recovery -v
```

Test scenarios include:
- Circuit breaker state transitions
- Recovery strategy selection and execution
- Health check failure handling
- Concurrent failure scenarios
- Recovery performance under load

## Performance Considerations

- **Health Check Frequency** - Balance monitoring with overhead
- **Circuit Breaker Thresholds** - Tune for application requirements
- **Recovery Strategy Priority** - Order strategies by effectiveness
- **Concurrent Recovery** - Limit simultaneous recovery attempts
- **Memory Usage** - Monitor metrics storage and cleanup

## Dependencies

- `context` - Context-based cancellation
- `sync` - Concurrency primitives
- `time` - Time-based operations
- `log/slog` - Structured logging
- Plugin and security packages

## Future Enhancements

- Machine learning-based failure prediction
- Advanced correlation analysis between failures
- Integration with external monitoring systems
- Automated recovery strategy optimization
- Cross-service failure correlation
- Real-time recovery dashboards