# Plugin Health Monitoring System

This document describes the comprehensive health monitoring and restart logic implemented for the gRPC plugin architecture.

## Overview

The health monitoring system provides:

- **Automatic Health Checks**: Continuous monitoring of plugin health
- **Failure Detection**: Detection of unhealthy plugins
- **Automatic Restart**: Automatic restart of failed plugins with backoff
- **HTTP Endpoints**: REST API for health status and management
- **Kubernetes Integration**: Liveness and readiness probes
- **Comprehensive Metrics**: Detailed health and performance metrics

## Architecture

### Core Components

1. **Health Monitor** (`pkg/health/monitor.go`)
   - Monitors plugin health continuously
   - Manages restart logic with exponential backoff
   - Tracks failure counts and restart attempts

2. **Health Handler** (`pkg/health/handler.go`)
   - Provides HTTP endpoints for health status
   - Implements Kubernetes probe endpoints
   - Handles manual restart requests

3. **Plugin Integration** (`pkg/grpc/client/hockeypuck_integration.go`)
   - Integrates health monitoring with plugin system
   - Provides simplified interface for Hockeypuck

### Health States

Plugins can be in one of these states:

- **Unknown**: Initial state or after restart
- **Healthy**: Plugin is functioning normally
- **Unhealthy**: Plugin failed health checks
- **Degraded**: Plugin responding but with issues
- **Restarting**: Plugin is being restarted
- **Failed**: Plugin failed and exceeded max restart attempts

## Configuration

### Monitor Configuration

```go
type MonitorConfig struct {
    CheckInterval     time.Duration // How often to check (default: 30s)
    CheckTimeout      time.Duration // Health check timeout (default: 10s)
    FailureThreshold  int           // Failures before unhealthy (default: 3)
    SuccessThreshold  int           // Successes to mark healthy (default: 2)
    MaxRestarts       int           // Max restart attempts (default: 5)
    RestartBackoff    time.Duration // Initial restart delay (default: 5s)
    MaxRestartBackoff time.Duration // Max restart delay (default: 5m)
}
```

### Usage in Hockeypuck

```go
// Create plugin host with health monitoring
pluginAdapter := client.NewSimplePluginAdapter("/etc/hockeypuck/plugins", logger)

// Start plugins with health monitoring
if err := pluginAdapter.Start(ctx); err != nil {
    logger.WithError(err).Error("Failed to start plugins")
}

// Add HTTP middleware with health checks
handler = pluginAdapter.HTTPMiddleware()(handler)

// Add health endpoints
mux.HandleFunc("/health", pluginAdapter.HandleManagement)
mux.HandleFunc("/plugins/", pluginAdapter.HandleManagement)
```

## HTTP Endpoints

### Health Check Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Overall system health status |
| `/health/liveness` | GET | Kubernetes liveness probe |
| `/health/readiness` | GET | Kubernetes readiness probe |
| `/health/{plugin}` | GET | Specific plugin health |

### Plugin Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/plugins/status` | GET | Plugin status overview |
| `/plugins/health` | GET | Detailed plugin health |
| `/plugins/restart?plugin={name}` | POST | Restart specific plugin |

### Response Examples

#### Overall Health (`/health`)

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "plugins": {
    "antiabuse": {
      "status": "healthy",
      "lastCheckTime": "2024-01-15T10:29:45Z",
      "lastHealthyTime": "2024-01-15T10:29:45Z",
      "failureCount": 0,
      "restartCount": 0,
      "responseTime": "15ms",
      "healthy": true
    }
  },
  "summary": {
    "totalPlugins": 1,
    "healthyPlugins": 1,
    "unhealthyPlugins": 0,
    "restartingPlugins": 0,
    "failedPlugins": 0
  }
}
```

#### Plugin Status (`/plugins/status`)

```json
{
  "enabled": true,
  "initialized": true,
  "total": 1,
  "connected": 1,
  "plugins": [
    {
      "name": "antiabuse",
      "version": "1.0.0",
      "description": "Anti-abuse rate limiting plugin",
      "connected": true,
      "executable": "/path/to/plugin"
    }
  ]
}
```

## Health Check Logic

### Monitoring Loop

1. **Periodic Checks**: Health checks run every 30 seconds (configurable)
2. **Timeout Handling**: Each check has a 10-second timeout
3. **Failure Tracking**: Failed checks increment failure counter
4. **State Transitions**: State changes based on thresholds

### Restart Logic

When a plugin becomes unhealthy:

1. **Backoff Calculation**: `backoff = RestartBackoff * restartCount`
2. **Maximum Backoff**: Capped at `MaxRestartBackoff`
3. **Restart Attempt**: Plugin process is stopped and restarted
4. **Connection Retry**: New gRPC connection established
5. **Health Reset**: Failure count reset on successful restart

### State Diagram

```
Unknown → (health check) → Healthy
Healthy → (failures >= threshold) → Unhealthy
Unhealthy → (restart attempt) → Restarting
Restarting → (success) → Unknown
Restarting → (failure) → Failed (if max restarts exceeded)
Failed → (manual restart) → Restarting
```

## Kubernetes Integration

### Liveness Probe

```yaml
livenessProbe:
  httpGet:
    path: /health/liveness
    port: 11371
  initialDelaySeconds: 30
  periodSeconds: 10
```

### Readiness Probe

```yaml
readinessProbe:
  httpGet:
    path: /health/readiness
    port: 11371
  initialDelaySeconds: 5
  periodSeconds: 5
```

## Monitoring and Alerting

### Metrics Available

- Plugin health status
- Failure counts
- Restart counts
- Response times
- Last health check time
- Last healthy time

### Alerting Recommendations

1. **High Failure Rate**: Alert if failure count > 2
2. **Restart Frequency**: Alert if restart count > 3 in 1 hour
3. **Response Time**: Alert if average response time > 5 seconds
4. **Plugin Down**: Alert if plugin status = "failed"

## Demo Application

A complete demonstration is available:

```bash
# Build and run health monitoring demo
make health-monitoring
cd cmd/health-monitoring
./health-monitoring

# Visit http://localhost:8080 for interactive demo
```

### Demo Features

- Interactive web interface
- Load simulation tools
- Failure simulation
- Real-time health monitoring
- Plugin restart testing

## Advanced Features

### Custom Health Checks

Plugins can implement custom health logic:

```go
// In plugin implementation
func (p *Plugin) HealthCheck(ctx context.Context, req *proto.Empty) (*proto.HealthStatus, error) {
    // Custom health logic
    if p.checkDatabase() && p.checkRedis() && p.checkExternalAPI() {
        return &proto.HealthStatus{
            Status: proto.HealthStatus_HEALTHY,
            Message: "All dependencies healthy",
        }, nil
    }
    
    return &proto.HealthStatus{
        Status: proto.HealthStatus_UNHEALTHY,
        Message: "Database connection failed",
    }, nil
}
```

### Circuit Breaker Integration

The health monitoring can integrate with circuit breakers to prevent cascading failures:

```go
// Circuit breaker pattern
if pluginUnhealthy {
    // Open circuit - fail fast
    return http.StatusServiceUnavailable
}
```

### Metrics Export

Health metrics can be exported to monitoring systems:

```go
// Prometheus metrics example
pluginHealthGauge.WithLabelValues(pluginName).Set(healthValue)
pluginRestartCounter.WithLabelValues(pluginName).Inc()
```

## Production Considerations

### Performance

- Health checks are performed in parallel
- Timeouts prevent hanging checks
- Efficient resource usage with goroutines

### Reliability

- Graceful degradation when monitoring fails
- Automatic recovery from monitoring issues
- Configurable thresholds for different environments

### Security

- Health endpoints can be secured with authentication
- Rate limiting on management endpoints
- Audit logging for restart operations

### Scalability

- Monitoring scales with number of plugins
- Efficient memory usage for health data
- Configurable monitoring intervals

## Troubleshooting

### Common Issues

1. **Plugin Won't Start**: Check plugin binary and permissions
2. **Health Checks Failing**: Verify gRPC connectivity
3. **Excessive Restarts**: Increase failure threshold or check plugin logs
4. **Slow Health Checks**: Tune timeout settings

### Debug Logging

Enable debug logging to see health check details:

```toml
[logging]
level = "debug"
```

### Manual Recovery

Force restart a plugin:

```bash
curl -X POST "http://localhost:11371/plugins/restart?plugin=antiabuse"
```

## Integration Examples

### Docker Compose

```yaml
version: '3'
services:
  hockeypuck:
    image: hockeypuck:latest
    ports:
      - "11371:11371"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11371/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hockeypuck
spec:
  template:
    spec:
      containers:
      - name: hockeypuck
        image: hockeypuck:latest
        ports:
        - containerPort: 11371
        livenessProbe:
          httpGet:
            path: /health/liveness
            port: 11371
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/readiness
            port: 11371
          initialDelaySeconds: 5
          periodSeconds: 5
```

This health monitoring system provides comprehensive monitoring, automatic recovery, and operational visibility for the gRPC plugin architecture, ensuring high availability and reliability in production environments.