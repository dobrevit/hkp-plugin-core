# Anti-Abuse Plugin

> **Implementation Status**: ⚠️ **Middleware Only** - This plugin currently implements only HTTP middleware functionality with no exposed API endpoints.

## Overview

The Anti-Abuse Plugin provides fundamental behavioral analysis and abuse detection capabilities for the HKP (Hockeypuck) server. This plugin implements basic yet effective anti-abuse mechanisms including request rate limiting, behavioral pattern detection, and abuse prevention measures that serve as a foundation for more advanced security plugins.

## Key Features

### Basic Rate Limiting
- **Sliding Window Algorithm**: Implements sliding window rate limiting for precise control
- **Per-IP Tracking**: Individual rate limits per client IP address
- **Configurable Thresholds**: Adjustable request limits and time windows
- **Memory Efficient**: Automatic cleanup of expired request records

### Behavioral Monitoring
- **Request Pattern Analysis**: Monitors request timing and frequency patterns
- **Abuse Detection**: Identifies basic abuse patterns like rapid-fire requests
- **Client Fingerprinting**: Basic client identification and tracking
- **Violation Logging**: Records and logs rate limit violations

### Integration Support
- **Event Publishing**: Publishes abuse events for other plugins to consume
- **Header Communication**: Adds anti-abuse headers for downstream processing
- **Middleware Architecture**: Seamlessly integrates with existing HTTP middleware
- **Coordination Ready**: Designed to work alongside advanced security plugins

## Configuration

### Basic Configuration

```toml
[plugins.antiabuse-basic]
enabled = true
requestThreshold = 10
windowSeconds = 10
autoCleanupInterval = "5m"
logViolations = true
enableHeaders = true
```

### Advanced Configuration

```toml
[plugins.antiabuse-basic]
enabled = true
requestThreshold = 15
windowSeconds = 10
autoCleanupInterval = "3m"
logViolations = true
enableHeaders = true

# Advanced behavioral settings
strictMode = false
burstTolerance = 3
adaptiveThresholds = false
gracePeriodsEnabled = true

# Integration settings
publishEvents = true
coordinateWithML = true
respectWhitelist = true

# Response customization
customErrorMessage = "Request rate exceeded. Please wait before retrying."
banDuration = "30s"
escalationEnabled = false

# Monitoring and debugging
verboseLogging = false
metricsEnabled = true
statisticsInterval = "1m"
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable the plugin |
| `requestThreshold` | int | `10` | Maximum requests per time window |
| `windowSeconds` | int | `10` | Time window for rate limiting (seconds) |
| `autoCleanupInterval` | string | `"5m"` | How often to clean up old request records |
| `logViolations` | boolean | `true` | Log rate limit violations |
| `enableHeaders` | boolean | `true` | Add anti-abuse headers to responses |
| `strictMode` | boolean | `false` | More aggressive abuse detection |
| `burstTolerance` | int | `3` | Allow brief bursts above threshold |
| `adaptiveThresholds` | boolean | `false` | Adjust thresholds based on traffic patterns |

## Abuse Detection Methods

### Rate Limiting Algorithm

The plugin uses a sliding window algorithm that provides accurate rate limiting:

```
Time Window: [-------- 10 seconds --------]
Requests:    |  |  |     |  |  |  |  |  |
             1  2  3     4  5  6  7  8  9
                         ^
                    Current time

If requests > threshold: BLOCK
Else: ALLOW
```

### Detection Patterns

| Pattern | Description | Action |
|---------|-------------|--------|
| **Rate Exceeded** | More than N requests in time window | Block with 429 status |
| **Burst Attack** | Sudden spike in request rate | Block with configurable duration |
| **Sustained Load** | Consistent high request rate | Escalate to longer ban |
| **Pattern Abuse** | Repeated violations | Increase ban duration |

### Behavioral Metrics

- **Request Frequency**: Average time between requests
- **Burst Patterns**: Detection of rapid-fire request sequences  
- **Violation History**: Track of previous rate limit violations
- **Timing Analysis**: Analysis of request timing patterns
- **Client Consistency**: Monitoring of client behavior consistency

## Response Headers

The plugin adds informational headers for monitoring and coordination:

```http
X-AntiAbuse-Plugin: antiabuse-basic/1.0.0
X-AntiAbuse-Requests: 8/10
X-AntiAbuse-Window: 10s
X-AntiAbuse-Reset: 1609459200
X-AntiAbuse-Blocked: false
```

When a request is blocked:
```http
X-AntiAbuse-Blocked: true
X-RateLimit-Ban: 30s
X-AntiAbuse-Reason: rate_exceeded
X-AntiAbuse-Retry-After: 30
```

## Client IP Extraction

The plugin intelligently extracts client IPs considering various proxy scenarios:

### IP Extraction Priority
1. **X-Forwarded-For** header (first IP in chain)
2. **X-Real-IP** header 
3. **Remote address** from connection

### Proxy Handling
```go
// Example of robust IP extraction
func extractClientIP(r *http.Request) string {
    // Handle X-Forwarded-For with multiple IPs
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        if idx := strings.Index(xff, ","); idx != -1 {
            return strings.TrimSpace(xff[:idx])
        }
        return strings.TrimSpace(xff)
    }
    
    // Handle load balancer scenarios
    if xri := r.Header.Get("X-Real-IP"); xri != "" {
        return xri
    }
    
    // Direct connection
    if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
        return ip
    }
    return r.RemoteAddr
}
```

## Integration with Security Ecosystem

### Event Publishing

The plugin publishes events that other security plugins can subscribe to:

```go
// Published events
type AbuseEvent struct {
    Type        string    // "rate_exceeded", "pattern_detected"
    ClientIP    string    // Source IP address
    Timestamp   time.Time // When violation occurred
    Requests    int       // Number of requests in window
    Threshold   int       // Configured threshold
    Window      duration  // Time window
    Severity    string    // "low", "medium", "high"
}
```

### Coordination with Advanced Plugins

The anti-abuse plugin is designed to work alongside more sophisticated security plugins:

#### With ML Abuse Detection
- Provides basic behavioral data for ML analysis
- Receives ML confidence scores to adjust thresholds
- Escalates to ML plugin for complex pattern analysis

#### With Zero Trust
- Feeds violation data into risk assessment
- Respects Zero Trust authentication requirements
- Contributes to overall trust scoring

#### With Rate Limiting Plugins
- Coordinates with geographic and threat intelligence plugins
- Shares violation data for comprehensive analysis
- Participates in coordinated blocking decisions

### Header Coordination

```http
# Anti-abuse provides foundation data
X-AntiAbuse-Requests: 12/10
X-AntiAbuse-Violations: 3

# ML plugin adds sophisticated analysis
X-ML-Anomaly-Score: 0.8
X-ML-Pattern: rapid_requests

# Zero Trust incorporates into risk assessment
X-ZTNA-Risk-Score: 0.6
X-ZTNA-Action: monitor
```

## Performance Characteristics

### Resource Usage
- **Memory**: ~1-5MB for typical workloads
- **CPU**: <1% overhead for most traffic patterns
- **Latency**: <1ms processing time per request
- **Storage**: In-memory only, no persistent storage required

### Scalability Considerations

#### Memory Management
```go
// Automatic cleanup prevents memory leaks
func (p *AntiAbusePlugin) cleanup() {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    now := time.Now()
    cutoff := now.Add(-p.window * 2) // Keep some history
    
    for ip, requests := range p.requestCounts {
        filtered := requests[:0]
        for _, req := range requests {
            if req.After(cutoff) {
                filtered = append(filtered, req)
            }
        }
        
        if len(filtered) == 0 {
            delete(p.requestCounts, ip)
        } else {
            p.requestCounts[ip] = filtered
        }
    }
}
```

#### Performance Optimization
- **Lock Optimization**: Minimizes lock contention for high-traffic scenarios
- **Memory Pooling**: Reuses slice allocations where possible
- **Batch Cleanup**: Periodic cleanup prevents memory bloat
- **Efficient Algorithms**: O(1) amortized operations for request tracking

## Error Handling and Responses

### Standard Rate Limit Response

When rate limits are exceeded:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: text/plain
X-AntiAbuse-Blocked: true
X-RateLimit-Ban: 30s
X-AntiAbuse-Reason: rate_exceeded
X-AntiAbuse-Retry-After: 30
Retry-After: 30

Rate limit exceeded: Too many requests
```

### Custom Error Responses

```toml
# Customizable error responses
[plugins.antiabuse-basic.responses]
rate_exceeded = "Too many requests. Please wait {retry_seconds} seconds."
pattern_detected = "Suspicious activity detected. Access temporarily restricted."
burst_detected = "Request burst detected. Please reduce request rate."
```

## Monitoring and Observability

### Metrics Collection

The plugin can export metrics in various formats:

```json
{
    "plugin": "antiabuse-basic",
    "version": "1.0.0",
    "timestamp": "2024-01-01T15:00:00Z",
    "metrics": {
        "total_requests": 125847,
        "blocked_requests": 1247,
        "block_rate": 0.0099,
        "unique_ips": 5672,
        "violations_per_hour": 89,
        "avg_requests_per_ip": 22.2,
        "top_violators": [
            {
                "ip": "203.0.113.45",
                "violations": 23,
                "last_violation": "2024-01-01T14:58:30Z"
            }
        ]
    }
}
```

### Logging

Structured logging provides detailed abuse tracking:

```json
{
    "timestamp": "2024-01-01T15:00:00Z",
    "level": "WARN",
    "plugin": "antiabuse-basic",
    "event": "rate_limit_exceeded",
    "client_ip": "192.168.1.100",
    "requests": 12,
    "threshold": 10,
    "window": "10s",
    "action": "blocked",
    "user_agent": "Mozilla/5.0...",
    "path": "/pks/add"
}
```

## Best Practices

### Configuration Guidelines

1. **Start Conservative**: Begin with higher thresholds and adjust downward
2. **Monitor False Positives**: Track legitimate users being blocked
3. **Adjust for Traffic Patterns**: Different thresholds for different endpoints
4. **Consider User Experience**: Balance security with usability

### Operational Recommendations

1. **Regular Monitoring**: Monitor metrics and logs for abuse patterns
2. **Threshold Tuning**: Regularly review and adjust rate limit thresholds
3. **Integration Planning**: Plan integration with other security plugins
4. **Incident Response**: Establish procedures for handling abuse incidents

### Security Considerations

1. **IP Spoofing**: Consider proxy and CDN scenarios in IP extraction
2. **Bypass Attempts**: Monitor for attempts to circumvent rate limiting
3. **Resource Exhaustion**: Prevent the plugin itself from becoming a DoS vector
4. **Privacy**: Ensure IP logging complies with privacy regulations

## Troubleshooting

### Common Issues

#### High False Positive Rate
**Symptoms:**
- Legitimate users being blocked frequently
- User complaints about access issues
- High block rate in metrics

**Solutions:**
- Increase `requestThreshold` 
- Extend `windowSeconds` for longer averaging
- Enable `burstTolerance` for brief spikes
- Review proxy configuration for IP extraction accuracy

#### Memory Usage Growing
**Symptoms:**
- Increasing memory consumption over time
- Slow response times
- Plugin consuming excessive resources

**Solutions:**
- Reduce `autoCleanupInterval` for more frequent cleanup
- Verify cleanup logic is working correctly
- Monitor for IP address churn
- Consider implementing LRU cache with size limits

#### Ineffective Abuse Prevention
**Symptoms:**
- Known abusers not being blocked
- Continued abuse despite plugin activation
- Low block rate with obvious abuse

**Solutions:**
- Decrease `requestThreshold` for stricter limits
- Reduce `windowSeconds` for faster detection
- Enable `strictMode` for more aggressive detection
- Coordinate with advanced security plugins

### Debug Mode

Enable detailed debugging:

```toml
[plugins.antiabuse-basic]
verboseLogging = true
debugMode = true
logAllRequests = true  # Warning: High volume
```

This provides detailed request tracking and decision logging.

## Advanced Features

### Adaptive Thresholds

When enabled, the plugin can automatically adjust thresholds based on traffic patterns:

```toml
[plugins.antiabuse-basic]
adaptiveThresholds = true
adaptationPeriod = "1h"
maxThresholdIncrease = 2.0
minThresholdDecrease = 0.5
trafficPatternWindow = "24h"
```

### Whitelist Support

Integration with whitelist systems:

```toml
[plugins.antiabuse-basic.whitelist]
enabled = true
staticIPs = ["192.168.1.0/24", "10.0.0.0/8"]
dynamicWhitelist = true
whitelistTTL = "24h"
```

### Escalation Support

Progressive ban durations for repeat offenders:

```toml
[plugins.antiabuse-basic.escalation]
enabled = true
firstViolation = "30s"
secondViolation = "5m"
thirdViolation = "30m"
persistentOffender = "24h"
escalationWindow = "1h"
```

## API Extensions

The plugin can expose additional endpoints for management:

### Status Endpoint ❌ **Not Implemented - Planned Feature**

```http
GET /antiabuse/status

{
    "enabled": true,
    "threshold": 10,
    "window": "10s",
    "active_ips": 1234,
    "violations_last_hour": 89,
    "memory_usage": "4.2MB"
}
```

### Configuration Endpoint ❌ **Not Implemented - Planned Feature**

```http
POST /antiabuse/config
{
    "requestThreshold": 15,
    "windowSeconds": 15
}
```

## Version History

- **v1.0.0**: Initial release with core anti-abuse features
  - Sliding window rate limiting
  - Basic behavioral monitoring
  - Client IP extraction with proxy support
  - Integration-ready event publishing
  - Memory-efficient request tracking
  - Configurable thresholds and responses
  - Comprehensive logging and metrics

## Migration and Upgrade

### From Basic Rate Limiting

If migrating from a simpler rate limiting solution:

1. **Analyze Current Patterns**: Review existing rate limit violations
2. **Match Thresholds**: Set initial thresholds to match current behavior
3. **Gradual Rollout**: Deploy in monitoring mode first
4. **Fine-tune**: Adjust based on observed traffic patterns

### Integration Path

Recommended integration with other security plugins:

1. **Phase 1**: Deploy Anti-Abuse plugin alone
2. **Phase 2**: Add Threat Intelligence plugin
3. **Phase 3**: Add Geographic Analysis
4. **Phase 4**: Add ML Abuse Detection
5. **Phase 5**: Complete with Zero Trust integration

This plugin provides the foundation for a comprehensive security ecosystem while being fully functional as a standalone solution.