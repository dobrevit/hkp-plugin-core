# Plugin Communication Architecture

## Overview

The HKP Plugin System uses a **hybrid communication approach** that combines event-driven inter-plugin communication with HTTP headers for external monitoring and debugging.

## Communication Methods

### 1. Event Bus (Primary - Inter-Plugin Communication)

Plugins primarily communicate with each other through a publish-subscribe event system. This is the **main method** for plugin coordination.

#### How It Works

```go
// Publishing an event
p.host.PublishEvent(plugin.PluginEvent{
    Type:      "ml.abuse.detected",
    Source:    p.Name(),
    Timestamp: time.Now(),
    Data: map[string]interface{}{
        "client_ip":     clientIP,
        "anomaly_score": 0.95,
        "reasons":       []string{"bot_pattern", "rapid_requests"},
    },
})

// Subscribing to events
host.SubscribeEvent("ml.abuse.detected", p.handleAbuseEvent)
```

#### Common Event Types

| Event Type | Publisher | Subscribers | Purpose |
|------------|-----------|-------------|---------|
| `ml.abuse.detected` | ML Abuse | Zero Trust, Tarpit | ML detects abuse pattern |
| `ratelimit.violation` | Anti-Abuse | ML, Zero Trust | Rate limit exceeded |
| `security.threat.detected` | Threat Intel | All plugins | Known threat identified |
| `geo.impossible_travel` | Geographic | Zero Trust, ML | Location anomaly |
| `ztna.risk.high` | Zero Trust | Tarpit, ML | High risk session |

### 2. HTTP Headers (Secondary - External Monitoring & Debugging)

HTTP headers are added to responses for **debugging, SIEM integration, and monitoring** - NOT for inter-plugin communication.

#### Purpose of Headers

1. **SIEM Integration**: Security Information and Event Management tools can read headers
2. **Debugging**: Developers can see plugin decisions in HTTP responses
3. **Monitoring**: Load balancers and monitoring tools can make routing decisions
4. **Audit Trail**: Headers provide a record of security decisions

#### Header Categories

##### Always Present (Debugging Headers)
These headers are added to EVERY request for debugging:

```http
# Anti-Abuse Plugin
X-AntiAbuse-Plugin: antiabuse-basic/1.0.0
X-AntiAbuse-Requests: 5/10
X-AntiAbuse-Window: 10s
X-AntiAbuse-ClientIP: 192.168.1.100
X-AntiAbuse-Blocked: false

# ML Abuse Plugin
X-ML-Plugin: ml-abuse-detector/1.0.0
X-ML-Enabled: true
X-ML-Threshold: 0.850
X-ML-Anomaly-Score: 0.234
X-ML-Anomaly-Type: normal
X-ML-Confidence: 0.890
```

##### Conditional Headers
These headers appear only when specific conditions are met:

```http
# When blocking occurs
X-AntiAbuse-Blocked: true
X-AntiAbuse-Reason: rate_exceeded
X-RateLimit-Ban: 30s

# When ML detects issues
X-ML-LLM-Detected: true
X-ML-Synthetic-Score: 0.812

# When Zero Trust is active (if enabled)
X-ZTNA-Session-ID: sess_abc123
X-ZTNA-Trust-Level: medium
X-ZTNA-Risk-Score: 0.456
```

## Architecture Comparison

### ❌ What Documentation Previously Suggested (Not Implemented)
```
Plugin A → Headers → Plugin B reads headers → Makes decision
```

### ✅ How It Actually Works
```
Plugin A → Event Bus → Plugin B receives event → Makes decision
         ↘ Headers → External Systems (SIEM, Monitoring, Debugging)
```

## Implementation Examples

### Example 1: ML Abuse Detection Flow

```go
// 1. ML Plugin detects abuse
anomalyScore := p.detector.DetectAnomaly(profile)

// 2. Add headers for external systems
w.Header().Set("X-ML-Anomaly-Score", fmt.Sprintf("%.3f", anomalyScore.Score))
w.Header().Set("X-ML-Anomaly-Type", anomalyScore.AnomalyType)

// 3. Communicate with other plugins via events
if anomalyScore.Score > threshold {
    p.host.PublishEvent(plugin.PluginEvent{
        Type: "ml.abuse.detected",
        Data: map[string]interface{}{
            "client_ip": clientIP,
            "score": anomalyScore.Score,
        },
    })
}
```

### Example 2: Zero Trust Receiving Events

```go
// Zero Trust subscribes to ML events
func (p *ZeroTrustPlugin) Initialize(...) {
    host.SubscribeEvent("ml.abuse.detected", p.handleMLEvent)
}

// Handle ML abuse detection
func (p *ZeroTrustPlugin) handleMLEvent(event plugin.PluginEvent) error {
    data := event.Data
    clientIP := data["client_ip"].(string)
    score := data["score"].(float64)
    
    // Adjust risk score based on ML detection
    p.updateRiskScore(clientIP, score)
    return nil
}
```

## Benefits of This Architecture

### Event Bus Benefits
- **Loose Coupling**: Plugins don't need to know about each other's headers
- **Reliability**: Events are queued and guaranteed delivery
- **Performance**: Asynchronous processing doesn't block requests
- **Flexibility**: Easy to add new event types and subscribers

### Header Benefits
- **Visibility**: Security teams can see decisions in HTTP logs
- **Integration**: Works with existing SIEM/monitoring tools
- **Debugging**: Developers can trace plugin behavior
- **Standards**: Uses standard HTTP header mechanisms

## Configuration for Headers

### Enabling Debug Headers

Debug headers are now always enabled for the Anti-Abuse and ML plugins. For other plugins:

```toml
# Zero Trust Plugin
[plugins.zero-trust-security]
enabled = true  # Must be true to see headers
includeDebugHeaders = true  # Optional: adds more verbose headers

# Threat Intelligence
[plugins.ratelimit-threat-intel]
enabled = true
debugHeaders = true  # Adds detailed threat info
```

## Monitoring Integration

### SIEM Rules Example

```yaml
# Splunk search for high-risk sessions
index=web_logs 
| where "X-ML-Anomaly-Score" > 0.8 OR "X-ZTNA-Risk-Score" > 0.7
| stats count by src_ip, "X-ML-Anomaly-Type"

# Alert on coordinated attacks
index=web_logs "X-ML-Anomaly-Type"="coordinated_attack"
| alert
```

### Prometheus Metrics

```yaml
# Expose header data as metrics
hkp_ml_anomaly_score{client_ip="..."} 0.234
hkp_antiabuse_requests{client_ip="..."} 5
hkp_ztna_risk_score{session_id="..."} 0.456
```

## Testing Headers

### 1. Basic Request (Should Show Headers)
```bash
curl -v http://localhost:8080/pks/lookup

# Expected headers:
# X-AntiAbuse-Plugin: antiabuse-basic/1.0.0
# X-AntiAbuse-Requests: 1/10
# X-ML-Plugin: ml-abuse-detector/1.0.0
# X-ML-Anomaly-Score: 0.100
```

### 2. Trigger Rate Limit
```bash
# Make 11 requests quickly
for i in {1..11}; do curl http://localhost:8080/pks/add; done

# Last request should show:
# X-AntiAbuse-Blocked: true
# X-AntiAbuse-Reason: rate_exceeded
# HTTP 429 Too Many Requests
```

## Future Enhancements

### Planned Header Additions
- `X-Geo-Country`: Geographic location (not yet implemented)
- `X-Geo-Risk-Score`: Location-based risk (not yet implemented)
- `X-Threat-Sources`: Threat intelligence sources (not yet implemented)
- `X-Tarpit-Active`: Tarpit status (not yet implemented)

### Header Standardization
Future versions will implement a standard header format:
```
X-HKP-{Plugin}-{Metric}: value
X-HKP-ML-Score: 0.234
X-HKP-GEO-Country: US
```

## Summary

- **Events**: Primary method for plugin communication (implemented and working)
- **Headers**: Secondary method for external monitoring and debugging (partially implemented)
- **Both are important**: Events for reliability, Headers for visibility
- **Not competing**: They serve different purposes in the architecture

This hybrid approach provides the best of both worlds: reliable inter-plugin communication through events, and excellent observability through HTTP headers.