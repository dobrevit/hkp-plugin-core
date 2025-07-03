# ML Abuse Detection Plugin

## Overview

The ML Abuse Detection Plugin provides advanced machine learning-based abuse detection capabilities for the HKP (Hockeypuck) server. This plugin uses sophisticated behavioral analysis, anomaly detection algorithms, and AI-generated content detection to identify and prevent various forms of abuse including bot attacks, automated scripts, AI-generated content, and prompt injection attempts.

## Key Features

### Advanced Detection Capabilities
- **Behavioral Anomaly Detection**: Uses Isolation Forest algorithm to detect abnormal request patterns
- **LLM/AI Content Detection**: Identifies AI-generated content and prompt injection attempts  
- **Real-time Learning**: Adapts to new attack patterns through online learning
- **Entropy Analysis**: Measures randomness in user behavior patterns
- **Session Profiling**: Tracks comprehensive session-level behavioral metrics

### Machine Learning Models
- **Isolation Forest Algorithm**: Detects outliers in multi-dimensional behavioral space
- **Perplexity Analysis**: Identifies synthetic text based on language model predictions
- **Pattern Recognition**: Recognizes known attack signatures and behavioral patterns
- **Adaptive Thresholds**: Self-adjusting detection thresholds based on traffic patterns

### Intelligence Coordination
- **Event Integration**: Coordinates with rate limiting and other security plugins
- **Header Intelligence**: Adds ML scores to HTTP headers for downstream processing
- **Escalation Logic**: Can trigger extended bans for persistent abusers
- **Real-time Metrics**: Comprehensive statistics and performance monitoring

## Configuration

### Basic Configuration

```toml
[plugins.ml-abuse-detector]
enabled = true
modelPath = "/var/lib/hockeypuck/ml-models/anomaly.model"
anomalyThreshold = 0.85
behaviorWindowSize = 100
updateInterval = "5m"
llmDetection = true
syntheticThreshold = 0.75
maxMemoryMB = 256
enableRealtimeUpdate = true
```

### Advanced Configuration

```toml
[plugins.ml-abuse-detector]
enabled = true
modelPath = "/var/lib/hockeypuck/ml-models/anomaly.model"
anomalyThreshold = 0.85
behaviorWindowSize = 100
updateInterval = "5m"
llmDetection = true
syntheticThreshold = 0.75
maxMemoryMB = 256
enableRealtimeUpdate = true

# Custom anomaly type thresholds
[plugins.ml-abuse-detector.thresholds]
bot_regular = 0.8
bot_random = 0.85
rapid_requests = 0.75
crawler = 0.9
user_agent_rotation = 0.85
high_errors = 0.7

# Model training settings
[plugins.ml-abuse-detector.training]
minDataPoints = 10
updateBatchSize = 100
retrainPercentage = 0.1
normalDataRatio = 0.5

# LLM detection tuning
[plugins.ml-abuse-detector.llm]
perplexityWeight = 0.4
patternWeight = 0.4
countWeight = 0.2
minTextLength = 50
maxTextLength = 1048576
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable the plugin |
| `modelPath` | string | `""` | Path to the ML model file |
| `anomalyThreshold` | float | `0.85` | Score above this triggers blocking (0.0-1.0) |
| `behaviorWindowSize` | int | `100` | Number of requests to analyze for behavior |
| `updateInterval` | string | `"5m"` | How often to update ML models |
| `llmDetection` | boolean | `true` | Enable AI/LLM content detection |
| `syntheticThreshold` | float | `0.75` | Threshold for AI-generated content |
| `maxMemoryMB` | int | `256` | Maximum memory usage in MB |
| `enableRealtimeUpdate` | boolean | `true` | Enable online learning and model updates |

## API Endpoints

> **Implementation Status**: ✅ All ML Abuse Detection endpoints listed below are currently implemented in the codebase.

### Status and Monitoring

#### GET `/api/ml/status`
Get ML abuse detection system status.

**Response:**
```json
{
    "plugin": "ml-abuse-detector",
    "version": "1.0.0",
    "enabled": true,
    "threshold": 0.85,
    "llm_detection": true,
    "metrics": {
        "total_requests": 145823,
        "blocked_requests": 1247,
        "block_rate": 0.00855,
        "avg_anomaly_score": 0.324
    }
}
```

#### GET `/api/ml/metrics`
Get comprehensive ML detection metrics.

**Response:**
```json
{
    "total_requests": 145823,
    "blocked_requests": 1247,
    "block_rate": 0.00855,
    "anomaly_detections": {
        "bot_regular": 423,
        "rapid_requests": 312,
        "crawler": 189,
        "user_agent_rotation": 156,
        "high_errors": 98,
        "general_anomaly": 69
    },
    "llm_detections": 234,
    "injection_attempts": 45,
    "avg_anomaly_score": 0.324,
    "avg_synthetic_score": 0.287,
    "hourly_stats": [
        {
            "hour": 14,
            "requests": 8234,
            "blocked": 67,
            "anomalies_detected": 45,
            "llm_detected": 12,
            "avg_anomaly_score": 0.342
        }
    ],
    "uptime": "6h23m45s"
}
```

#### POST `/api/ml/analyze`
Analyze specific client or content for abuse patterns.

**Request:**
```json
{
    "client_ip": "192.168.1.100",
    "text": "Optional text content to analyze for AI generation"
}
```

**Response:**
```json
{
    "client_ip": "192.168.1.100",
    "anomaly_score": 0.923,
    "anomaly_type": "bot_regular",
    "reasons": [
        "Timing patterns too regular",
        "Low entropy in request intervals",
        "Suspicious user agent rotation"
    ],
    "confidence": 0.89,
    "llm_analysis": {
        "is_ai_generated": true,
        "perplexity": 2.34,
        "synthetic_score": 0.812,
        "prompt_injection": false,
        "token_patterns": ["formal_language", "repetitive_structure"]
    }
}
```

## Detection Capabilities

### Anomaly Types

| Type | Description | Detection Indicators |
|------|-------------|---------------------|
| `bot_regular` | Too-regular timing patterns | Timing entropy < 0.2, consistent intervals |
| `bot_random` | Artificially random patterns | Timing entropy > 0.9, suspicious randomness |
| `rapid_requests` | Inhuman request speed | Average interval < 0.5s, burst patterns |
| `user_agent_rotation` | Suspicious UA switching | >3 different user agents in session |
| `crawler` | Aggressive crawling behavior | >50 unique paths, systematic access |
| `high_errors` | Excessive error generation | Error rate > 30%, repeated failures |
| `general_anomaly` | Other abnormal patterns | High overall anomaly score |

### Behavioral Analysis Metrics

#### Session Pattern Analysis
- **Session Duration**: Total time of user session
- **Request Count**: Number of requests in session
- **Unique Paths**: Number of distinct endpoints accessed
- **Error Rate**: Percentage of requests resulting in errors
- **Bytes Transferred**: Total data transfer volume
- **Key Operation Ratio**: Ratio of key operations to total requests

#### Entropy Metrics
- **Timing Entropy**: Randomness in request timing patterns
- **Path Entropy**: Randomness in path access patterns
- **Parameter Entropy**: Randomness in request parameters
- **Overall Score**: Composite entropy assessment

### LLM/AI Detection

#### Detection Patterns
The plugin identifies AI-generated content through:
- **Perplexity Analysis**: Low perplexity indicates overly predictable text
- **Token Patterns**: Specific phrases and structures common in AI text
- **Formal Language**: Excessive use of formal or academic language
- **Repetitive Structure**: Consistent sentence and paragraph patterns
- **Prompt Injection**: Attempts to manipulate AI systems

#### AI Content Indicators
- Unnaturally perfect grammar and syntax
- Overuse of transitional phrases
- Lack of personal anecdotes or informal language
- Consistent tone without emotional variation
- Technical accuracy combined with generic explanations

## Response Headers

The plugin adds intelligence headers for coordination with other security plugins:

```http
X-ML-Anomaly-Score: 0.923
X-ML-Anomaly-Type: bot_regular
X-ML-LLM-Detected: true
X-ML-Synthetic-Score: 0.812
```

## Integration with Other Plugins

### Rate Limiting Integration
- **Event Subscription**: Listens to `ratelimit.violation` events
- **Profile Updates**: Uses violation data to improve behavioral profiles
- **Escalation**: Can trigger extended bans for persistent abusers
- **Shared Intelligence**: Provides ML scores for informed rate limiting decisions

### Zero Trust Integration
- **Risk Assessment**: ML scores contribute to Zero Trust risk calculations
- **Behavioral Analytics**: Shared behavior data improves trust scoring
- **Authentication Triggers**: High anomaly scores can trigger step-up authentication

### Event System Integration

#### Published Events
- `ml.abuse.detected`: When abuse is detected and blocked
- `ml.abuse.escalate`: When extended ban is recommended

#### Subscribed Events
- `ratelimit.violation`: Rate limiting violations for profile updates

## Performance Considerations

### Resource Usage
- **Memory Usage**: 50-100MB for models and behavior profiles
- **CPU Impact**: <5% overhead for typical traffic loads
- **Latency**: <10ms processing time per request
- **Model Updates**: Background process, doesn't block requests
- **Disk Usage**: Model files typically 10-50MB

### Scaling Recommendations

#### Small Deployments (<1000 req/min)
- Default configuration suitable
- 2-4 CPU cores recommended
- 4GB RAM minimum

#### Medium Deployments (1000-10000 req/min)
- Consider Redis backend for shared profiles
- 4-8 CPU cores recommended
- 8-16GB RAM for model caching

#### Large Deployments (>10000 req/min)
- Distribute ML processing across instances
- Dedicated ML inference servers
- 8+ CPU cores, 16-32GB RAM per instance

## Best Practices

### Configuration Tuning
1. **Start Conservative**: Begin with higher thresholds (0.9+) and lower gradually
2. **Monitor False Positives**: Track legitimate traffic patterns
3. **Adjust by Traffic Type**: Different thresholds for different endpoint types
4. **Regular Model Updates**: Keep models current with traffic patterns

### Operational Guidelines
1. **Gradual Rollout**: Enable monitoring before enforcement
2. **Baseline Establishment**: Allow learning period before strict enforcement
3. **Regular Review**: Periodically review blocked requests for accuracy
4. **Performance Monitoring**: Track resource usage and processing times

### Security Configuration
1. **Model Protection**: Secure model files with appropriate permissions
2. **Log Analysis**: Regular review of detection patterns and effectiveness
3. **Threshold Adjustment**: Adapt thresholds based on threat landscape
4. **Backup Strategy**: Regular backups of trained models and configurations

## Troubleshooting

### High False Positive Rate
**Symptoms:**
- Legitimate users being blocked
- High block rate in metrics
- User complaints about access issues

**Solutions:**
- Increase `anomalyThreshold` (e.g., from 0.85 to 0.9)
- Increase `behaviorWindowSize` for more data points
- Review whitelist paths for legitimate automation
- Check if CDN or proxy is affecting behavioral analysis

### Model Performance Issues
**Symptoms:**
- High CPU usage
- Slow response times
- Memory leaks

**Solutions:**
- Reduce `behaviorWindowSize` if memory constrained
- Disable `enableRealtimeUpdate` to prevent model growth
- Increase `updateInterval` to reduce update frequency
- Monitor cleanup intervals and adjust as needed

### Detection Accuracy Problems
**Symptoms:**
- Missing obvious bot traffic
- Inconsistent detection results
- Poor LLM detection accuracy

**Solutions:**
- Lower detection thresholds gradually
- Increase training data through longer observation periods
- Verify model file integrity and version
- Check for sufficient diverse training data

### Integration Issues
**Symptoms:**
- Events not being received
- Headers not appearing
- Plugin conflicts

**Solutions:**
- Verify plugin load order (ML should load after rate limiting)
- Check event subscription setup
- Review middleware registration
- Monitor plugin communication logs

## Monitoring and Alerting

### Key Metrics to Monitor
1. **Detection Rates**: Block rate, false positive rate
2. **Performance**: Processing latency, memory usage
3. **Model Health**: Accuracy metrics, update success rate
4. **System Load**: CPU usage, goroutine counts

### Recommended Alerts
```yaml
alerts:
  - name: high_ml_block_rate
    condition: ml_block_rate > 0.1
    severity: warning
    
  - name: ml_processing_latency
    condition: ml_avg_latency > 50ms
    severity: warning
    
  - name: ml_memory_usage
    condition: ml_memory_mb > 400
    severity: critical
    
  - name: ml_model_update_failure
    condition: ml_update_failures > 3
    severity: critical
```

## Security Considerations

### Threat Model
The plugin addresses:
- **Automated Bot Attacks**: Detection through behavioral analysis
- **AI-Generated Spam**: LLM detection capabilities
- **Prompt Injection**: Specific detection for AI manipulation attempts
- **Coordinated Attacks**: Pattern recognition across multiple clients
- **Evasion Attempts**: Adaptive learning to counter sophisticated attackers

### Privacy Considerations
- **Data Minimization**: Only essential behavioral metrics are stored
- **Anonymization**: Client profiles use hashed identifiers where possible
- **Retention Limits**: Automatic cleanup of old behavioral data
- **GDPR Compliance**: Support for data deletion requests

## Version History

- **v1.0.0**: Initial release with core ML abuse detection features
  - Isolation Forest anomaly detection
  - Basic LLM content detection
  - Event-driven integration with rate limiting
  - Real-time learning capabilities
  - Tomb.Tomb integration for reliable goroutine management
  - Comprehensive metrics and monitoring