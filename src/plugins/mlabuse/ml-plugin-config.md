# ML Abuse Detection Plugin for Hockeypuck

## Overview

The ML Abuse Detection Plugin provides advanced machine learning-based abuse detection capabilities for Hockeypuck, including:

- **Behavioral Anomaly Detection**: Uses Isolation Forest algorithm to detect abnormal request patterns
- **LLM/AI Content Detection**: Identifies AI-generated content and prompt injection attempts
- **Real-time Learning**: Adapts to new attack patterns through online learning
- **Integration with Rate Limiting**: Coordinates with the existing rate limiting system for comprehensive protection

## Features

### 1. Behavioral Analysis
- Request timing pattern analysis
- Entropy-based bot detection
- User agent rotation tracking
- Session behavior profiling
- Path sequence analysis

### 2. Anomaly Detection
- Isolation Forest algorithm for outlier detection
- Multiple anomaly types: bots, crawlers, rapid requests, high error rates
- Confidence scoring for detection accuracy
- Adaptive thresholds based on behavior patterns

### 3. LLM/AI Detection
- Perplexity analysis for synthetic text detection
- Token pattern recognition for AI-generated content
- Prompt injection detection
- Base64 and encoded content analysis

### 4. Metrics and Monitoring
- Real-time metrics collection
- Hourly statistics aggregation
- Detection rate tracking
- Performance monitoring

## Configuration

Add the ML abuse detection plugin to your Hockeypuck configuration:

```toml
# Enable plugin system
[plugins]
enabled = true
directory = "/etc/hockeypuck/plugins"
loadOrder = ["ml-abuse-detector"]

# ML Abuse Detection Plugin Configuration
[plugins.ml-abuse-detector]
enabled = true
type = "middleware"

# Model configuration
config.modelPath = "/var/lib/hockeypuck/ml-models/anomaly-detector.model"
config.anomalyThreshold = 0.85  # Score above this triggers blocking (0.0-1.0)

# Behavior analysis settings
config.behaviorWindowSize = 100  # Number of requests to analyze
config.updateInterval = "5m"     # Model update frequency

# LLM detection settings
config.llmDetection = true
config.syntheticThreshold = 0.75  # Threshold for AI-generated content

# Resource limits
config.maxMemoryMB = 256
config.enableRealtimeUpdate = true  # Enable online learning
```

## Installation

1. **Build the plugin**:
```bash
go build -buildmode=plugin -o ml-abuse-detector.so ./plugins/mlabuse
```

2. **Install the plugin**:
```bash
sudo cp ml-abuse-detector.so /etc/hockeypuck/plugins/
sudo chown hockeypuck:hockeypuck /etc/hockeypuck/plugins/ml-abuse-detector.so
```

3. **Create model directory**:
```bash
sudo mkdir -p /var/lib/hockeypuck/ml-models
sudo chown hockeypuck:hockeypuck /var/lib/hockeypuck/ml-models
```

4. **Update configuration** and restart Hockeypuck:
```bash
sudo systemctl restart hockeypuck
```

## Detection Capabilities

### Anomaly Types

| Type | Description | Indicators |
|------|-------------|------------|
| `bot_regular` | Too-regular timing patterns | Timing entropy < 0.2 |
| `bot_random` | Artificially random patterns | Timing entropy > 0.9 |
| `rapid_requests` | Inhuman request speed | Average interval < 0.5s |
| `user_agent_rotation` | Suspicious UA switching | >3 different user agents |
| `crawler` | Aggressive crawling behavior | >50 unique paths |
| `high_errors` | Excessive error generation | Error rate > 30% |
| `general_anomaly` | Other abnormal patterns | High anomaly score |

### LLM Detection Patterns

The plugin detects:
- AI-specific phrases and sentence structures
- Repetitive formal language patterns
- Low perplexity text (too predictable)
- Prompt injection attempts
- Encoded or obfuscated content

## Response Headers

The plugin adds intelligence headers for downstream systems:

```http
X-ML-Anomaly-Score: 0.923
X-ML-Anomaly-Type: bot_regular
X-ML-LLM-Detected: true
X-ML-Synthetic-Score: 0.812
```

## Metrics Endpoint

Access ML detection metrics at `/metrics/ml-abuse`:

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

## Integration with Rate Limiting

The plugin integrates seamlessly with Hockeypuck's rate limiting system:

1. **Event Subscription**: Listens to rate limit violations for pattern learning
2. **Escalation**: Can trigger extended bans for persistent abusers
3. **Shared Intelligence**: Provides ML scores to rate limiter for informed decisions

## Performance Considerations

- **Memory Usage**: ~50-100MB for model and behavior profiles
- **CPU Impact**: <5% overhead for typical traffic
- **Latency**: <10ms added per request
- **Model Updates**: Background process, doesn't block requests

## Troubleshooting

### High False Positive Rate
- Reduce `anomalyThreshold` (e.g., 0.9 instead of 0.85)
- Increase `behaviorWindowSize` for more data points
- Check if legitimate automated tools are being blocked

### Model Not Loading
- Verify model file permissions
- Check model path in configuration
- Review logs for initialization errors

### Memory Usage
- Reduce `behaviorWindowSize` if memory constrained
- Disable `enableRealtimeUpdate` to prevent model growth
- Configure cleanup intervals

## Advanced Configuration

### Custom Anomaly Thresholds

```toml
[plugins.ml-abuse-detector.config.thresholds]
bot_regular = 0.8
bot_random = 0.85
rapid_requests = 0.75
crawler = 0.9
user_agent_rotation = 0.85
high_errors = 0.7
```

### Model Training Settings

```toml
[plugins.ml-abuse-detector.config.training]
minDataPoints = 10        # Minimum data for model updates
updateBatchSize = 100     # Samples per update batch
retrainPercentage = 0.1   # Percentage of trees to update
normalDataRatio = 0.5     # Ratio of synthetic normal data
```

### LLM Detection Tuning

```toml
[plugins.ml-abuse-detector.config.llm]
perplexityWeight = 0.4
patternWeight = 0.4
countWeight = 0.2
minTextLength = 50        # Minimum text length to analyze
maxTextLength = 1048576   # Maximum text length (1MB)
```

## Security Best Practices

1. **Protect Model Files**: Ensure model files are not world-readable
2. **Monitor Metrics**: Set up alerts for sudden changes in block rates
3. **Regular Updates**: Keep the plugin updated for new detection patterns
4. **Coordinate with Rate Limiting**: Use both systems together for defense in depth
5. **Review Logs**: Regularly review blocked requests for false positives

## Future Enhancements

- Deep learning models for advanced pattern recognition
- Distributed learning across multiple Hockeypuck instances
- Custom training interfaces for site-specific patterns
- Integration with threat intelligence feeds
- Real-time visualization dashboards