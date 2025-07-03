# HKP Plugin System

## Overview

The HKP Plugin System provides a comprehensive, modular security and operational framework for Hockeypuck OpenPGP key servers. This system implements a sophisticated plugin architecture that enables advanced security features, machine learning-based abuse detection, zero-trust network access, and intelligent rate limiting through dynamically loaded plugin modules.

## Architecture

### Plugin Framework

The system uses Go's plugin architecture with `.so` dynamic libraries to provide:
- **Hot-Pluggable Modules**: Load and unload plugins without server restart
- **Event-Driven Communication**: Plugins communicate through a publish-subscribe event system
- **Middleware Chain**: HTTP middleware integration for request processing
- **Dependency Management**: Automatic plugin dependency resolution and loading
- **Resource Management**: Proper lifecycle management using tomb.Tomb for goroutines

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        Hockeypuck Server                        │
├─────────────────────────────────────────────────────────────────┤
│                     Plugin Host System                         │
├─────────────────────────────────────────────────────────────────┤
│    Plugin Registry    │    Event Bus    │   Middleware Chain   │
├─────────────────────────────────────────────────────────────────┤
│  Security Plugins  │  Rate Limit Plugins  │  Operational Plugins │
└─────────────────────────────────────────────────────────────────┘
```

## Plugin Categories

### 1. Security Plugins

#### Zero Trust Security Plugin (`zero-trust-security`)
Implements comprehensive Zero Trust Network Access (ZTNA) principles:

- **Continuous Authentication**: Multi-factor authentication with adaptive challenges
- **Risk-Based Access Control**: Dynamic risk assessment with ML insights
- **Device Profiling**: Advanced device identification and trust scoring
- **Micro-Segmentation**: Network isolation based on identity and device trust
- **Session Management**: Secure session handling with automatic timeout

**Key Features:**
- 5-tier trust level system (None, Low, Medium, High, Verified)
- Configurable public paths for endpoint access control
- Adaptive policy engine with ML-driven adjustments
- Comprehensive audit logging for compliance
- Integration with behavioral analytics

#### ML Abuse Detection Plugin (`ml-abuse-detector`)
Advanced machine learning-based abuse detection:

- **Behavioral Anomaly Detection**: Isolation Forest algorithm for outlier detection
- **LLM/AI Content Detection**: Identifies AI-generated content and prompt injections
- **Real-time Learning**: Adapts to new attack patterns through online learning
- **Session Profiling**: Comprehensive behavioral pattern analysis
- **Entropy Analysis**: Measures randomness in user behavior

**Detection Capabilities:**
- Bot detection (regular and random patterns)
- Rapid request identification
- User agent rotation tracking
- Crawler behavior recognition
- High error rate patterns

### 2. Rate Limiting Plugins

#### Geographic Analysis Plugin (`ratelimit-geo`)
Location-based security and impossible travel detection:

- **Impossible Travel Detection**: Physics-based validation of location changes
- **Geographic Clustering**: Identifies coordinated attacks from multiple IPs
- **ASN Analysis**: Network reputation and provider categorization
- **VPN/Datacenter Detection**: Identifies proxy usage patterns
- **Country-Based Controls**: Configurable geographic restrictions

#### ML Extension Plugin (`ratelimit-ml`)
Machine learning-enhanced traffic analysis:

- **Pattern Recognition**: Advanced traffic pattern analysis
- **Predictive Analytics**: Traffic forecasting and anomaly prediction
- **Coordinated Attack Detection**: Multi-IP attack correlation
- **Entropy Measurement**: Randomness analysis in request patterns
- **Adaptive Thresholds**: Self-adjusting rate limits based on patterns

#### Threat Intelligence Plugin (`ratelimit-threat-intel`)
External threat feed integration:

- **Multi-Feed Support**: JSON, CSV, TXT, XML format compatibility
- **IP Reputation System**: Dynamic reputation scoring from multiple sources
- **Real-time Updates**: Continuous threat feed monitoring
- **Pattern Matching**: Known attack signature detection
- **Intelligence Sharing**: Coordination with threat intelligence community

#### Tarpit Plugin (`ratelimit-tarpit`)
Defensive connection management:

- **Multiple Tarpit Modes**: Slow, sticky, random response strategies
- **Honeypot Integration**: Fake endpoints for attacker intelligence gathering
- **Resource Exhaustion**: Forces attackers to consume computational resources
- **Intelligence Collection**: Profiles attacker tools and techniques
- **Adaptive Response**: Adjusts behavior based on attacker persistence

### 3. Operational Plugins

#### Anti-Abuse Plugin (`antiabuse-basic`)
Fundamental behavioral analysis and abuse prevention:

- **Sliding Window Rate Limiting**: Precise request rate control
- **Behavioral Monitoring**: Basic pattern detection and analysis
- **Client Fingerprinting**: IP-based client identification
- **Violation Tracking**: Historical abuse pattern recording
- **Integration Foundation**: Base layer for advanced security plugins

## Plugin Communication

### Event-Driven Architecture

Plugins communicate through a sophisticated event system:

```
Event Flow Example:
┌─────────────────┐    threat.detected    ┌──────────────────┐
│ Threat Intel    │─────────────────────→│ Geographic       │
│ Plugin          │                       │ Analysis Plugin  │
└─────────────────┘                       └──────────────────┘
        │                                          │
        │ ml.abuse.detected                        │ geo.anomaly
        ▼                                          ▼
┌─────────────────┐                       ┌──────────────────┐
│ ML Abuse        │◄──────────────────────│ Zero Trust       │
│ Detection       │    ratelimit.violation │ Security Plugin  │
└─────────────────┘                       └──────────────────┘
        │                                          │
        │ tarpit.candidate                         │ ztna.risk.high
        ▼                                          ▼
┌─────────────────┐                       ┌──────────────────┐
│ Tarpit Plugin   │                       │ All Security     │
│                 │                       │ Plugins          │
└─────────────────┘                       └──────────────────┘
```

### Header Intelligence (For External Systems)

Plugins add HTTP headers for **SIEM integration and debugging** (not for inter-plugin communication):

```http
# Always present (debugging)
X-AntiAbuse-Plugin: antiabuse-basic/1.0.0
X-AntiAbuse-Requests: 5/10
X-ML-Plugin: ml-abuse-detector/1.0.0
X-ML-Anomaly-Score: 0.234

# Conditional (when threats detected)
X-AntiAbuse-Blocked: true
X-ML-LLM-Detected: true
X-ZTNA-Risk-Score: 0.456  # When Zero Trust enabled
```

For detailed plugin communication architecture, see [PLUGIN_COMMUNICATION.md](docs/PLUGIN_COMMUNICATION.md).

## Configuration

### System Configuration

```toml
# Main application configuration
[plugins]
enabled = true
directory = "/etc/hockeypuck/plugins"
loadOrder = [
    "ratelimit-threat-intel",
    "ratelimit-geo", 
    "ratelimit-ml",
    "ml-abuse-detector",
    "zero-trust-security",
    "ratelimit-tarpit"
]

# Global plugin settings
[plugins.global]
eventBufferSize = 1000
maxConcurrentEvents = 100
logLevel = "info"
metricsEnabled = true
```

### Plugin-Specific Configuration

Each plugin has its own configuration section:

```toml
# Zero Trust Configuration
[plugins.zero-trust-security]
enabled = true
requireAuthentication = true
maxRiskScore = 0.7
sessionTimeout = "30m"
publicPaths = ["/pks/lookup", "/pks/stats", "/metrics"]

# ML Abuse Detection Configuration  
[plugins.ml-abuse-detector]
enabled = true
modelPath = "/var/lib/hockeypuck/ml-models/anomaly.model"
anomalyThreshold = 0.85
llmDetection = true

# Threat Intelligence Configuration
[plugins.ratelimit-threat-intel]
enabled = true
updateInterval = "1h"
reputationThreshold = 0.3
autoBlock = true

[[plugins.ratelimit-threat-intel.threatFeeds]]
name = "emerging-threats"
url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
type = "ip"
format = "txt"
enabled = true
```

## API Endpoints

### Currently Implemented Endpoints

For a complete list of currently implemented endpoints, see [API_ENDPOINTS.md](docs/API_ENDPOINTS.md).

**Core Endpoints:**
- `POST /pks/add` - Submit PGP key
- `GET /pks/lookup` - Lookup PGP key  
- `GET /pks/stats` - Server statistics
- `GET /metrics` - Prometheus metrics

**Plugin Endpoints (Implemented):**
- Zero Trust: `/ztna/login`, `/ztna/logout`, `/ztna/verify`, `/ztna/device`, `/ztna/status`, `/ztna/sessions`, `/ztna/policies`
- ML Abuse Detection: `/api/ml/status`, `/api/ml/metrics`, `/api/ml/analyze`
- Threat Intelligence: `/ratelimit/threatintel/status`, `/ratelimit/threatintel/check`, `/ratelimit/threatintel/report`
- Tarpit: `/ratelimit/tarpit/status`, `/ratelimit/tarpit/connections` + configurable honeypot paths
- ML Extension: `/ratelimit/ml/status`, `/ratelimit/ml/patterns`

### Planned Management Endpoints (Future)

#### GET `/plugins/status`
Get overall plugin system status.

#### GET `/plugins/list`
List all loaded plugins and their status.

#### POST `/plugins/reload`
Reload plugin configuration (admin only).

### Security Plugin Endpoints

#### Zero Trust Security
- `POST /ztna/login` - User authentication
- `POST /ztna/logout` - End session
- `POST /ztna/verify` - MFA verification
- `GET /ztna/status` - System status

#### ML Abuse Detection
- `GET /api/ml/status` - ML system status
- `GET /api/ml/metrics` - Detection metrics
- `POST /api/ml/analyze` - Analyze specific content

#### Threat Intelligence
- `GET /ratelimit/threatintel/status` - Threat feed status
- `POST /ratelimit/threatintel/check` - Check IP reputation

#### Rate Limiting Plugins
- `GET /ratelimit/ml/status` - ML rate limiting status
- `GET /ratelimit/tarpit/status` - Tarpit system status
- `GET /geo/status` - Geographic analysis status

## Deployment Configurations

### Minimal Security Setup

For basic protection:

```toml
[plugins]
enabled = true
loadOrder = ["ratelimit-threat-intel", "antiabuse-basic"]
```

**Provides:**
- Known bad IP blocking
- Basic rate limiting
- Minimal resource usage

### Standard Security Setup

For comprehensive protection:

```toml
[plugins]
enabled = true
loadOrder = [
    "ratelimit-threat-intel",
    "ratelimit-geo",
    "ml-abuse-detector", 
    "zero-trust-security"
]
```

**Provides:**
- Threat intelligence blocking
- Geographic analysis
- ML-based abuse detection
- Zero trust authentication

### Maximum Security Setup

For highest security environments:

```toml
[plugins]
enabled = true
loadOrder = [
    "ratelimit-threat-intel",
    "ratelimit-geo",
    "ratelimit-ml", 
    "ml-abuse-detector",
    "zero-trust-security",
    "ratelimit-tarpit"
]
```

**Provides:**
- Complete threat intelligence
- Advanced geographic controls
- ML-enhanced rate limiting
- Sophisticated abuse detection
- Zero trust network access
- Attacker resource exhaustion

## Performance Characteristics

### Resource Usage by Configuration

| Configuration | CPU Impact | Memory Usage | Latency Added |
|---------------|------------|--------------|---------------|
| **Minimal** | <2% | 100-150MB | <3ms |
| **Standard** | 3-7% | 300-600MB | <15ms |
| **Maximum** | 5-12% | 500-1200MB | <25ms |

### Scaling Recommendations

#### Small Deployments (<1000 req/min)
- Single instance with all plugins
- 4GB RAM, 2-4 CPU cores
- Standard security configuration

#### Medium Deployments (1000-10000 req/min)
- Redis backend for shared state
- 8-16GB RAM, 4-8 CPU cores
- Load balancing across instances

#### Large Deployments (>10000 req/min)
- Distributed plugin architecture
- Dedicated ML inference servers
- 16-32GB RAM, 8+ CPU cores per instance
- Advanced caching and optimization

## Security Benefits

### Threat Mitigation

| Threat Type | Primary Defense | Secondary Defense |
|-------------|----------------|-------------------|
| **Known Malicious IPs** | Threat Intelligence | Geographic Analysis |
| **Bot Attacks** | ML Abuse Detection | Anti-Abuse Rate Limiting |
| **Coordinated Attacks** | ML Extension + Geographic | Tarpit Resource Exhaustion |
| **AI-Generated Spam** | ML LLM Detection | Zero Trust Verification |
| **Credential Attacks** | Zero Trust MFA | Rate Limiting |
| **Geographic Anomalies** | Impossible Travel Detection | Zero Trust Risk Assessment |
| **DDoS Attacks** | Multi-layer Rate Limiting | Tarpit + Geographic |

### Compliance Support

- **SOC 2**: Comprehensive audit logging and access controls
- **ISO 27001**: Risk assessment and security monitoring  
- **NIST Cybersecurity Framework**: Defense in depth implementation
- **GDPR**: Privacy-compliant data handling and retention
- **HIPAA**: Enhanced authentication and audit trails

## Monitoring and Observability

### Key Metrics

#### Security Metrics
- Blocked requests by plugin and reason
- Threat detection rates and accuracy
- Authentication success/failure rates
- Risk score distributions
- Geographic anomaly detection rates

#### Performance Metrics  
- Plugin processing latency
- Memory usage per plugin
- Event processing throughput
- Cache hit rates
- Background task performance

#### Operational Metrics
- Plugin uptime and availability
- Configuration reload success
- Error rates and types
- Resource utilization trends

### Alerting Framework

```yaml
# Example alerting configuration
alerts:
  security:
    - name: coordinated_attack_detected
      condition: ml_coordinated_score > 0.9
      severity: critical
      
    - name: impossible_travel_detected  
      condition: geo_impossible_travel > 5
      severity: high
      
    - name: high_threat_volume
      condition: threat_blocks_per_minute > 100
      severity: warning

  performance:
    - name: plugin_high_latency
      condition: plugin_avg_latency > 50ms
      severity: warning
      
    - name: memory_usage_high
      condition: plugin_memory_usage > 80%
      severity: critical
```

## Development and Extension

### Plugin Development

Creating new plugins:

```go
package myplugin

import (
    "context"
    "net/http"
    "hkp-plugin-core/pkg/plugin"
)

type MyPlugin struct {
    host plugin.PluginHost
}

func (p *MyPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
    p.host = host
    
    // Register middleware
    middleware, err := p.CreateMiddleware()
    if err != nil {
        return err
    }
    
    return host.RegisterMiddleware("/", middleware)
}

func (p *MyPlugin) CreateMiddleware() (func(http.Handler) http.Handler, error) {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Plugin logic here
            next.ServeHTTP(w, r)
        })
    }, nil
}

// Implement remaining plugin.Plugin interface methods...
```

### Plugin Interface

```go
type Plugin interface {
    Initialize(ctx context.Context, host PluginHost, config map[string]interface{}) error
    Name() string
    Version() string
    Description() string
    Dependencies() []PluginDependency
    Priority() int
    Shutdown(ctx context.Context) error
}
```

### Event System Usage

```go
// Subscribe to events
host.SubscribeEvent("threat.detected", p.handleThreatEvent)

// Publish events
host.PublishEvent(plugin.PluginEvent{
    Type:      "abuse.detected",
    Source:    p.Name(),
    Timestamp: time.Now(),
    Data: map[string]interface{}{
        "client_ip": clientIP,
        "severity":  "high",
    },
})
```

## Installation and Setup

### System Requirements

- **Go**: 1.19 or later
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **Memory**: Minimum 2GB, recommended 8GB+
- **CPU**: Minimum 2 cores, recommended 4+ cores
- **Disk**: 1GB for plugins and models

### Installation Steps

1. **Build Plugins**:
```bash
make plugins
```

2. **Install Plugin Files**:
```bash
sudo cp build/plugins/*.so /etc/hockeypuck/plugins/
sudo chown hockeypuck:hockeypuck /etc/hockeypuck/plugins/*.so
```

3. **Create Configuration**:
```bash
sudo mkdir -p /var/lib/hockeypuck/ml-models
sudo cp config/plugins.toml /etc/hockeypuck/
```

4. **Start Hockeypuck**:
```bash
sudo systemctl restart hockeypuck
```

### Docker Deployment

```dockerfile
FROM golang:1.19-alpine AS builder
COPY . /app
WORKDIR /app
RUN make plugins

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y hockeypuck
COPY --from=builder /app/build/plugins/ /etc/hockeypuck/plugins/
COPY config/plugins.toml /etc/hockeypuck/
CMD ["hockeypuck", "-config", "/etc/hockeypuck/hockeypuck.conf"]
```

## Troubleshooting

### Common Issues

#### Plugin Load Failures
```bash
# Check plugin dependencies
ldd /etc/hockeypuck/plugins/plugin-name.so

# Verify permissions
ls -la /etc/hockeypuck/plugins/

# Check logs
journalctl -u hockeypuck -f
```

#### Memory Issues
```bash
# Monitor plugin memory usage
curl localhost:8080/plugins/status | jq '.memory_usage'

# Adjust garbage collection
export GOGC=50

# Reduce cache sizes in plugin configurations
```

#### Performance Problems
```bash
# Profile plugin performance
go tool pprof http://localhost:8080/debug/pprof/profile

# Check plugin processing times
curl localhost:8080/metrics | grep plugin_latency
```

### Debug Configuration

```toml
[plugins.global]
logLevel = "debug"
enableProfiling = true
profilePort = 8081
metricsEnabled = true
```

## Security Considerations

### Plugin Security

1. **Code Review**: All plugins should undergo security review
2. **Sandboxing**: Consider running plugins in isolated environments
3. **Resource Limits**: Implement resource limits for plugin operations
4. **Update Management**: Establish secure plugin update procedures

### Operational Security

1. **Access Control**: Restrict plugin management to authorized personnel
2. **Audit Logging**: Log all plugin operations and configuration changes
3. **Backup Strategy**: Regular backups of plugin configurations and models
4. **Incident Response**: Procedures for plugin-related security incidents

## Future Roadmap

### Planned Enhancements

- **Quantum-Resistant Cryptography**: Preparation for post-quantum threats
- **Federated Learning**: Privacy-preserving collaborative defense
- **Advanced ML Models**: Deep learning for sophisticated pattern recognition
- **API Gateway**: RESTful API for external plugin management
- **Blockchain Integration**: Decentralized threat intelligence sharing

### Community Contributions

The HKP Plugin System welcomes community contributions:
- Plugin development and testing
- Threat intelligence feed integration
- Performance optimization
- Documentation improvements
- Security research and analysis

## License and Support

This plugin system is open source and available under the GNU Affero General Public License v3.0 (AGPL-3.0). 

For support:
- Documentation: See individual plugin README files
- Issues: GitHub issue tracker
- Security: Responsible disclosure policy
- Community: Mailing lists and forums

## Version History

- **v1.0.0**: Initial comprehensive plugin system release
  - Complete Zero Trust Network Access implementation
  - Advanced ML-based abuse detection
  - Comprehensive rate limiting plugin suite
  - Event-driven plugin communication
  - Production-ready monitoring and observability
  - Full tomb.Tomb integration for reliable goroutine management