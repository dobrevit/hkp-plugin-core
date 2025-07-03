# Rate Limiting Plugins Suite

## Overview

The Rate Limiting Plugins Suite provides comprehensive, multi-layered protection against various forms of abuse and attack patterns. This suite consists of four specialized plugins that work together to create an intelligent, adaptive defense system:

1. **Geographic Analysis Plugin** - Location-based security and impossible travel detection
2. **ML Extension Plugin** - Machine learning-enhanced traffic analysis and prediction
3. **Threat Intelligence Plugin** - External threat feed integration and IP reputation
4. **Tarpit Plugin** - Defensive connection management and attacker resource exhaustion

## Plugin Architecture

### Layered Defense Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                    Incoming Request                         │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│           1. Threat Intelligence Check                      │
│              (Known Bad IPs & Feeds)                       │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│           2. Geographic Analysis                            │
│        (Impossible Travel & Location Validation)           │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│           3. ML Traffic Analysis                            │
│         (Pattern Recognition & Anomaly Detection)          │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│           4. Tarpit (if flagged)                           │
│         (Resource Exhaustion & Intelligence)               │
└─────────────────────────────────────────────────────────────┘
```

### Event-Driven Coordination

The plugins communicate through a sophisticated event system:

```
Threat Intel → "threat.detected" → Geographic Analysis
                                → ML Extension
                                → Tarpit

Geographic   → "geo.anomaly"   → ML Extension
                              → Threat Intel
                              → Tarpit

ML Extension → "ml.anomaly"    → All plugins
             → "ml.pattern"    → Threat Intel

Tarpit       → "tarpit.intel" → Threat Intel
             → "attacker.profile" → All plugins
```

---

# Geographic Analysis Plugin (`ratelimit-geo`)

## Overview

The Geographic Analysis Plugin provides location-based security through impossible travel detection, geographic clustering analysis, and ASN (Autonomous System Number) monitoring. It tracks user location patterns to identify physically impossible movements and coordinated attacks.

## Key Features

### Impossible Travel Detection
- **Physics-Based Validation**: Detects location changes that exceed maximum possible travel speed
- **Time-Distance Analysis**: Calculates minimum travel time between geographic points
- **Configurable Speed Limits**: Adjustable maximum travel speeds (default: 1000 km/h)
- **False Positive Reduction**: Accounts for VPN usage and legitimate proxy services

### Geographic Clustering
- **Attack Pattern Recognition**: Identifies coordinated attacks from multiple IPs in close proximity
- **Cluster Analysis**: Detects suspicious geographic clusters of activity
- **Time Window Correlation**: Analyzes temporal patterns within geographic regions
- **Distributed Attack Detection**: Identifies botnets and coordinated campaigns

### ASN Analysis
- **Network Reputation**: Tracks reputation of autonomous systems
- **ASN Jumping Detection**: Identifies rapid network changes indicating proxy/VPN hopping
- **Provider Analysis**: Categorizes traffic by hosting provider, ISP, or datacenter
- **Behavioral Profiling**: Builds profiles of normal vs. suspicious network usage

## Configuration

### Basic Configuration

```toml
[plugins.ratelimit-geo]
enabled = true
geoip_database_path = "/usr/share/GeoIP/GeoLite2-City.mmdb"
tracking_ttl = "24h"
cleanup_interval = "1h"
max_locations = 100

# Impossible travel detection
impossible_travel_enabled = true
max_travel_speed_kmh = 1000.0

# Geographic clustering
clustering_enabled = true
cluster_radius_km = 50.0
cluster_size_threshold = 5
cluster_time_window = "1h"

# ASN analysis
asn_analysis_enabled = true
max_asns_per_ip = 3

# Ban durations
ban_duration = "1h"
impossible_travel_ban = "6h"
clustering_ban = "2h"
asn_jumping_ban = "30m"
```

### Advanced Configuration

```toml
[plugins.ratelimit-geo]
enabled = true
geoip_database_path = "/usr/share/GeoIP/GeoLite2-City.mmdb"
tracking_ttl = "24h"
cleanup_interval = "1h"
max_locations = 100

# Enhanced impossible travel detection
impossible_travel_enabled = true
max_travel_speed_kmh = 800.0  # More strict
allow_datacenter_jumps = false
vpn_detection_enabled = true
proxy_whitelist = ["8.8.8.8", "1.1.1.1"]

# Advanced geographic clustering
clustering_enabled = true
cluster_radius_km = 30.0  # Tighter clusters
cluster_size_threshold = 3
cluster_time_window = "30m"
cluster_confidence_threshold = 0.8

# Enhanced ASN analysis
asn_analysis_enabled = true
max_asns_per_ip = 2
datacenter_detection = true
hosting_provider_scoring = true
residential_ip_preference = true

# Geo-specific policies
[plugins.ratelimit-geo.country_policies]
high_risk_countries = ["XX", "YY", "ZZ"]
blocked_countries = ["AA", "BB"]
require_verification = ["CC", "DD"]

# Time-zone analysis
timezone_analysis_enabled = true
timezone_jump_threshold = 6  # hours
business_hours_only = false
```

## Detection Capabilities

### Impossible Travel Scenarios

| Scenario | Detection Method | Default Action |
|----------|------------------|----------------|
| Intercontinental jumps | Distance/time calculation | 6-hour ban |
| Rapid country changes | Geographic boundaries | 1-hour ban |
| Datacenter hopping | ASN + location analysis | 30-minute ban |
| VPN circumvention | Pattern + timing analysis | Verification required |

### Geographic Risk Scoring

- **Distance Factor**: Penalty based on impossible travel distance
- **Time Factor**: Bonus for reasonable time intervals between locations
- **ASN Consistency**: Penalty for frequent network changes
- **Country Risk**: Adjustment based on country-specific threat levels
- **Historical Patterns**: Bonus for consistent geographic behavior

## API Endpoints

> **Implementation Status**: ⚠️ **Mixed** - Some endpoints are implemented, others are planned features. See individual plugin status below.

### Status and Monitoring

#### GET `/geo/status` ❌ **Not Implemented**
Get geographic analysis system status.

**Response:**
```json
{
    "enabled": true,
    "impossible_travel_enabled": true,
    "clustering_enabled": true,
    "asn_analysis_enabled": true,
    "tracked_ips": 15432,
    "active_clusters": 3,
    "impossible_travel_detections": 127,
    "asn_violations": 89,
    "uptime": "2h45m12s"
}
```

#### GET `/geo/metrics` ❌ **Not Implemented**
Get detailed geographic metrics.

**Response:**
```json
{
    "total_requests": 298743,
    "geographic_blocks": 1456,
    "impossible_travel_blocks": 234,
    "clustering_blocks": 89,
    "asn_blocks": 67,
    "country_distribution": {
        "US": 156789,
        "GB": 45678,
        "DE": 23456,
        "CN": 12345
    },
    "top_asns": [
        {"asn": 15169, "org": "Google Inc.", "requests": 45678},
        {"asn": 16509, "org": "Amazon.com", "requests": 34567}
    ]
}
```

---

# ML Extension Plugin (`ratelimit-ml`)

## Overview

The ML Extension Plugin enhances traditional rate limiting with machine learning-based traffic pattern analysis, anomaly detection, and predictive capabilities. It uses sophisticated algorithms to identify coordinated attacks, bot behavior, and traffic anomalies.

## Key Features

### Advanced Pattern Analysis
- **Traffic Pattern Recognition**: Identifies normal vs. abnormal traffic patterns
- **Burst Detection**: Recognizes coordinated burst attacks
- **Periodicity Analysis**: Detects regular bot-like behavior patterns
- **Entropy Measurement**: Analyzes randomness in request patterns

### Predictive Traffic Analysis
- **Traffic Forecasting**: Predicts traffic spikes and patterns
- **Anomaly Prediction**: Anticipates unusual traffic before it occurs
- **Capacity Planning**: Helps predict resource needs
- **Attack Early Warning**: Identifies coordinated attacks in early stages

### Coordinated Attack Detection
- **Multi-IP Coordination**: Detects attacks across multiple IP addresses
- **Timing Correlation**: Identifies synchronized attack patterns
- **Distributed Campaign Recognition**: Recognizes large-scale coordinated efforts
- **Botnet Identification**: Identifies bot network activity patterns

## Configuration

### Basic Configuration

```toml
[plugins.ratelimit-ml]
enabled = true
modelPath = "/var/lib/hockeypuck/ml/ratelimit-model.dat"
anomalyThreshold = 0.85
predictionWindow = "5m"
learningEnabled = true
coordinationEnabled = true
blockDuration = "1h"
escalationMultiplier = 2.0
```

### Advanced Configuration

```toml
[plugins.ratelimit-ml]
enabled = true
modelPath = "/var/lib/hockeypuck/ml/ratelimit-model.dat"
anomalyThreshold = 0.8
predictionWindow = "3m"
learningEnabled = true
coordinationEnabled = true
blockDuration = "30m"
escalationMultiplier = 1.5

# Pattern analysis settings
[plugins.ratelimit-ml.pattern_analysis]
entropy_threshold = 0.3
periodicity_threshold = 0.8
burst_detection_window = "30s"
coordination_window = "2m"
min_samples_for_learning = 100

# Anomaly detection tuning
[plugins.ratelimit-ml.anomaly_detection]
isolation_forest_trees = 100
contamination_ratio = 0.1
feature_subsampling = 0.8
score_aggregation = "average"

# Prediction settings
[plugins.ratelimit-ml.prediction]
forecast_horizon = "10m"
confidence_interval = 0.95
model_update_frequency = "15m"
prediction_accuracy_threshold = 0.7
```

## Detection Capabilities

### Pattern Types

| Pattern Type | Detection Method | Typical Score Range |
|-------------|------------------|-------------------|
| Human-like | High entropy, irregular timing | 0.1 - 0.3 |
| Bot regular | Low entropy, regular intervals | 0.7 - 0.9 |
| Bot random | Artificial randomness | 0.6 - 0.8 |
| Coordinated | Multi-IP synchronization | 0.8 - 0.95 |
| Distributed attack | Large-scale coordination | 0.9 - 1.0 |

### Traffic Metrics

- **Request Rate Entropy**: Measures randomness in request timing
- **Burst Pattern Score**: Identifies coordinated burst attacks
- **Periodicity Score**: Detects regular, non-human patterns
- **Coordination Score**: Measures multi-IP attack coordination
- **Prediction Accuracy**: Success rate of traffic forecasting

## API Endpoints

### Status and Control

#### GET `/ratelimit/ml/status` ✅ **Implemented**
Get ML rate limiting system status.

**Response:**
```json
{
    "enabled": true,
    "model_loaded": true,
    "model_version": "v1.2.3",
    "learning_enabled": true,
    "coordination_enabled": true,
    "patterns_detected": 1247,
    "coordinated_attacks_blocked": 89,
    "prediction_accuracy": 0.87,
    "model_last_updated": "2024-01-01T14:30:00Z"
}
```

#### GET `/ratelimit/ml/patterns` ✅ **Implemented**
Get detected traffic patterns.

**Response:**
```json
{
    "active_patterns": [
        {
            "pattern_id": "coord_001",
            "type": "coordinated_attack",
            "ips_involved": 45,
            "anomaly_score": 0.92,
            "first_detected": "2024-01-01T14:25:00Z",
            "requests_per_second": 156,
            "geographic_spread": ["US", "GB", "DE"],
            "status": "active"
        }
    ],
    "historical_patterns": 234,
    "prediction_confidence": 0.89
}
```

---

# Threat Intelligence Plugin (`ratelimit-threat-intel`)

## Overview

The Threat Intelligence Plugin integrates external threat feeds, maintains IP reputation databases, and provides real-time threat detection capabilities. It serves as the first line of defense by blocking known malicious IPs and coordinating with other security systems.

## Key Features

### Multi-Feed Integration
- **Format Support**: JSON, CSV, TXT, XML threat feed formats
- **Real-time Updates**: Continuous feed monitoring and updates
- **Feed Validation**: Automatic feed integrity and freshness checks
- **Custom Feeds**: Support for organization-specific threat intelligence

### IP Reputation System
- **Dynamic Scoring**: Real-time reputation score calculation
- **Multi-Source Aggregation**: Combines data from multiple threat feeds
- **Historical Analysis**: Tracks IP behavior over time
- **Confidence Scoring**: Provides confidence levels for threat assessments

### Threat Pattern Matching
- **Signature Detection**: Matches known attack patterns and signatures
- **Behavioral Analysis**: Identifies threats based on behavior patterns
- **IOC Matching**: Indicator of Compromise correlation and matching
- **Threat Categorization**: Classifies threats by type and severity

## Configuration

### Basic Configuration

```toml
[plugins.ratelimit-threat-intel]
enabled = true
updateInterval = "1h"
cacheSize = 100000
blockDuration = "24h"
reputationThreshold = 0.3
autoBlock = true
shareThreatData = false
localBlocklist = "/etc/hockeypuck/blocklist.txt"

# Example threat feed
[[plugins.ratelimit-threat-intel.threatFeeds]]
name = "emerging-threats"
url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
type = "ip"
format = "txt"
updateFreq = "1h"
enabled = true
```

### Advanced Multi-Feed Configuration

```toml
[plugins.ratelimit-threat-intel]
enabled = true
updateInterval = "30m"
cacheSize = 500000
blockDuration = "12h"
reputationThreshold = 0.2
autoBlock = true
shareThreatData = true
localBlocklist = "/etc/hockeypuck/blocklist.txt"
intelligenceSharing = true
feedFailureThreshold = 3
backgroundUpdateEnabled = true

# Multiple threat feeds
[[plugins.ratelimit-threat-intel.threatFeeds]]
name = "emerging-threats-compromised"
url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
type = "ip"
format = "txt"
updateFreq = "1h"
enabled = true
priority = "high"

[[plugins.ratelimit-threat-intel.threatFeeds]]
name = "spamhaus-drop"
url = "https://www.spamhaus.org/drop/drop.txt"
type = "ip"
format = "txt"
updateFreq = "24h"
enabled = true
priority = "critical"

[[plugins.ratelimit-threat-intel.threatFeeds]]
name = "abuse-ch-malware"
url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
type = "ip"
format = "txt"
updateFreq = "4h"
enabled = true
category = "malware"

[[plugins.ratelimit-threat-intel.threatFeeds]]
name = "custom-internal"
url = "https://internal.company.com/threat-feed.json"
type = "mixed"
format = "json"
updateFreq = "15m"
enabled = true
apiKey = "your-api-key"
headers = {"X-Custom-Auth" = "bearer-token"}

# Reputation scoring weights
[plugins.ratelimit-threat-intel.reputation_scoring]
malware_weight = 0.9
botnet_weight = 0.8
spam_weight = 0.6
scanner_weight = 0.5
phishing_weight = 0.85
```

## Threat Feed Types

### Supported Feed Formats

| Format | Description | Example Sources |
|--------|-------------|-----------------|
| **TXT** | Plain text, one indicator per line | Emerging Threats, Spamhaus |
| **CSV** | Comma-separated values with metadata | Custom feeds, commercial |
| **JSON** | Structured JSON with rich metadata | Internal feeds, APIs |
| **XML** | XML-formatted threat intelligence | STIX/TAXII feeds |

### Popular Threat Feeds

```toml
# High-quality free threat feeds
[[plugins.ratelimit-threat-intel.threatFeeds]]
name = "emergingthreats-compromised"
url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
type = "ip"
format = "txt"
category = "compromised-hosts"

[[plugins.ratelimit-threat-intel.threatFeeds]]
name = "spamhaus-edrop"
url = "https://www.spamhaus.org/drop/edrop.txt"
type = "ip"
format = "txt"
category = "spam-botnet"

[[plugins.ratelimit-threat-intel.threatFeeds]]
name = "abuse-ch-feodo"
url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
type = "ip"
format = "txt"
category = "banking-trojans"

[[plugins.ratelimit-threat-intel.threatFeeds]]
name = "blocklist-de"
url = "https://lists.blocklist.de/lists/all.txt"
type = "ip"
format = "txt"
category = "attack-sources"
```

## API Endpoints

### Threat Intelligence Management

#### GET `/ratelimit/threatintel/status` ✅ **Implemented**
Get threat intelligence system status.

**Response:**
```json
{
    "enabled": true,
    "feeds_active": 4,
    "feeds_total": 5,
    "last_update": "2024-01-01T14:45:00Z",
    "cache_size": 125847,
    "blocked_ips": 98432,
    "reputation_checks": 1547832,
    "feed_status": [
        {
            "name": "emerging-threats",
            "status": "active",
            "last_update": "2024-01-01T14:30:00Z",
            "indicators": 45678,
            "errors": 0
        }
    ]
}
```

#### POST `/ratelimit/threatintel/check` ✅ **Implemented**
Check IP reputation.

**Request:**
```json
{
    "ip": "192.168.1.100"
}
```

**Response:**
```json
{
    "ip": "192.168.1.100",
    "is_threat": false,
    "reputation_score": 0.8,
    "threat_level": "low",
    "categories": [],
    "sources": [],
    "confidence": 0.9,
    "last_seen": null,
    "recommendation": "allow"
}
```

#### POST `/ratelimit/threatintel/report` ✅ **Implemented**
Report new threat indicator.

**Request:**
```json
{
    "ip": "203.0.113.45",
    "threat_type": "scanner",
    "confidence": 0.85,
    "evidence": "Automated scanning detected",
    "source": "internal-detection"
}
```

---

# Tarpit Plugin (`ratelimit-tarpit`)

## Overview

The Tarpit Plugin implements defensive connection management by deliberately slowing down or "trapping" malicious connections. It serves as the final layer of defense, wasting attacker resources while gathering intelligence about attack methods and tools.

## Key Features

### Tarpit Modes
- **Slow Mode**: Gradually slows response times to waste attacker resources
- **Sticky Mode**: Keeps connections open for extended periods
- **Random Mode**: Applies unpredictable delays to confuse automated tools
- **Resource Exhaustion**: Forces attackers to consume computational resources

### Honeypot Integration
- **Fake Endpoints**: Creates attractive targets for attackers
- **Intelligence Gathering**: Collects information about attack tools and methods
- **Behavioral Analysis**: Profiles attacker sophistication and persistence
- **Attack Signature Collection**: Gathers signatures for future detection

### Connection Management
- **Adaptive Response**: Adjusts behavior based on attacker persistence
- **Resource Monitoring**: Prevents tarpit from overwhelming server resources  
- **Connection Limiting**: Manages maximum concurrent tarpitted connections
- **Graceful Degradation**: Maintains service availability under attack

## Configuration

### Basic Configuration

```toml
[plugins.ratelimit-tarpit]
enabled = true
tarpitMode = "slow"
delayMin = "100ms"
delayMax = "10s"
responseChunkSize = 64
connectionTimeout = "5m"
maxConcurrentTarpits = 1000
honeypotEnabled = true
honeypotPaths = [
    "/admin",
    "/wp-admin", 
    "/.git",
    "/.env",
    "/phpmyadmin",
    "/api/v1/users",
    "/backup.sql"
]
intelligenceMode = true
autoTarpitThreshold = 0.8
```

### Advanced Configuration

```toml
[plugins.ratelimit-tarpit]
enabled = true
tarpitMode = "adaptive"  # Changes based on attacker behavior
delayMin = "50ms"
delayMax = "30s"
responseChunkSize = 32
connectionTimeout = "10m"
maxConcurrentTarpits = 2000
honeypotEnabled = true
intelligenceMode = true
autoTarpitThreshold = 0.7

# Extended honeypot paths
honeypotPaths = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/.git", "/.svn", "/.env", "/.htaccess",
    "/phpmyadmin", "/pma", "/mysql", "/db",
    "/api/v1/users", "/api/admin", "/admin/api",
    "/backup.sql", "/database.sql", "/dump.sql",
    "/config.php", "/settings.php", "/wp-config.php",
    "/xmlrpc.php", "/readme.html", "/license.txt"
]

# Resource exhaustion settings
[plugins.ratelimit-tarpit.resourceExhaustion]
enabled = true
cpuIntensive = true      # Force CPU-intensive operations
memoryIntensive = false  # Avoid memory exhaustion attacks
bandwidthMode = "slow"   # slow, burst, random
fakeDataSize = 1048576   # 1MB of fake data

# Intelligence collection
[plugins.ratelimit-tarpit.intelligence]
profileAttackers = true
collectUserAgents = true
analyzePersistence = true
trackToolSignatures = true
shareIntelligence = true
```

## Honeypot Paths

### Default Honeypot Endpoints

The plugin includes common attack targets that immediately trigger tarpit mode:

| Path | Target Type | Typical Attackers |
|------|-------------|-------------------|
| `/admin` | Admin panels | Brute force attacks |
| `/wp-admin` | WordPress admin | WordPress scanners |
| `/.git` | Version control | Source code theft |
| `/.env` | Environment files | Configuration theft |
| `/phpmyadmin` | Database admin | Database attacks |
| `/api/v1/users` | API endpoints | Data harvesting |
| `/backup.sql` | Database dumps | Data theft |
| `/xmlrpc.php` | WordPress XML-RPC | DDoS amplification |

### Custom Honeypot Configuration

```toml
# Application-specific honeypots
honeypotPaths = [
    # Your application paths
    "/app/admin",
    "/internal/api",
    "/private/data",
    
    # Common attack paths
    "/admin", "/administrator", "/wp-admin",
    "/.git", "/.svn", "/.env", "/.htaccess",
    "/phpmyadmin", "/pma", "/mysql",
    "/api/admin", "/api/users", "/api/keys",
    
    # File download attempts  
    "/backup.sql", "/database.sql", "/dump.sql",
    "/config.php", "/wp-config.php", "/settings.php"
]
```

## API Endpoints

### Status and Control

#### GET `/ratelimit/tarpit/status` ✅ **Implemented**
Get tarpit system status.

**Response:**
```json
{
    "enabled": true,
    "mode": "slow",
    "active_connections": 23,
    "total_trapped": 1456,
    "max_concurrent": 1000,
    "honeypot_enabled": true,
    "honeypot_triggers": 89,
    "intelligence_mode": true,
    "uptime": "4h15m23s",
    "resource_usage": {
        "cpu_percent": 2.1,
        "memory_mb": 45,
        "goroutines": 67
    }
}
```

#### GET `/ratelimit/tarpit/connections` ✅ **Implemented**
Get active tarpit connections.

**Response:**
```json
{
    "active_connections": [
        {
            "client_ip": "203.0.113.45",
            "connected_at": "2024-01-01T14:32:15Z",
            "duration": "3m45s",
            "bytes_sent": 2048,
            "delays_applied": 12,
            "state": "draining",
            "reason": "honeypot_trigger",
            "intelligence": {
                "patterns": ["wp-scan", "admin-brute"],
                "tools": ["nmap", "dirb"],
                "sophistication": "low",
                "persistence": 3
            }
        }
    ],
    "total_active": 23
}
```

#### GET `/ratelimit/tarpit/intelligence` ❌ **Not Implemented**
Get collected attacker intelligence.

**Response:**
```json
{
    "attack_profiles": [
        {
            "profile_id": "att_001",
            "first_seen": "2024-01-01T12:00:00Z",
            "last_seen": "2024-01-01T14:45:00Z",
            "ip_addresses": ["203.0.113.45", "203.0.113.46"],
            "tools_detected": ["nmap", "dirb", "sqlmap"],
            "attack_patterns": ["directory-scan", "sql-injection", "admin-brute"],
            "sophistication": "medium",
            "persistence_score": 7,
            "total_requests": 1247,
            "success_rate": 0.02
        }
    ],
    "tool_signatures": {
        "nmap": 234,
        "dirb": 156, 
        "sqlmap": 89,
        "nikto": 67
    },
    "attack_trends": {
        "hourly_distribution": [12, 15, 8, 23, 45, 67, 34],
        "top_targets": ["/admin", "/.git", "/wp-admin"],
        "geographic_sources": ["CN", "RU", "US", "BR"]
    }
}
```

## Performance and Resource Management

### Resource Limits

```toml
# Prevent tarpit from overwhelming server
maxConcurrentTarpits = 1000
connectionTimeout = "5m"
maxMemoryPerConnection = "1MB"
maxBandwidthPerConnection = "10KB/s"

# Auto-scaling based on load
[plugins.ratelimit-tarpit.scaling]
autoScaleEnabled = true
cpuThreshold = 80        # Scale down if CPU > 80%
memoryThreshold = 85     # Scale down if memory > 85%
minConcurrentTarpits = 100
emergencyModeEnabled = true
```

### Monitoring Metrics

- **Active Connections**: Current tarpitted connections
- **Resource Usage**: CPU, memory, bandwidth consumption
- **Effectiveness**: Attack disruption success rate
- **Intelligence Quality**: Usefulness of collected data
- **False Positive Rate**: Legitimate traffic accidentally tarpitted

## Best Practices

### Deployment Strategy
1. **Start Small**: Begin with low concurrent connection limits
2. **Monitor Resources**: Watch CPU and memory usage carefully
3. **Tune Delays**: Adjust delay ranges based on attack persistence
4. **Review Intelligence**: Regularly analyze collected attack data

### Security Considerations
1. **Resource Protection**: Prevent tarpit from becoming a DoS vector
2. **False Positive Management**: Ensure legitimate traffic isn't trapped
3. **Intelligence Sharing**: Consider sharing attack signatures with community
4. **Legal Compliance**: Ensure tarpit usage complies with local laws

---

# Integration and Coordination

## Plugin Load Order

The recommended load order ensures optimal coordination:

```toml
[plugins]
enabled = true
loadOrder = [
    "ratelimit-threat-intel",  # First: Block known threats
    "ratelimit-geo",           # Second: Geographic validation  
    "ratelimit-ml",            # Third: Pattern analysis
    "ratelimit-tarpit"         # Last: Defensive response
]
```

## Event Coordination

### Published Events

```yaml
ratelimit-threat-intel:
  - threat.detected
  - reputation.updated
  - blocklist.updated

ratelimit-geo:
  - geo.impossible_travel
  - geo.clustering_detected
  - geo.asn_violation

ratelimit-ml:
  - ml.anomaly_detected
  - ml.pattern_recognized
  - ml.coordination_detected

ratelimit-tarpit:
  - tarpit.connection_trapped
  - tarpit.intelligence_gathered
  - tarpit.attacker_profiled
```

### Event Subscriptions

Each plugin subscribes to relevant events from other plugins to enhance their decision-making and coordination.

## Shared Intelligence Headers

All plugins add intelligence headers that downstream plugins can use:

```http
X-Threat-Level: high
X-Threat-Sources: emerging-threats,spamhaus
X-Geo-Risk-Score: 0.85
X-Geo-Country: CN
X-ML-Anomaly-Score: 0.92
X-ML-Pattern: coordinated_attack
X-Tarpit-Candidate: true
```

## Performance Considerations

### Resource Usage Summary

| Plugin | CPU Impact | Memory Usage | Latency Added |
|--------|------------|--------------|---------------|
| Threat Intel | Low | 100-500MB* | <2ms |
| Geographic | Low | 50-200MB** | <5ms |
| ML Extension | Medium | 30-80MB | <5ms |
| Tarpit | Variable*** | 10-50MB | Variable |

\* Depends on threat feed size
\** Depends on GeoIP database size  
\*** High with many active tarpits

### Scaling Recommendations

- **Small deployments**: All plugins on single instance
- **Medium deployments**: Consider Redis for shared state
- **Large deployments**: Distribute plugins across instances

## Security Best Practices

1. **Defense in Depth**: Use all plugins together for maximum protection
2. **Monitoring**: Set up comprehensive alerting for all plugins
3. **Tuning**: Regularly adjust thresholds based on traffic patterns
4. **Updates**: Keep threat feeds and models current
5. **Testing**: Test in staging before production deployment

---

# Version History

- **v1.0.0**: Initial release of all four rate limiting plugins
  - Threat Intelligence Plugin with multi-feed support
  - Geographic Analysis Plugin with impossible travel detection
  - ML Extension Plugin with pattern recognition
  - Tarpit Plugin with honeypot integration
  - Comprehensive event-driven coordination
  - Tomb.Tomb integration for reliable goroutine management