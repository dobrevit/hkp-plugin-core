# HTTP Header Implementation Analysis

## Overview

This document analyzes the gap between documented header coordination and actual implementation in the Hockeypuck plugin system.

## Headers Actually SET by Plugins

### 1. Zero Trust Plugin (zerotrust)

**Headers Set:**
- `X-ZTNA-Session-ID` - Session identifier
- `X-ZTNA-Trust-Level` - Trust level (none/low/medium/high/verified)
- `X-ZTNA-Risk-Score` - Risk score (0.000-1.000)
- `X-ZTNA-Segment` - Network segment assignment
- `X-ZTNA-Policy` - Applied policy name
- `Content-Type` - For JSON responses

**Cookie Set:**
- `ztna-session` - Session cookie with HttpOnly, Secure, SameSite flags

### 2. ML Abuse Detection Plugin (mlabuse)

**Headers Set:**
- `X-ML-Anomaly-Score` - Anomaly score (0.000-1.000)
- `X-ML-Anomaly-Type` - Type of anomaly detected
- `X-ML-LLM-Detected` - "true" if LLM/AI content detected
- `X-ML-Synthetic-Score` - Synthetic content score (0.000-1.000)

### 3. Anti-Abuse Plugin (antiabuse)

**Headers Set:**
- `X-RateLimit-Ban` - Ban duration (e.g., "10s")
- `X-AntiAbuse-Blocked` - "true" when blocked

### 4. Geographic Rate Limit Plugin (ratelimit-geo)

**Headers Set:**
- `X-RateLimit-Ban` - Ban duration (e.g., "1h", "6h", "30m")
- `X-RateLimit-Ban-Reason` - Human-readable ban reason
- `X-RateLimit-Ban-Type` - "geo"

### 5. Threat Intelligence Plugin (ratelimit-threat)

**Headers Set:**
- `X-Threat-Detected` - "true" when threat detected
- `X-Threat-Type` - Type of threat (e.g., malware, phishing, scanner)
- `X-Threat-Severity` - Severity level (low/medium/high/critical)
- `X-IP-Reputation` - IP reputation score (0.00-1.00)
- `X-Threat-Level` - Threat level assessment

## Headers Actually READ by Plugins

### 1. Zero Trust Plugin
**Headers Read:**
- `Authorization` - For Bearer token authentication
- `X-ZTNA-Session` - Alternative session ID header
- `X-Forwarded-For` - For client IP extraction
- Cookie: `ztna-session` - Session cookie

### 2. ML Abuse Detection Plugin
**Headers Read:**
- `X-Forwarded-For` - For client IP extraction
- `X-Real-IP` - Alternative IP header
- All headers scanned for threat patterns

### 3. Anti-Abuse Plugin
**Headers Read:**
- `X-Forwarded-For` - For client IP extraction

### 4. Geographic Rate Limit Plugin
**Headers Read:**
- `X-Forwarded-For` - For client IP extraction
- `X-Real-IP` - Alternative IP header

### 5. Threat Intelligence Plugin
**Headers Read:**
- `X-Forwarded-For` - For client IP extraction
- All headers scanned for threat patterns (e.g., User-Agent for scanner detection)

## Documented vs Implemented Headers

### Headers Documented but NOT Implemented:
1. `X-Geo-Country` - Mentioned in docs but not set by geo plugin
2. `X-Tarpit-Candidate` - Mentioned in docs but tarpit plugin doesn't set this
3. Many plugin coordination headers mentioned in documentation are not actually implemented

### Headers Implemented but NOT Documented:
1. `X-ZTNA-Session-ID` - Zero Trust session tracking
2. `X-ZTNA-Policy` - Policy enforcement tracking
3. `X-RateLimit-Ban-Type` - Categorization of ban type
4. `X-RateLimit-Ban-Reason` - Human-readable ban reasons
5. `X-IP-Reputation` - Reputation scoring system

## Plugin Communication Gaps

### Current State:
- Plugins primarily communicate through the event system, NOT headers
- Events published: `ml.abuse.detected`, `security.threat.detected`, `ratelimit.violation`
- Headers are mostly used for external communication (to load balancers, proxies)

### Missing Inter-Plugin Headers:
1. No risk score sharing between plugins via headers
2. No authentication state sharing via headers
3. No threat intelligence sharing via headers
4. No coordinated rate limit information via headers

## Key Findings

### 1. Limited Header Coordination
- Plugins don't read each other's headers for decision making
- Each plugin makes independent decisions
- Coordination happens through events, not headers

### 2. External vs Internal Communication
- Headers are primarily for external systems (load balancers, monitoring)
- Internal coordination uses the event bus system
- No standardized header format for plugin coordination

### 3. Security Headers Focus
- Most headers are security-focused (bans, threats, anomalies)
- Limited operational headers (metrics, performance)
- No headers for debugging or tracing

## Recommendations

### 1. Implement Documented Headers
```go
// Example: Geographic plugin should set country header
w.Header().Set("X-Geo-Country", location.Country)
w.Header().Set("X-Geo-City", location.City)
w.Header().Set("X-Geo-ASN", fmt.Sprintf("%d", location.ASN))
```

### 2. Add Plugin Coordination Headers
```go
// Example: Share risk scores between plugins
w.Header().Set("X-Plugin-Risk-Score", fmt.Sprintf("%.3f", aggregateRisk))
w.Header().Set("X-Plugin-Decision", "allow|challenge|block")
w.Header().Set("X-Plugin-Confidence", fmt.Sprintf("%.3f", confidence))
```

### 3. Standardize Header Format
- Use consistent naming: `X-{Plugin}-{Property}`
- Use consistent value formats (especially for numbers)
- Document all headers in a central location

### 4. Enable Header-Based Coordination
```go
// Example: Read other plugin headers for decisions
mlScore := r.Header.Get("X-ML-Anomaly-Score")
geoRisk := r.Header.Get("X-Geo-Risk-Score")
// Make coordinated decision based on multiple signals
```

## Conclusion

There is a significant gap between the documented header coordination system and the actual implementation. While the documentation suggests sophisticated header-based communication between plugins, the reality is that:

1. Plugins primarily use events for coordination
2. Headers are mainly for external system integration
3. Many documented headers are not implemented
4. Plugins don't read each other's headers for decision making

To realize the full potential of the plugin system, the header coordination should be implemented as documented, enabling plugins to make more informed decisions based on the collective intelligence of the system.