# Zero-Trust Security Plugin for Hockeypuck

## Overview

The Zero-Trust Security Plugin implements comprehensive Zero-Trust Network Access (ZTNA) principles for Hockeypuck, providing continuous authentication, micro-segmentation, and adaptive security policies. It ensures that no user or device is trusted by default, and all access requests are continuously verified based on multiple factors.

## Key Features

### 1. Continuous Authentication
- **Session-based verification**: Every request is authenticated and authorized
- **Multi-factor authentication**: Support for TOTP, email, SMS, certificates
- **Behavioral biometrics**: Tracks user behavior patterns for anomaly detection
- **Device fingerprinting**: Identifies and tracks devices across sessions

### 2. Risk-Based Access Control
- **Dynamic risk assessment**: Continuous evaluation of session risk
- **Adaptive policies**: Security policies adjust based on risk levels
- **Trust levels**: Five-tier trust system (None, Low, Medium, High, Verified)
- **Context-aware decisions**: Access decisions based on multiple contextual factors

### 3. Network Micro-Segmentation
- **Dynamic segments**: Users assigned to network segments based on trust
- **Segment policies**: Different access rules for each segment
- **Service mesh support**: Special handling for service-to-service communication
- **Lateral movement prevention**: Restricts access between segments

### 4. Comprehensive Audit Logging
- **Detailed audit trail**: Every access decision is logged
- **Security event tracking**: Records authentication failures, policy violations
- **Compliance support**: Structured logs for regulatory requirements
- **Real-time monitoring**: Integration with monitoring systems

## Configuration

Add the Zero-Trust plugin to your Hockeypuck configuration:

```toml
[plugins]
enabled = true
directory = "/etc/hockeypuck/plugins"
loadOrder = ["zero-trust-security", "ml-abuse-detector"]

[plugins.zero-trust-security]
enabled = true
type = "security"

# Core settings
config.requireAuthentication = true
config.sessionTimeout = "30m"
config.reevaluationInterval = "5m"
config.maxRiskScore = 0.7
config.deviceFingerprintingLevel = "standard"  # basic, standard, advanced
config.auditLevel = "detailed"  # basic, standard, detailed

# Network segmentation
config.networkSegmentation.enabled = true
config.networkSegmentation.defaultSegment = "public"

# Segment policies
[plugins.zero-trust-security.config.networkSegmentation.segmentPolicies.public]
name = "public"
allowedServices = ["/pks/lookup", "/pks/stats"]
allowedMethods = ["GET"]
riskThreshold = 0.9
requireMFA = false

[plugins.zero-trust-security.config.networkSegmentation.segmentPolicies.authenticated]
name = "authenticated"
allowedServices = ["/pks/add", "/pks/lookup", "/pks/delete"]
allowedMethods = ["GET", "POST", "DELETE"]
riskThreshold = 0.7
requireMFA = false

[plugins.zero-trust-security.config.networkSegmentation.segmentPolicies.admin]
name = "admin"
allowedServices = ["/admin", "/api/v1", "/pks"]
allowedMethods = ["GET", "POST", "PUT", "DELETE"]
riskThreshold = 0.5
requireMFA = true

# Service mesh configuration
config.networkSegmentation.serviceMesh.enabled = true
config.networkSegmentation.serviceMesh.trustedServices = ["keyserver-sync", "monitoring", "backup"]
config.networkSegmentation.serviceMesh.mutualTLSRequired = true
config.networkSegmentation.serviceMesh.serviceAuthTokenTTL = "1h"

# Adaptive policies
config.adaptivePolicies.enabled = true
config.adaptivePolicies.learningMode = true
config.adaptivePolicies.policyUpdateInterval = "30m"
config.adaptivePolicies.anomalyThreshold = 0.6
```

## API Endpoints

### Authentication Endpoints

#### POST /auth/login
Authenticate a user and create a session.

```json
// Request
{
  "username": "user@example.com",
  "password": "secure-password",
  "device_id": "optional-device-id"
}

// Response
{
  "status": "success",
  "session_id": "base64-encoded-session-id",
  "trust_level": "medium",
  "valid_until": "2025-07-01T15:30:00Z"
}

// MFA Required Response
{
  "status": "mfa_required",
  "session_id": "base64-encoded-session-id",
  "challenge": {
    "type": "totp",
    "challenge": "Enter TOTP code for user user@example.com",
    "expires_at": "2025-07-01T15:05:00Z"
  }
}
```

#### POST /auth/logout
Terminate a session.

```json
// Response
{
  "status": "logged_out"
}
```

#### POST /auth/verify
Complete MFA or step-up authentication.

```json
// Request
{
  "type": "totp",
  "code": "123456"
}

// Response
{
  "status": "verified",
  "trust_level": "high",
  "risk_score": 0.2
}
```

#### POST /auth/device/register
Register device information for enhanced fingerprinting.

```json
// Request
{
  "platform": "Windows",
  "screen_resolution": "1920x1080",
  "timezone": "America/New_York",
  "plugins": ["Chrome PDF Plugin", "Native Client"],
  "fonts": ["Arial", "Times New Roman", "Courier New"],
  "webgl_fingerprint": "hash-of-webgl-params",
  "canvas_fingerprint": "hash-of-canvas-rendering",
  "audio_fingerprint": "hash-of-audio-context"
}

// Response
{
  "status": "registered",
  "device_id": "device-fingerprint-id",
  "trust": 0.75
}
```

#### GET /ztna/status
Get Zero-Trust system status.

```json
// Response
{
  "enabled": true,
  "timestamp": "2025-07-01T15:00:00Z",
  "session": {
    "session_id": "current-session-id",
    "user_id": "user@example.com",
    "trust_level": "high",
    "risk_score": 0.3,
    "segment": "authenticated",
    "auth_factors": 2,
    "created_at": "2025-07-01T14:30:00Z",
    "last_activity": "2025-07-01T14:59:00Z"
  },
  "statistics": {
    "active_sessions": 42,
    "policy_count": 7,
    "segment_count": 4,
    "average_risk": 0.35,
    "high_risk_sessions": 3
  }
}
```

## Trust Levels

| Level | Score Range | Description | Access Rights |
|-------|-------------|-------------|---------------|
| None | 1.0 - 0.8 | No trust established | Minimal access only |
| Low | 0.8 - 0.6 | Basic trust | Public resources only |
| Medium | 0.6 - 0.4 | Moderate trust | Authenticated resources |
| High | 0.4 - 0.2 | High trust | Most resources |
| Verified | 0.2 - 0.0 | Fully verified | All resources |

## Risk Assessment Factors

The plugin evaluates multiple factors to calculate risk:

1. **Location Risk (15%)**
   - Geographic anomalies
   - VPN/Proxy detection
   - Known malicious IPs

2. **Time Risk (10%)**
   - Off-hours access
   - Unusual access patterns
   - Rapid session creation

3. **Device Risk (15%)**
   - Device trust score
   - New or unknown devices
   - Vulnerable user agents

4. **Behavior Risk (20%)**
   - Access pattern anomalies
   - Failed access attempts
   - Request velocity

5. **Threat Intelligence (15%)**
   - Known attack patterns
   - Malicious indicators
   - Threat feeds

6. **Authentication Strength (10%)**
   - Number of verified factors
   - Factor quality
   - Time since authentication

7. **Anomaly Detection (15%)**
   - Statistical anomalies
   - Behavioral deviations
   - ML-based detection

## Network Segments

### Public Segment
- **Trust Level**: Low
- **Access**: Read-only public endpoints
- **Authentication**: Optional
- **Use Case**: Anonymous key lookups

### Authenticated Segment
- **Trust Level**: Medium
- **Access**: Standard user operations
- **Authentication**: Required
- **Use Case**: Key management operations

### Admin Segment
- **Trust Level**: High
- **Access**: Administrative functions
- **Authentication**: MFA required
- **Use Case**: System administration

### Service Mesh Segment
- **Trust Level**: Verified
- **Access**: Internal service APIs
- **Authentication**: mTLS required
- **Use Case**: Service-to-service communication

## Security Policies

### Default Policies

1. **High Risk Denial**
   - Blocks access when risk > 0.8
   - Priority: 100
   - Action: Deny

2. **Admin MFA Requirement**
   - Requires MFA for /admin paths
   - Priority: 90
   - Action: Step-up authentication

3. **Off-Hours Restriction**
   - Challenges access outside business hours
   - Priority: 80
   - Action: Request justification

4. **Location Anomaly Detection**
   - Challenges access from new locations
   - Priority: 70
   - Action: Additional verification

## Response Headers

The plugin adds security headers to responses:

```http
X-ZTNA-Session-ID: base64-session-id
X-ZTNA-Trust-Level: high
X-ZTNA-Risk-Score: 0.234
X-ZTNA-Segment: authenticated
X-ZTNA-Policy: admin_mfa
```

## Audit Log Format

Audit logs are written in JSON format:

```json
{
  "timestamp": "2025-07-01T15:00:00Z",
  "event_type": "access_granted",
  "session_id": "session-id",
  "user_id": "user@example.com",
  "client_ip": "192.168.1.100",
  "resource": "/pks/add",
  "action": "POST",
  "result": "success",
  "risk_score": 0.3,
  "details": {
    "duration_ms": 45,
    "trust_level": "high",
    "segment": "authenticated",
    "policy_applied": "default"
  }
}
```

## Integration with Other Plugins

### ML Abuse Detection Integration
The Zero-Trust plugin subscribes to ML abuse detection events:
- Increases risk scores for detected anomalies
- Terminates sessions for confirmed abuse
- Shares behavioral data for improved detection

### Rate Limiting Integration
Responds to rate limit violations:
- Downgrades trust levels for violators
- Records incidents in risk assessment
- Applies stricter policies for repeat offenders

## Best Practices

1. **Start with Learning Mode**
   - Enable adaptive policies in learning mode
   - Monitor behavior patterns before enforcement
   - Gradually tighten policies based on data

2. **Configure Appropriate Timeouts**
   - Balance security with user experience
   - Set session timeouts based on risk tolerance
   - Use shorter timeouts for high-risk operations

3. **Implement Gradual Rollout**
   - Start with monitoring/logging only
   - Enable enforcement for specific segments
   - Expand coverage based on results

4. **Regular Policy Review**
   - Review audit logs for false positives
   - Adjust risk weights based on environment
   - Update threat intelligence regularly

5. **Multi-Factor Authentication**
   - Require MFA for sensitive operations
   - Support multiple MFA methods
   - Consider risk-based MFA triggers

## Troubleshooting

### High False Positive Rate
- Review risk factor weights
- Adjust anomaly thresholds
- Check behavioral baselines
- Verify threat intelligence accuracy

### Session Timeout Issues
- Verify session timeout configuration
- Check inactivity timeout settings
- Review continuous verification interval
- Monitor session cleanup logs

### Performance Impact
- Optimize risk assessment frequency
- Cache device fingerprints
- Batch audit log writes
- Consider async policy evaluation

### Integration Problems
- Verify plugin load order
- Check event subscription setup
- Review shared data formats
- Monitor plugin communication

## Security Considerations

1. **Session Management**
   - Use secure session ID generation
   - Implement proper session invalidation
   - Protect against session fixation
   - Monitor for session hijacking

2. **Authentication Security**
   - Store passwords securely (bcrypt/scrypt)
   - Implement account lockout policies
   - Use secure MFA implementations
   - Protect against timing attacks

3. **Audit Log Protection**
   - Secure audit log storage
   - Implement log rotation
   - Protect against tampering
   - Consider remote logging

4. **Network Security**
   - Enforce TLS for all connections
   - Validate certificates properly
   - Implement mutual TLS where appropriate
   - Monitor for protocol downgrade attacks