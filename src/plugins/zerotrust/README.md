# Zero Trust Security Plugin

## Overview

The Zero Trust Security Plugin implements comprehensive Zero Trust Network Access (ZTNA) principles for the HKP (Hockeypuck) server. This plugin provides continuous authentication, risk-based access control, device profiling, and micro-segmentation to ensure that no entity is inherently trusted within the network perimeter.

Based on the "never trust, always verify" principle, this plugin continuously evaluates user identity, device posture, and behavioral patterns to make real-time access decisions.

## Key Features

### Core Security Features
- **Continuous Authentication**: Multi-factor authentication with adaptive challenges
- **Risk-Based Access Control**: Dynamic risk assessment with machine learning insights
- **Device Profiling & Fingerprinting**: Advanced device identification and trust scoring
- **Micro-Segmentation**: Network isolation based on user identity and device trust
- **Session Management**: Secure session handling with automatic timeout and termination
- **Behavioral Analytics**: Real-time monitoring of user and device behavior patterns

### Advanced Capabilities
- **Adaptive Policy Engine**: ML-driven policy adjustments based on threat landscape
- **Policy Engine Integration**: Dynamic policy updates based on risk patterns
- **Configurable Public Paths**: Flexible endpoint access control configuration
- **Comprehensive Audit Logging**: Detailed security event tracking and compliance reporting
- **Background Task Management**: Efficient goroutine lifecycle management using tomb.Tomb

## Configuration

### Basic Configuration

```toml
[plugins.zero-trust-security]
enabled = true
requireAuthentication = true
maxRiskScore = 0.7
sessionTimeout = "30m"
reevaluationInterval = "5m"
deviceFingerprintingLevel = "standard"
auditLevel = "detailed"
auditLogPath = "./logs"

# Configure which endpoints don't require authentication
publicPaths = [
    "/pks/lookup",
    "/pks/stats", 
    "/health",
    "/metrics",
    "/ratelimit/tarpit/status",
    "/ratelimit/ml/status",
    "/ratelimit/threatintel/status"
]
```

### Advanced Configuration

```toml
[plugins.zero-trust-security]
enabled = true
requireAuthentication = true
maxRiskScore = 0.7
sessionTimeout = "30m"
reevaluationInterval = "5m"
deviceFingerprintingLevel = "advanced"
auditLevel = "detailed"
auditLogPath = "./logs"

# Network Segmentation
[plugins.zero-trust-security.networkSegmentation]
enabled = true
defaultSegment = "untrusted"

[plugins.zero-trust-security.networkSegmentation.segmentPolicies.untrusted]
name = "Untrusted Zone"
allowedServices = ["/public/*"]
allowedMethods = ["GET"]
riskThreshold = 0.8
requireMFA = false

[plugins.zero-trust-security.networkSegmentation.segmentPolicies.trusted]
name = "Trusted Zone"
allowedServices = ["/*"]
allowedMethods = ["GET", "POST", "PUT", "DELETE"]
riskThreshold = 0.6
requireMFA = true

[plugins.zero-trust-security.networkSegmentation.segmentPolicies.admin]
name = "Administrative Zone"
allowedServices = ["/admin/*", "/api/admin/*"]
allowedMethods = ["GET", "POST", "PUT", "DELETE"]
riskThreshold = 0.3
requireMFA = true

# Service Mesh Integration
[plugins.zero-trust-security.networkSegmentation.serviceMesh]
enabled = true
trustedServices = ["hkp-core", "metrics-collector", "audit-service"]
mutualTLSRequired = true
serviceAuthTokenTTL = "1h"

# Adaptive Policies
[plugins.zero-trust-security.adaptivePolicies]
enabled = true
learningMode = true
policyUpdateInterval = "30m"
anomalyThreshold = 0.7
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable the plugin |
| `requireAuthentication` | boolean | `true` | Require authentication for protected endpoints |
| `maxRiskScore` | float | `0.7` | Maximum allowed risk score (0.0-1.0) |
| `sessionTimeout` | string | `"30m"` | Session timeout duration |
| `reevaluationInterval` | string | `"5m"` | How often to re-evaluate sessions |
| `deviceFingerprintingLevel` | string | `"standard"` | Device profiling level: basic, standard, advanced |
| `auditLevel` | string | `"detailed"` | Audit logging level: basic, standard, detailed |
| `auditLogPath` | string | `"./logs"` | Path for audit log files |
| `publicPaths` | []string | See config | List of endpoints that don't require authentication |

## API Endpoints

> **Implementation Status**: ✅ All Zero Trust endpoints listed below are currently implemented in the codebase.

### Authentication Endpoints

#### POST `/ztna/login`
Authenticate user and establish session.

**Request:**
```json
{
    "username": "user@example.com",
    "password": "secure_password",
    "device_id": "optional_device_identifier"
}
```

**Response (Success):**
```json
{
    "status": "success",
    "session_id": "sess_abc123def456",
    "trust_level": "high",
    "valid_until": "2024-01-01T12:00:00Z"
}
```

**Response (MFA Required):**
```json
{
    "status": "mfa_required",
    "session_id": "sess_abc123def456",
    "challenge": {
        "type": "totp",
        "challenge": "Enter TOTP code for user@example.com",
        "expires_at": "2024-01-01T11:05:00Z"
    }
}
```

#### POST `/ztna/verify`
Complete MFA verification or step-up authentication.

**Request:**
```json
{
    "type": "totp",
    "code": "123456"
}
```

**Response:**
```json
{
    "status": "verified",
    "trust_level": "high",
    "risk_score": 0.2
}
```

#### POST `/ztna/logout`
End user session.

**Headers:**
```
Cookie: ztna-session=sess_abc123def456
```

**Response:**
```json
{
    "status": "logged_out"
}
```

### Device Management

#### POST `/ztna/device`
Register or update device profile.

**Request:**
```json
{
    "platform": "linux",
    "screen_resolution": "1920x1080",
    "timezone": "UTC",
    "plugins": ["pdf", "flash"],
    "fonts": ["Arial", "Times New Roman"],
    "webgl_fingerprint": "abc123...",
    "canvas_fingerprint": "def456...",
    "audio_fingerprint": "ghi789..."
}
```

**Response:**
```json
{
    "status": "registered",
    "device_id": "dev_xyz789abc123",
    "trust": 0.85
}
```

### Status and Monitoring

#### GET `/ztna/status`
Get Zero Trust system status.

**Response:**
```json
{
    "enabled": true,
    "timestamp": "2024-01-01T12:00:00Z",
    "session": {
        "session_id": "sess_abc123def456",
        "user_id": "user@example.com",
        "trust_level": "high",
        "risk_score": 0.3,
        "segment": "trusted",
        "auth_factors": 2,
        "created_at": "2024-01-01T11:30:00Z",
        "last_activity": "2024-01-01T11:58:00Z"
    },
    "statistics": {
        "active_sessions": 15,
        "policy_count": 8,
        "segment_count": 3,
        "average_risk": 0.35,
        "high_risk_sessions": 2
    }
}
```

#### GET `/ztna/sessions` (Admin)
List active sessions (requires admin privileges).

#### GET `/ztna/policies` (Admin)
Get current security policies (requires admin privileges).

## Trust Levels and Risk Assessment

### Trust Levels

| Level | Score Range | Description | Access Granted |
|-------|-------------|-------------|----------------|
| **Very High** | 0.9 - 1.0 | Fully verified user with trusted device | All resources |
| **High** | 0.7 - 0.89 | Authenticated user, known device | Most resources |
| **Medium** | 0.5 - 0.69 | Authenticated user, some risk factors | Limited resources |
| **Low** | 0.3 - 0.49 | Authenticated but high risk | Public resources only |
| **Very Low** | 0.0 - 0.29 | Unauthenticated or very high risk | Denied access |

### Risk Assessment Factors

#### User Factors (Weight: 40%)
- Authentication method strength
- Recent authentication failures
- Account age and history
- Behavioral patterns
- Geographic location consistency

#### Device Factors (Weight: 35%)
- Device recognition and history
- Platform security posture
- Browser/client security features
- Device fingerprint consistency
- Jailbreak/root detection

#### Context Factors (Weight: 25%)
- Request time and frequency
- Geographic location
- Network reputation
- Resource sensitivity
- Session duration

### Risk Calculation

The risk score is calculated using a weighted algorithm:

```
Risk Score = (UserRisk × 0.4) + (DeviceRisk × 0.35) + (ContextRisk × 0.25)
```

## Security Policies

### Access Policies

Access policies define resource access based on trust levels and risk scores:

```json
{
    "id": "admin-access",
    "name": "Administrative Access",
    "resources": ["/admin/*", "/api/admin/*"],
    "required_trust_level": "high",
    "required_factors": ["password", "totp"],
    "max_risk_score": 0.3,
    "conditions": {
        "time_restrictions": ["09:00-17:00"],
        "location_restrictions": ["office", "vpn"],
        "device_requirements": ["managed", "encrypted"]
    }
}
```

### Adaptive Policies

When enabled, the system automatically adjusts policies based on:

- **Threat Intelligence**: External threat feeds and indicators
- **Behavioral Analytics**: User and device behavior patterns
- **Risk Trends**: Historical risk assessment data
- **Security Events**: Real-time security incident correlation

## Network Segmentation

### Micro-Segmentation Rules

The plugin supports fine-grained network segmentation:

#### Default Segments

1. **Untrusted Zone**
   - New or unrecognized devices
   - High-risk users or sessions
   - Limited access to public resources

2. **Trusted Zone**
   - Authenticated users with known devices
   - Standard access to most resources
   - Regular security re-evaluation

3. **Administrative Zone**
   - High-privilege users
   - Managed and compliant devices
   - Access to sensitive administrative functions

#### Service Mesh Integration

When integrated with a service mesh:

- **Mutual TLS**: Automatic certificate-based authentication
- **Service Authorization**: Token-based service-to-service auth
- **Traffic Encryption**: End-to-end encryption for all communications
- **Policy Enforcement**: Distributed policy enforcement at the mesh level

## Integration

### Middleware Integration

The plugin operates as HTTP middleware and can be integrated with various frameworks:

```go
// Integration example
func setupZeroTrust(router *mux.Router, plugin *zerotrust.ZeroTrustPlugin) {
    middleware, err := plugin.CreateMiddleware()
    if err != nil {
        log.Fatal(err)
    }
    router.Use(middleware)
}
```

### Event System

The plugin subscribes to security events:

- `security.threat.detected`: External threat detection events
- `ratelimit.violation`: Rate limiting violations
- `authentication.failure`: Authentication failures
- `device.suspicious`: Suspicious device behavior

### Logging Integration

All security events are logged with structured data:

```json
{
    "timestamp": "2024-01-01T12:00:00Z",
    "level": "INFO",
    "event": "access_granted",
    "user_id": "user@example.com",
    "session_id": "sess_abc123def456",
    "resource": "/api/users",
    "trust_level": "high",
    "risk_score": 0.25,
    "device_id": "dev_xyz789abc123",
    "client_ip": "192.168.1.100",
    "decision": "allow",
    "policy": "standard-access"
}
```

## Performance and Scalability

### Performance Metrics

| Metric | Typical Value | Target |
|--------|---------------|--------|
| Authentication latency | < 100ms | < 50ms |
| Risk assessment time | < 50ms | < 25ms |
| Session lookup time | < 10ms | < 5ms |
| Policy evaluation time | < 25ms | < 10ms |
| Memory usage per session | ~2KB | < 1KB |

### Scalability Considerations

- **Session Storage**: Supports pluggable session storage backends
- **Horizontal Scaling**: Stateless design supports load balancing
- **Cache Strategy**: Intelligent caching of risk assessments and policies
- **Background Processing**: Asynchronous policy updates and cleanup

## Best Practices

### Security Configuration

1. **Enable MFA**: Always require multi-factor authentication for sensitive resources
2. **Regular Re-evaluation**: Set short re-evaluation intervals for high-risk environments
3. **Device Management**: Implement device registration and compliance checking
4. **Audit Logging**: Enable detailed audit logging for compliance and forensics
5. **Policy Review**: Regularly review and update access policies

### Operational Guidelines

1. **Monitoring**: Set up alerts for high-risk sessions and policy violations
2. **Backup**: Regularly backup session data and policy configurations
3. **Testing**: Test policy changes in a staging environment first
4. **Documentation**: Maintain current documentation of policies and procedures

### Troubleshooting

#### Common Issues

**High CPU Usage:**
- Check adaptive policy update frequency
- Verify session cleanup intervals
- Monitor background task performance

**Memory Leaks:**
- Ensure proper session cleanup
- Check goroutine termination with tomb.Tomb
- Monitor device profile cache size

**Authentication Failures:**
- Verify MFA token synchronization
- Check password policy compliance
- Review rate limiting settings

#### Debug Logging

Enable debug logging for troubleshooting:

```toml
[plugins.zero-trust-security]
auditLevel = "debug"
```

This provides detailed information about:
- Risk score calculations
- Policy evaluations
- Session state changes
- Device profiling results

## Security Considerations

### Threat Model

The plugin addresses the following threats:

- **Credential Compromise**: Multi-factor authentication and behavioral monitoring
- **Device Compromise**: Device profiling and trust scoring
- **Session Hijacking**: Secure session management and re-evaluation
- **Privilege Escalation**: Fine-grained access controls and monitoring
- **Lateral Movement**: Micro-segmentation and service mesh integration

### Compliance

The plugin supports compliance with:

- **NIST Zero Trust Architecture**: Comprehensive implementation of NIST SP 800-207
- **SOC 2**: Detailed audit logging and access controls
- **ISO 27001**: Risk assessment and security monitoring
- **GDPR**: Privacy-compliant session and device data handling

## Migration and Deployment

### Migration from Traditional Security

1. **Phase 1**: Deploy in monitoring mode alongside existing security
2. **Phase 2**: Enable authentication for non-critical resources
3. **Phase 3**: Gradually expand to all resources
4. **Phase 4**: Enable adaptive policies and full Zero Trust

### Production Deployment

- **Load Testing**: Verify performance under expected load
- **Gradual Rollout**: Deploy to small user groups first
- **Monitoring**: Set up comprehensive monitoring and alerting
- **Rollback Plan**: Prepare for quick rollback if issues occur

## Version History

- **v1.0.0**: Initial release with core Zero Trust features
  - Continuous authentication and risk assessment
  - Device profiling and fingerprinting
  - Basic micro-segmentation
  - Audit logging and session management
  - Tomb.Tomb integration for reliable goroutine management
  - Configurable public paths support