# HKP Plugin API Endpoints Documentation

## Overview
This document lists all HTTP endpoints exposed by the HKP plugin system and its plugins.

## Core Application Endpoints

### HKP Server Endpoints
- **POST** `/pks/add` - Submit a PGP key
- **GET** `/pks/lookup` - Lookup a PGP key
- **GET** `/pks/stats` - Server statistics
- **GET** `/metrics` - Prometheus metrics

## Plugin Endpoints

### 1. Zero Trust Security Plugin (`zerotrust`)

#### Configuration
The Zero Trust plugin supports configurable public paths that don't require authentication:
```json
{
  "publicPaths": [
    "/pks/lookup",
    "/pks/stats", 
    "/health",
    "/metrics",
    "/ratelimit/tarpit/status",
    "/ratelimit/ml/status",
    "/ratelimit/threatintel/status"
  ]
}
```

#### Authentication & Session Management
- **POST** `/ztna/login` - User authentication
  - Request: `{"username": "string", "password": "string", "device_id": "string"}`
  - Response: `{"status": "success|mfa_required", "session_id": "string", "trust_level": "string", "challenge": {...}}`

- **POST** `/ztna/logout` - End user session
  - Headers: `Cookie: ztna-session=<session_id>`
  - Response: `{"status": "logged_out"}`

- **POST** `/ztna/verify` - MFA/step-up authentication
  - Request: `{"type": "totp|email|sms", "code": "string"}`
  - Response: `{"status": "verified", "trust_level": "string", "risk_score": float}`

#### Device Management
- **POST** `/ztna/device` - Register device
  - Request: Device fingerprint data
  - Response: `{"status": "registered", "device_id": "string", "trust": float}`

#### Status & Monitoring
- **GET** `/ztna/status` - ZTNA system status
  - Response: System status including session info and statistics

- **GET** `/ztna/sessions` - Active sessions (admin)
- **GET** `/ztna/policies` - Policy information (admin)

### 2. ML Abuse Detection Plugin (`mlabuse`)

- **GET** `/api/ml/status` - ML system status
  - Response: `{"status": "string", "models_loaded": int, "requests_analyzed": int}`

- **GET** `/api/ml/metrics` - ML metrics and statistics
  - Response: Detailed metrics about detection rates, model performance

- **POST** `/api/ml/analyze` - Analyze request for abuse
  - Request: `{"request_data": {...}, "context": {...}}`
  - Response: `{"is_abuse": bool, "confidence": float, "reasons": [...]}`

### 3. Rate Limit Threat Intelligence Plugin (`ratelimit-threat`)

- **GET** `/ratelimit/threatintel/status` - Threat intel status
  - Response: `{"enabled": bool, "sources": [...], "last_update": "timestamp"}`

- **POST** `/ratelimit/threatintel/check` - Check IP reputation
  - Request: `{"ip": "string"}`
  - Response: `{"is_threat": bool, "threat_level": "string", "sources": [...]}`

- **POST** `/ratelimit/threatintel/report` - Report threat
  - Request: `{"ip": "string", "type": "string", "details": {...}}`
  - Response: `{"status": "reported"}`

### 4. Rate Limit Tarpit Plugin (`ratelimit-tarpit`)

- **GET** `/ratelimit/tarpit/status` - Tarpit status
  - Response: `{"enabled": bool, "active_connections": int, "total_trapped": int}`

- **GET** `/ratelimit/tarpit/connections` - Active tarpit connections
  - Response: List of currently trapped connections

#### Honeypot Paths (configurable)
Default honeypot paths that trigger tarpit:
- `/admin`
- `/wp-admin`
- `/.git`
- `/.env`
- `/phpmyadmin`
- `/api/v1/users`
- `/backup.sql`

### 5. Rate Limit ML Extension Plugin (`ratelimit-ml`)

- **GET** `/ratelimit/ml/status` - ML rate limiting status
  - Response: `{"enabled": bool, "model_version": "string", "patterns_detected": int}`

- **GET** `/ratelimit/ml/patterns` - Pattern analysis
  - Response: Detected traffic patterns and anomalies

## Middleware-Only Plugins

The following plugins operate as middleware and don't expose HTTP endpoints:

### Geographic Rate Limiting Plugin (`ratelimit-geo`)
- Intercepts all requests for geographic-based rate limiting
- No direct HTTP endpoints

### Anti-Abuse Plugin (`antiabuse`)
- Monitors all requests for abuse patterns
- No direct HTTP endpoints

## Testing Endpoints

To test all endpoints are working:
1. Start the server with all plugins loaded
2. Use the test suite or manual curl commands
3. Check plugin logs for middleware activity