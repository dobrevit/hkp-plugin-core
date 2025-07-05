# Security Package

The security package provides comprehensive plugin verification, digital signature validation, and security audit logging for the HKP plugin system.

## Overview

This package implements enterprise-grade security measures to ensure plugin integrity, authenticity, and runtime safety through digital signatures, certificate chain validation, and comprehensive audit logging.

## Components

### Core Files

- **`verification.go`** - Core verification engine with signature validation
- **`sandbox.go`** - Plugin sandboxing using cgroups and seccomp
- **`audit.go`** - Security audit logging and event tracking
- **`certificates.go`** - Certificate management and chain validation
- **`manager.go`** - Central security manager coordinating all components
- **`alerts.go`** - Security alerting and notification system
- **`integration_test.go`** - Comprehensive security testing

## Key Features

### Digital Signature Verification

```go
verifier := security.NewPluginVerifier(&security.VerificationConfig{
    RequireSignature: true,
    TrustedKeys: []string{"path/to/trusted.pub"},
    SignatureAlgorithms: []security.SignatureAlgorithm{
        security.SignatureAlgorithmRSA4096,
        security.SignatureAlgorithmEd25519,
    },
})

result, err := verifier.VerifyPlugin("plugin.so")
```

### Plugin Sandboxing

```go
sandboxManager := security.NewSandboxManager(&security.SandboxConfig{
    EnableCgroups: true,
    EnableSeccomp: true,
    ResourceLimits: &security.ResourceLimits{
        MaxMemoryMB: 256,
        MaxCPUPercent: 50,
    },
})

err := sandboxManager.SandboxPlugin("plugin-name", 12345)
```

### Security Audit Logging

```go
auditLogger := security.NewSecurityAuditLogger()
auditLogger.LogPluginSecurityViolation("plugin-name", "signature_invalid", details)
```

## Configuration

### Verification Configuration

```go
type VerificationConfig struct {
    RequireSignature    bool
    TrustedKeys        []string
    SignatureAlgorithms []SignatureAlgorithm
    CertificateChains  []string
    RequireCertificate bool
    MaxCertChainLength int
    EnableCRL          bool
    CRLEndpoints       []string
    VerificationTimeout time.Duration
}
```

### Sandbox Configuration

```go
type SandboxConfig struct {
    EnableCgroups     bool
    EnableSeccomp     bool
    CgroupsVersion    string
    ResourceLimits    *ResourceLimits
    AllowedSyscalls   []string
    BlockedSyscalls   []string
    NetworkPolicy     NetworkPolicy
    FilesystemPolicy  FilesystemPolicy
}
```

## Signature Algorithms Supported

- **RSA-2048** - Standard RSA with 2048-bit keys
- **RSA-4096** - Enhanced RSA with 4096-bit keys
- **Ed25519** - Modern elliptic curve signature algorithm
- **ECDSA P-256** - NIST P-256 elliptic curve
- **ECDSA P-384** - NIST P-384 elliptic curve

## Security Manager Integration

The security manager coordinates all security components:

```go
manager := security.NewSecurityManager(&security.SecurityConfig{
    Verification: verificationConfig,
    Sandbox:     sandboxConfig,
    Audit:       auditConfig,
    Alerts:      alertConfig,
})

// Comprehensive security check
result, err := manager.SecurePlugin("plugin.so", config)
```

## Audit Events

The system logs various security events:

- Plugin signature verification results
- Certificate validation outcomes
- Sandbox policy violations
- Resource limit breaches
- Security configuration changes
- Plugin loading/unloading events

## Testing

The package includes comprehensive tests:

```bash
go test ./pkg/security -v
```

Tests cover:
- Signature verification with multiple algorithms
- Certificate chain validation
- Sandbox enforcement
- Audit logging functionality
- Error handling scenarios

## Dependencies

- `crypto/rsa` - RSA signature verification
- `crypto/ed25519` - Ed25519 signature verification
- `crypto/x509` - Certificate handling
- `golang.org/x/sys/unix` - Linux cgroups and seccomp
- `log/slog` - Structured logging

## Security Considerations

1. **Private Key Protection** - Signing keys must be stored securely
2. **Certificate Validation** - Always validate certificate chains
3. **Sandbox Escapes** - Monitor for sandbox bypass attempts
4. **Audit Integrity** - Protect audit logs from tampering
5. **Resource Monitoring** - Watch for resource exhaustion attacks

## Future Enhancements

- Hardware Security Module (HSM) integration
- Advanced threat detection using ML
- Automated security policy generation
- Integration with external PKI systems
- Real-time security dashboards