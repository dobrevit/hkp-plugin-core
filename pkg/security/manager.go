package security

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// SecurityManager coordinates all security operations for plugins
type SecurityManager struct {
	verifier         *PluginVerifier
	certStore        CertificateStore
	auditLogger      SecurityAuditLogger
	sandboxManager   *SandboxManager
	config           *SecurityConfig
	enforcementLevel EnforcementLevel
	mutex            sync.RWMutex
	logger           *slog.Logger
}

// SecurityConfig contains security configuration
type SecurityConfig struct {
	RequireSignature     bool                 `json:"require_signature"`
	EnforcementLevel     EnforcementLevel     `json:"enforcement_level"`
	TrustedCertificates  []string             `json:"trusted_certificates"`
	CertificateStorePath string               `json:"certificate_store_path"`
	AuditLogPath         string               `json:"audit_log_path"`
	VerificationCacheTTL time.Duration        `json:"verification_cache_ttl"`
	AllowSelfSigned      bool                 `json:"allow_self_signed"`
	RequiredKeyUsage     []x509.KeyUsage      `json:"required_key_usage"`
	MinKeySize           int                  `json:"min_key_size"`
	AllowedAlgorithms    []SignatureAlgorithm `json:"allowed_algorithms"`
	SandboxConfig        *SandboxConfig       `json:"sandbox_config"`
}

// EnforcementLevel determines how strictly security policies are enforced
type EnforcementLevel string

const (
	EnforcementPermissive EnforcementLevel = "permissive" // Log violations but allow
	EnforcementWarning    EnforcementLevel = "warning"    // Log violations and warn
	EnforcementStrict     EnforcementLevel = "strict"     // Block violations
	EnforcementBlocking   EnforcementLevel = "blocking"   // Block and terminate
)

// SecurityCheckResult represents the result of a security check
type SecurityCheckResult struct {
	Allowed      bool                `json:"allowed"`
	Reason       string              `json:"reason,omitempty"`
	Verification *VerificationResult `json:"verification,omitempty"`
	Violations   []SecurityViolation `json:"violations,omitempty"`
	Timestamp    time.Time           `json:"timestamp"`
}

// SecurityViolation represents a security policy violation
type SecurityViolation struct {
	Type        string                 `json:"type"`
	Severity    SeverityLevel          `json:"severity"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details"`
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(config *SecurityConfig, logger *slog.Logger) (*SecurityManager, error) {
	// Create audit logger
	auditLogger, err := NewFileSecurityAuditLogger(config.AuditLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Create certificate store
	certStore, err := NewFileCertificateStore(config.CertificateStorePath, auditLogger)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate store: %w", err)
	}

	// Create plugin verifier
	verifier := NewPluginVerifier(certStore, auditLogger)

	// Create sandbox manager if configured
	var sandboxManager *SandboxManager
	if config.SandboxConfig != nil {
		sandboxManager, err = NewSandboxManager(config.SandboxConfig, auditLogger, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create sandbox manager: %w", err)
		}
	}

	// Load trusted certificates
	if err := loadTrustedCertificates(certStore, config.TrustedCertificates); err != nil {
		logger.Warn("failed to load some trusted certificates", "error", err)
	}

	return &SecurityManager{
		verifier:         verifier,
		certStore:        certStore,
		auditLogger:      auditLogger,
		sandboxManager:   sandboxManager,
		config:           config,
		enforcementLevel: config.EnforcementLevel,
		logger:           logger,
	}, nil
}

// CheckPluginSecurity performs comprehensive security check on a plugin
func (sm *SecurityManager) CheckPluginSecurity(pluginPath string) (*SecurityCheckResult, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	result := &SecurityCheckResult{
		Timestamp:  time.Now(),
		Violations: make([]SecurityViolation, 0),
	}

	// Skip security checks if enforcement is permissive and signature not required
	if sm.enforcementLevel == EnforcementPermissive && !sm.config.RequireSignature {
		result.Allowed = true
		result.Reason = "security checks disabled in permissive mode"
		return result, nil
	}

	// Verify plugin signature
	verification, err := sm.verifier.VerifyPlugin(pluginPath)
	if err != nil {
		result.Allowed = false
		result.Reason = fmt.Sprintf("verification failed: %v", err)
		return result, err
	}

	result.Verification = verification

	// Check signature requirement
	if sm.config.RequireSignature && !verification.Valid {
		violation := SecurityViolation{
			Type:        "unsigned_plugin",
			Severity:    SeverityCritical,
			Description: "Plugin is not properly signed",
			Details: map[string]interface{}{
				"plugin_path": pluginPath,
				"error":       verification.Error,
			},
		}
		result.Violations = append(result.Violations, violation)
	}

	// Check algorithm requirements
	if verification.Valid {
		if err := sm.checkAlgorithmCompliance(verification.Algorithm); err != nil {
			violation := SecurityViolation{
				Type:        "algorithm_violation",
				Severity:    SeverityWarning,
				Description: err.Error(),
				Details: map[string]interface{}{
					"algorithm": verification.Algorithm,
				},
			}
			result.Violations = append(result.Violations, violation)
		}

		// Check certificate compliance
		if verification.Certificate != nil {
			if err := sm.checkCertificateCompliance(verification.Certificate); err != nil {
				violation := SecurityViolation{
					Type:        "certificate_violation",
					Severity:    SeverityWarning,
					Description: err.Error(),
					Details: map[string]interface{}{
						"certificate": verification.Certificate,
					},
				}
				result.Violations = append(result.Violations, violation)
			}
		}

		// Check revocation status
		if verification.RevocationStatus == RevocationStatusRevoked {
			violation := SecurityViolation{
				Type:        "revoked_certificate",
				Severity:    SeverityCritical,
				Description: "Plugin signed with revoked certificate",
				Details: map[string]interface{}{
					"certificate": verification.Certificate,
				},
			}
			result.Violations = append(result.Violations, violation)
		}
	}

	// Determine if plugin should be allowed based on enforcement level and violations
	result.Allowed = sm.determineAllowance(result.Violations)

	// Log security violations
	for _, violation := range result.Violations {
		sm.auditLogger.LogPluginSecurityViolation(pluginPath, violation.Type, violation.Details)
	}

	return result, nil
}

// checkAlgorithmCompliance verifies the signature algorithm meets requirements
func (sm *SecurityManager) checkAlgorithmCompliance(algorithm SignatureAlgorithm) error {
	if len(sm.config.AllowedAlgorithms) == 0 {
		return nil // No restrictions
	}

	for _, allowed := range sm.config.AllowedAlgorithms {
		if algorithm == allowed {
			return nil
		}
	}

	return fmt.Errorf("signature algorithm %s is not allowed", algorithm)
}

// checkCertificateCompliance verifies certificate meets security requirements
func (sm *SecurityManager) checkCertificateCompliance(cert *CertificateInfo) error {
	// Check expiration
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}

	// Check key usage
	if len(sm.config.RequiredKeyUsage) > 0 {
		hasCodeSigning := false
		for _, usage := range cert.KeyUsage {
			if usage == "code_signing" {
				hasCodeSigning = true
				break
			}
		}
		if !hasCodeSigning {
			return fmt.Errorf("certificate does not have code signing capability")
		}
	}

	return nil
}

// determineAllowance determines if a plugin should be allowed based on violations and enforcement level
func (sm *SecurityManager) determineAllowance(violations []SecurityViolation) bool {
	if len(violations) == 0 {
		return true
	}

	switch sm.enforcementLevel {
	case EnforcementPermissive:
		return true // Allow but log

	case EnforcementWarning:
		// Allow unless there are critical violations
		for _, violation := range violations {
			if violation.Severity == SeverityCritical {
				return false
			}
		}
		return true

	case EnforcementStrict, EnforcementBlocking:
		// Block if any violations
		return false

	default:
		return false
	}
}

// AddTrustedCertificate adds a trusted certificate to the store
func (sm *SecurityManager) AddTrustedCertificate(cert *x509.Certificate, trustLevel TrustLevel) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	metadata := &CertificateMetadata{
		AddedAt:    time.Now(),
		AddedBy:    "security_manager",
		TrustLevel: trustLevel,
		Attributes: make(map[string]interface{}),
	}

	if fileCertStore, ok := sm.certStore.(*FileCertificateStore); ok {
		return fileCertStore.AddCertificateWithMetadata(cert, metadata)
	}

	return sm.certStore.AddCertificate(cert)
}

// RevokeCertificate revokes a certificate
func (sm *SecurityManager) RevokeCertificate(fingerprint string, reason string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if fileCertStore, ok := sm.certStore.(*FileCertificateStore); ok {
		return fileCertStore.RevokeCertificate(fingerprint, reason)
	}

	return fmt.Errorf("certificate revocation not supported by current store")
}

// GetTrustedCertificates returns all trusted certificates
func (sm *SecurityManager) GetTrustedCertificates() ([]*x509.Certificate, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	return sm.certStore.ListCertificates()
}

// UpdateEnforcementLevel updates the security enforcement level
func (sm *SecurityManager) UpdateEnforcementLevel(level EnforcementLevel) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	oldLevel := sm.enforcementLevel
	sm.enforcementLevel = level

	sm.auditLogger.LogSecurityEvent("enforcement_level_changed", map[string]interface{}{
		"old_level": oldLevel,
		"new_level": level,
	})
}

// GetSecurityStatus returns current security system status
func (sm *SecurityManager) GetSecurityStatus() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	certs, _ := sm.certStore.ListCertificates()

	status := map[string]interface{}{
		"enforcement_level":    sm.enforcementLevel,
		"require_signature":    sm.config.RequireSignature,
		"trusted_certificates": len(certs),
		"verification_enabled": true,
		"audit_logging":        true,
		"allowed_algorithms":   sm.config.AllowedAlgorithms,
		"cache_ttl":            sm.config.VerificationCacheTTL.String(),
	}

	// Add sandbox status if enabled
	if sm.sandboxManager != nil {
		status["sandbox"] = sm.sandboxManager.GetSandboxStatus()
	}

	return status
}

// Close gracefully shuts down the security manager
func (sm *SecurityManager) Close() error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if fileAuditLogger, ok := sm.auditLogger.(*FileSecurityAuditLogger); ok {
		return fileAuditLogger.Close()
	}

	return nil
}

// CreatePluginSandbox creates a sandbox for a plugin
func (sm *SecurityManager) CreatePluginSandbox(pluginName string) (*SandboxedProcess, error) {
	if sm.sandboxManager == nil {
		return nil, fmt.Errorf("sandbox manager not enabled")
	}

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	return sm.sandboxManager.CreateSandbox(pluginName)
}

// RunPluginInSandbox executes a plugin in its sandbox
func (sm *SecurityManager) RunPluginInSandbox(sandbox *SandboxedProcess, command string, args []string) error {
	if sm.sandboxManager == nil {
		return fmt.Errorf("sandbox manager not enabled")
	}

	return sm.sandboxManager.RunInSandbox(sandbox, command, args)
}

// DestroyPluginSandbox destroys a plugin sandbox
func (sm *SecurityManager) DestroyPluginSandbox(sandbox *SandboxedProcess) error {
	if sm.sandboxManager == nil {
		return fmt.Errorf("sandbox manager not enabled")
	}

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	return sm.sandboxManager.DestroySandbox(sandbox)
}

// Helper functions

// loadTrustedCertificates loads trusted certificates from file paths
func loadTrustedCertificates(certStore CertificateStore, certPaths []string) error {
	for _, certPath := range certPaths {
		if err := loadCertificateFromFile(certStore, certPath); err != nil {
			return fmt.Errorf("failed to load certificate %s: %w", certPath, err)
		}
	}
	return nil
}

// loadCertificateFromFile loads a certificate from a PEM file
func loadCertificateFromFile(certStore CertificateStore, certPath string) error {
	// Implementation would read PEM file and parse certificate
	// For now, this is a placeholder
	return fmt.Errorf("certificate loading from file not implemented")
}

// DefaultSecurityConfig returns a default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		RequireSignature:     true,
		EnforcementLevel:     EnforcementStrict,
		TrustedCertificates:  []string{},
		CertificateStorePath: "./certs",
		AuditLogPath:         "./logs/security_audit.log",
		VerificationCacheTTL: time.Hour,
		AllowSelfSigned:      false,
		RequiredKeyUsage:     []x509.KeyUsage{x509.KeyUsageDigitalSignature},
		MinKeySize:           2048,
		AllowedAlgorithms:    []SignatureAlgorithm{AlgorithmEd25519, AlgorithmRSA4096},
	}
}
