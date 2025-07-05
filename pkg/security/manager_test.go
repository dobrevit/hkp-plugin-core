package security_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/security"
)

// TestSecurityManagerDefaultConfig tests the default security configuration
func TestSecurityManagerDefaultConfig(t *testing.T) {
	config := security.DefaultSecurityConfig()

	if !config.RequireSignature {
		t.Error("Expected signature requirement in default config")
	}

	if config.EnforcementLevel != security.EnforcementStrict {
		t.Error("Expected strict enforcement in default config")
	}

	if config.AllowSelfSigned {
		t.Error("Expected self-signed certificates to be disallowed by default")
	}

	if len(config.AllowedAlgorithms) == 0 {
		t.Error("Expected allowed algorithms to be configured")
	}

	if config.VerificationCacheTTL == 0 {
		t.Error("Expected non-zero cache TTL")
	}
}

// TestSecurityManagerWithSandbox tests security manager with sandbox enabled
func TestSecurityManagerWithSandbox(t *testing.T) {
	// Skip if not root
	if os.Getuid() != 0 {
		t.Skip("Sandbox tests require root privileges")
	}

	tempDir := t.TempDir()

	sandboxConfig := security.DefaultSandboxConfig()
	sandboxConfig.CGroupRoot = filepath.Join(tempDir, "cgroup")

	config := &security.SecurityConfig{
		RequireSignature:     false,
		EnforcementLevel:     security.EnforcementPermissive,
		TrustedCertificates:  []string{},
		CertificateStorePath: filepath.Join(tempDir, "certs"),
		AuditLogPath:         filepath.Join(tempDir, "audit.log"),
		VerificationCacheTTL: time.Minute,
		AllowSelfSigned:      true,
		AllowedAlgorithms:    []security.SignatureAlgorithm{security.AlgorithmEd25519},
		SandboxConfig:        sandboxConfig,
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager, err := security.NewSecurityManager(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security manager with sandbox: %v", err)
	}
	defer manager.Close()

	// Verify sandbox is enabled in status
	status := manager.GetSecurityStatus()
	if status["sandbox_enabled"] != true {
		t.Error("Expected sandbox to be enabled")
	}
}

// TestCertificateValidation tests certificate validation
func TestCertificateValidation(t *testing.T) {
	tempDir := t.TempDir()

	config := &security.SecurityConfig{
		RequireSignature:     true,
		EnforcementLevel:     security.EnforcementStrict,
		TrustedCertificates:  []string{filepath.Join(tempDir, "trusted.crt")},
		CertificateStorePath: filepath.Join(tempDir, "certs"),
		AuditLogPath:         filepath.Join(tempDir, "audit.log"),
		VerificationCacheTTL: time.Minute,
		AllowSelfSigned:      false,
		AllowedAlgorithms:    []security.SignatureAlgorithm{security.AlgorithmEd25519},
		SandboxConfig:        nil,
	}

	// Create a fake trusted certificate file
	os.WriteFile(filepath.Join(tempDir, "trusted.crt"), []byte("fake cert"), 0644)

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager, err := security.NewSecurityManager(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security manager: %v", err)
	}
	defer manager.Close()

	// Try to load a plugin with strict enforcement
	result, err := manager.CheckPluginSecurity(filepath.Join(tempDir, "plugin.so"))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should not be allowed without proper signature
	if result.Allowed {
		t.Error("Plugin should not be allowed without valid signature in strict mode")
	}
}

// TestPluginVerifierHelpers tests helper methods in plugin verifier
func TestPluginVerifierHelpers(t *testing.T) {
	tempDir := t.TempDir()

	auditLogger, _ := security.NewFileSecurityAuditLogger(filepath.Join(tempDir, "audit.log"))
	defer auditLogger.Close()

	certStore, _ := security.NewFileCertificateStore(filepath.Join(tempDir, "certs"), auditLogger)
	verifier := security.NewPluginVerifier(certStore, auditLogger)

	// Create a test plugin with metadata
	pluginPath := filepath.Join(tempDir, "test.so")
	metadataPath := pluginPath + ".metadata"

	// Write plugin file
	os.WriteFile(pluginPath, []byte("fake plugin"), 0644)

	// Write metadata file with valid JSON
	metadata := `{
		"name": "test-plugin",
		"version": "1.0.0",
		"author": "test",
		"signature_algorithm": "Ed25519"
	}`
	os.WriteFile(metadataPath, []byte(metadata), 0644)

	// Verify plugin with metadata
	result, err := verifier.VerifyPlugin(pluginPath)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should still fail (no valid signature) but should process metadata
	if result.Valid {
		t.Error("Plugin should not be valid without proper signature")
	}
}

// TestSecurityConstants verifies security constants are properly defined
func TestSecurityConstants(t *testing.T) {
	// Test that severity levels are defined
	if security.SeverityInfo == "" {
		t.Error("SeverityInfo should not be empty")
	}
	if security.SeverityWarning == "" {
		t.Error("SeverityWarning should not be empty")
	}
	if security.SeverityError == "" {
		t.Error("SeverityError should not be empty")
	}
	if security.SeverityCritical == "" {
		t.Error("SeverityCritical should not be empty")
	}

	// Test enforcement levels
	if security.EnforcementStrict == "" {
		t.Error("EnforcementStrict should not be empty")
	}
	if security.EnforcementPermissive == "" {
		t.Error("EnforcementPermissive should not be empty")
	}
}
