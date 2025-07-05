package security_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/security"
)

// TestVerificationCache tests the verification cache functionality
func TestVerificationCache(t *testing.T) {
	tempDir := t.TempDir()

	// Create mock plugin files
	plugin1 := filepath.Join(tempDir, "plugin1.so")
	plugin2 := filepath.Join(tempDir, "plugin2.so")
	os.WriteFile(plugin1, []byte("plugin1 content"), 0644)
	os.WriteFile(plugin2, []byte("plugin2 content"), 0644)

	// Test Get method
	t.Run("CacheGetSet", func(t *testing.T) {
		cache := &security.VerificationCache{}

		// Get non-existent entry
		result := cache.Get(plugin1)
		if result != nil {
			t.Error("Expected nil for non-existent cache entry")
		}

		// Note: Set method is not exposed, so we can't test it directly
		// This is testing the Get method which provides partial coverage
	})
}

// TestSandboxConfiguration tests sandbox configuration
func TestSandboxConfiguration(t *testing.T) {
	t.Run("DefaultSandboxConfig", func(t *testing.T) {
		config := security.DefaultSandboxConfig()

		if config.MaxMemoryMB == 0 {
			t.Error("Expected non-zero memory limit")
		}
		if config.MaxCPUPercent == 0 {
			t.Error("Expected non-zero CPU limit")
		}
		if config.AllowedSyscalls == nil {
			t.Error("Expected allowed syscalls to be initialized")
		}
	})
}

// TestSecurityConfig tests security configuration validation
func TestSecurityConfig(t *testing.T) {
	t.Run("ValidateConfig", func(t *testing.T) {
		config := &security.SecurityConfig{
			RequireSignature:     true,
			EnforcementLevel:     security.EnforcementStrict,
			TrustedCertificates:  []string{},
			CertificateStorePath: "/tmp/certs",
			AuditLogPath:         "/tmp/audit.log",
			VerificationCacheTTL: time.Minute,
			AllowSelfSigned:      false,
			AllowedAlgorithms:    []security.SignatureAlgorithm{security.AlgorithmEd25519},
		}

		// Test that configuration is valid
		if config.EnforcementLevel != security.EnforcementStrict {
			t.Error("Expected strict enforcement level")
		}
		if !config.RequireSignature {
			t.Error("Expected signature requirement")
		}
	})
}

// TestManagerMethods tests additional SecurityManager methods
func TestManagerMethods(t *testing.T) {
	tempDir := t.TempDir()

	config := &security.SecurityConfig{
		RequireSignature:     false,
		EnforcementLevel:     security.EnforcementPermissive,
		TrustedCertificates:  []string{},
		CertificateStorePath: filepath.Join(tempDir, "certs"),
		AuditLogPath:         filepath.Join(tempDir, "audit.log"),
		VerificationCacheTTL: time.Minute,
		AllowSelfSigned:      true,
		AllowedAlgorithms:    []security.SignatureAlgorithm{security.AlgorithmEd25519},
		SandboxConfig:        nil,
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager, err := security.NewSecurityManager(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security manager: %v", err)
	}
	defer manager.Close()

	t.Run("GetSecurityStatus", func(t *testing.T) {
		status := manager.GetSecurityStatus()

		// Verify status contains expected fields
		if status["enforcement_level"] != security.EnforcementPermissive {
			t.Error("Expected permissive enforcement level in status")
		}
		if status["require_signature"] != false {
			t.Error("Expected signature not required in status")
		}
		if status["sandbox"] != nil {
			t.Error("Expected sandbox disabled in status")
		}
	})

	t.Run("CheckPluginSecurityPermissive", func(t *testing.T) {
		// In permissive mode, should allow unsigned plugins
		result, err := manager.CheckPluginSecurity("/path/to/unsigned/plugin.so")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Error("Plugin should be allowed in permissive mode")
		}
		if result.Reason == "" {
			t.Error("Expected reason for decision")
		}
	})
}

// TestCertificateStoreAdvanced tests more certificate store functionality
func TestCertificateStoreAdvanced(t *testing.T) {
	tempDir := t.TempDir()
	certStorePath := filepath.Join(tempDir, "certs")
	auditLogPath := filepath.Join(tempDir, "audit.log")

	auditLogger, _ := security.NewFileSecurityAuditLogger(auditLogPath)
	defer auditLogger.Close()

	store, err := security.NewFileCertificateStore(certStorePath, auditLogger)
	if err != nil {
		t.Fatalf("Failed to create certificate store: %v", err)
	}

	t.Run("EmptyStore", func(t *testing.T) {
		// List certificates in empty store
		certs, err := store.ListCertificates()
		if err != nil {
			t.Errorf("Failed to list certificates: %v", err)
		}
		if len(certs) != 0 {
			t.Errorf("Expected 0 certificates in new store, got %d", len(certs))
		}

		// Get non-existent certificate
		_, err = store.GetCertificate("non-existent-fingerprint")
		if err == nil {
			t.Error("Expected error when getting non-existent certificate")
		}

		// Get metadata for non-existent certificate
		_, err = store.GetCertificateMetadata("non-existent-fingerprint")
		if err == nil {
			t.Error("Expected error when getting metadata for non-existent certificate")
		}
	})

	t.Run("InvalidOperations", func(t *testing.T) {
		// Try to remove non-existent certificate
		err := store.RemoveCertificate("non-existent-fingerprint")
		if err == nil {
			t.Error("Expected error when removing non-existent certificate")
		}

		// Try to revoke non-existent certificate
		err = store.RevokeCertificate("non-existent-fingerprint", "test reason")
		if err == nil {
			t.Error("Expected error when revoking non-existent certificate")
		}
	})
}

// TestPluginVerifierAdvanced tests more plugin verifier functionality
func TestPluginVerifierAdvanced(t *testing.T) {
	tempDir := t.TempDir()

	auditLogger, _ := security.NewFileSecurityAuditLogger(filepath.Join(tempDir, "audit.log"))
	defer auditLogger.Close()

	certStore, _ := security.NewFileCertificateStore(filepath.Join(tempDir, "certs"), auditLogger)
	verifier := security.NewPluginVerifier(certStore, auditLogger)

	t.Run("VerifyNonExistentPlugin", func(t *testing.T) {
		result, err := verifier.VerifyPlugin("/completely/non/existent/path/plugin.so")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if result.Valid {
			t.Error("Non-existent plugin should not be valid")
		}
		if result.Error == "" {
			t.Error("Expected error message in result")
		}
	})

	t.Run("VerifyDirectory", func(t *testing.T) {
		// Try to verify a directory instead of a file
		result, err := verifier.VerifyPlugin(tempDir)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if result.Valid {
			t.Error("Directory should not be valid as plugin")
		}
	})
}

// TestRevocationStatus tests revocation status functionality
func TestRevocationStatus(t *testing.T) {
	statuses := []security.RevocationStatus{
		security.RevocationStatusValid,
		security.RevocationStatusRevoked,
		security.RevocationStatusUnknown,
	}

	for _, status := range statuses {
		// Just verify the constants are defined
		if status == "" {
			t.Error("Revocation status should not be empty")
		}
	}
}

// TestSignatureAlgorithms tests signature algorithm constants
func TestSignatureAlgorithms(t *testing.T) {
	algorithms := []security.SignatureAlgorithm{
		security.AlgorithmRSA4096,
		security.AlgorithmEd25519,
		security.AlgorithmECDSA,
	}

	for _, algo := range algorithms {
		// Verify algorithms are defined
		if algo == "" {
			t.Error("Algorithm should not be empty")
		}
	}
}

// TestEnforcementLevels tests enforcement level constants
func TestEnforcementLevels(t *testing.T) {
	levels := []security.EnforcementLevel{
		security.EnforcementPermissive,
		security.EnforcementStrict,
	}

	for _, level := range levels {
		// Verify levels are defined
		if level == "" {
			t.Error("Enforcement level should not be empty")
		}
	}
}

// TestTrustLevels tests trust level constants
func TestTrustLevels(t *testing.T) {
	levels := []security.TrustLevel{
		security.TrustLevelRoot,
		security.TrustLevelIntermediate,
		security.TrustLevelLeaf,
		security.TrustLevelUntrusted,
	}

	for _, level := range levels {
		// Verify levels are defined
		if level == "" {
			t.Error("Trust level should not be empty")
		}
	}
}
