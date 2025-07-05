package security_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/security"
)

// TestFileSecurityAuditLogger tests the file-based security audit logger
func TestFileSecurityAuditLogger(t *testing.T) {
	tempDir := t.TempDir()
	auditLogPath := filepath.Join(tempDir, "audit.log")

	logger, err := security.NewFileSecurityAuditLogger(auditLogPath)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer logger.Close()

	// Test LogSecurityEvent
	t.Run("LogSecurityEvent", func(t *testing.T) {
		details := map[string]interface{}{
			"user":     "test-user",
			"action":   "login",
			"severity": security.SeverityInfo,
		}
		logger.LogSecurityEvent("user_login", details)

		// Test with warning severity
		details["severity"] = security.SeverityWarning
		logger.LogSecurityEvent("failed_login", details)

		// Test with critical severity
		details["severity"] = security.SeverityCritical
		logger.LogSecurityEvent("breach_attempt", details)
	})

	// Test LogPluginSecurityViolation
	t.Run("LogPluginSecurityViolation", func(t *testing.T) {
		details := map[string]interface{}{
			"reason": "Plugin lacks required signature",
		}
		logger.LogPluginSecurityViolation("test-plugin", "unsigned_plugin", details)

		details2 := map[string]interface{}{
			"reason": "Attempted to escape sandbox",
			"pid":    12345,
		}
		logger.LogPluginSecurityViolation("malicious-plugin", "sandbox_escape", details2)
	})

	// Test LogResourceViolation
	t.Run("LogResourceViolation", func(t *testing.T) {
		logger.LogResourceViolation("test-plugin", "memory", 1024*1024*1024, 500*1024*1024)
		logger.LogResourceViolation("cpu-hungry-plugin", "cpu", 400.0, 100.0)
	})

	// Test LogFailureRecovery
	t.Run("LogFailureRecovery", func(t *testing.T) {
		logger.LogFailureRecovery("crashed-plugin", "segfault", "restart", true)
		logger.LogFailureRecovery("stuck-plugin", "deadlock", "kill_and_restart", false)
	})

	// Test LogCertificateOperation
	t.Run("LogCertificateOperation", func(t *testing.T) {
		certInfo := &security.CertificateInfo{
			Subject:      "CN=Test Plugin,O=Test Org",
			Issuer:       "CN=Test CA,O=Test Org",
			Fingerprint:  "1234567890abcdef",
			SerialNumber: "12345",
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     []string{"digital_signature", "key_encipherment"},
		}

		logger.LogCertificateOperation("add", certInfo)
		logger.LogCertificateOperation("verify", certInfo)
		logger.LogCertificateOperation("revoke", certInfo)
	})

	// Test GetAuditEvents
	t.Run("GetAuditEvents", func(t *testing.T) {
		// First flush to ensure events are written
		logger.Flush()

		events, err := logger.GetAuditEvents(10, nil)
		if err == nil {
			t.Error("Expected error for not implemented method")
		}
		if len(events) != 0 {
			t.Error("Expected no events due to not implemented method")
		}
	})

	// Verify log file was created
	if _, err := os.Stat(auditLogPath); os.IsNotExist(err) {
		t.Error("Audit log file was not created")
	}
}

// TestCertificateStore tests the certificate store functionality
func TestCertificateStore(t *testing.T) {
	tempDir := t.TempDir()
	certStorePath := filepath.Join(tempDir, "certs")
	auditLogPath := filepath.Join(tempDir, "audit.log")

	auditLogger, err := security.NewFileSecurityAuditLogger(auditLogPath)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer auditLogger.Close()

	store, err := security.NewFileCertificateStore(certStorePath, auditLogger)
	if err != nil {
		t.Fatalf("Failed to create certificate store: %v", err)
	}

	// Generate test certificates
	rootCert, rootKey := generateTestCertificate(t, "Test Root CA", true, nil, nil)
	leafCert, _ := generateTestCertificate(t, "Test Plugin", false, rootCert, rootKey)

	// Test AddCertificate
	t.Run("AddCertificate", func(t *testing.T) {
		err := store.AddCertificate(rootCert)
		if err != nil {
			t.Errorf("Failed to add root certificate: %v", err)
		}

		// Add leaf certificate with metadata
		leafMetadata := &security.CertificateMetadata{
			AddedBy:    "test-admin",
			TrustLevel: security.TrustLevelLeaf,
			Attributes: map[string]interface{}{
				"purpose": "plugin_signing",
			},
		}
		err = store.AddCertificateWithMetadata(leafCert, leafMetadata)
		if err != nil {
			t.Errorf("Failed to add leaf certificate: %v", err)
		}
	})

	// Test GetCertificate
	t.Run("GetCertificate", func(t *testing.T) {
		rootFingerprint := calculateFingerprint(rootCert)
		cert, err := store.GetCertificate(rootFingerprint)
		if err != nil {
			t.Errorf("Failed to get certificate: %v", err)
		}
		if cert == nil {
			t.Error("Expected certificate, got nil")
		}

		// Get metadata separately
		metadata, err := store.GetCertificateMetadata(rootFingerprint)
		if err != nil {
			t.Errorf("Failed to get certificate metadata: %v", err)
		}
		if metadata != nil && metadata.TrustLevel != "" {
			// Metadata might not be set for certificates added with AddCertificate
			t.Logf("Certificate trust level: %s", metadata.TrustLevel)
		}
	})

	// Test ListCertificates
	t.Run("ListCertificates", func(t *testing.T) {
		certs, err := store.ListCertificates()
		if err != nil {
			t.Errorf("Failed to list certificates: %v", err)
		}
		if len(certs) < 2 {
			t.Errorf("Expected at least 2 certificates, got %d", len(certs))
		}
	})

	// Test RevokeCertificate
	t.Run("RevokeCertificate", func(t *testing.T) {
		leafFingerprint := calculateFingerprint(leafCert)
		err := store.RevokeCertificate(leafFingerprint, "Test revocation")
		if err != nil {
			t.Errorf("Failed to revoke certificate: %v", err)
		}

		// Verify certificate is marked as revoked
		metadata, err := store.GetCertificateMetadata(leafFingerprint)
		if err != nil {
			t.Errorf("Failed to get metadata: %v", err)
		}
		if metadata != nil && !metadata.Revoked {
			t.Error("Certificate should be marked as revoked")
		}
	})

	// Test RemoveCertificate
	t.Run("RemoveCertificate", func(t *testing.T) {
		leafFingerprint := calculateFingerprint(leafCert)
		err := store.RemoveCertificate(leafFingerprint)
		if err != nil {
			t.Errorf("Failed to remove certificate: %v", err)
		}

		// Verify certificate is removed
		_, err = store.GetCertificate(leafFingerprint)
		if err == nil {
			t.Error("Expected error when getting removed certificate")
		}
	})

	// Test VerifyChain
	t.Run("VerifyChain", func(t *testing.T) {
		// This would require more setup for a proper chain
		// For now, just verify the method exists and handles basic cases
		err := store.VerifyChain(rootCert)
		if err != nil {
			t.Logf("VerifyChain returned error (expected): %v", err)
		}
	})
}

// TestPluginVerifier tests the plugin verification functionality
func TestPluginVerifier(t *testing.T) {
	tempDir := t.TempDir()

	// Create a mock plugin file
	pluginPath := filepath.Join(tempDir, "test-plugin.so")
	if err := os.WriteFile(pluginPath, []byte("mock plugin content"), 0644); err != nil {
		t.Fatalf("Failed to create mock plugin: %v", err)
	}

	// Create audit logger and cert store
	auditLogger, _ := security.NewFileSecurityAuditLogger(filepath.Join(tempDir, "audit.log"))
	defer auditLogger.Close()

	certStore, _ := security.NewFileCertificateStore(filepath.Join(tempDir, "certs"), auditLogger)

	// Create verifier
	verifier := security.NewPluginVerifier(certStore, auditLogger)

	// Test VerifyPlugin
	t.Run("VerifyPlugin", func(t *testing.T) {
		result, err := verifier.VerifyPlugin(pluginPath)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		// Should fail verification (no signature)
		if result.Valid {
			t.Error("Expected verification to fail for unsigned plugin")
		}
	})

	// Test with signature file
	t.Run("VerifyPluginWithSignature", func(t *testing.T) {
		// Create a mock signature file
		sigPath := pluginPath + ".sig"
		if err := os.WriteFile(sigPath, []byte("mock signature"), 0644); err != nil {
			t.Fatalf("Failed to create signature file: %v", err)
		}

		result, err := verifier.VerifyPlugin(pluginPath)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		// Should still fail verification (invalid signature)
		if result.Valid {
			t.Error("Should not validate with mock signature")
		}
	})

}

// TestSandboxManager tests sandbox management functionality
func TestSandboxManager(t *testing.T) {
	// Skip most sandbox tests if not root
	if os.Getuid() != 0 {
		t.Skip("Sandbox tests require root privileges")
	}

	tempDir := t.TempDir()
	auditLogger, _ := security.NewFileSecurityAuditLogger(filepath.Join(tempDir, "audit.log"))
	defer auditLogger.Close()

	config := security.DefaultSandboxConfig()
	config.CGroupRoot = filepath.Join(tempDir, "cgroup")

	// Use real logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	manager, err := security.NewSandboxManager(config, auditLogger, logger)
	if err != nil {
		t.Fatalf("Failed to create sandbox manager: %v", err)
	}

	t.Run("CreateDestroySandbox", func(t *testing.T) {
		sandbox, err := manager.CreateSandbox("test-plugin")
		if err != nil {
			t.Fatalf("Failed to create sandbox: %v", err)
		}

		if sandbox.PluginName != "test-plugin" {
			t.Errorf("Expected plugin name 'test-plugin', got %s", sandbox.PluginName)
		}

		// Test GetSandboxStatus
		status := manager.GetSandboxStatus()
		if status["active_cgroups"].(int) < 1 {
			t.Error("Expected at least 1 active cgroup")
		}

		// Destroy sandbox
		err = manager.DestroySandbox(sandbox)
		if err != nil {
			t.Errorf("Failed to destroy sandbox: %v", err)
		}
	})
}

// TestSecurityManagerMethods tests additional SecurityManager methods
func TestSecurityManagerMethods(t *testing.T) {
	tempDir := t.TempDir()

	config := &security.SecurityConfig{
		RequireSignature:     true,
		EnforcementLevel:     security.EnforcementStrict,
		TrustedCertificates:  []string{},
		CertificateStorePath: filepath.Join(tempDir, "certs"),
		AuditLogPath:         filepath.Join(tempDir, "audit.log"),
		VerificationCacheTTL: time.Minute,
		AllowSelfSigned:      false,
		AllowedAlgorithms:    []security.SignatureAlgorithm{security.AlgorithmEd25519},
		SandboxConfig:        nil, // Disable sandbox for tests
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager, err := security.NewSecurityManager(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security manager: %v", err)
	}
	defer manager.Close()

	// Test CheckPluginSecurity with strict enforcement
	t.Run("CheckPluginSecurityStrict", func(t *testing.T) {
		result, err := manager.CheckPluginSecurity("/nonexistent/plugin.so")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		// In strict mode without signature, should not be allowed
		if config.RequireSignature && config.EnforcementLevel == security.EnforcementStrict {
			if result.Allowed {
				t.Error("Plugin should not be allowed in strict mode without signature")
			}
		}
	})
}

// Helper functions

func generateTestCertificate(t *testing.T, commonName string, isCA bool, parent *x509.Certificate, parentKey interface{}) (*x509.Certificate, ed25519.PrivateKey) {
	// Generate key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	// Self-sign if no parent
	certParent := template
	signerKey := priv
	if parent != nil && parentKey != nil {
		certParent = parent
		signerKey = parentKey.(ed25519.PrivateKey)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, certParent, pub, signerKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, priv
}

func calculateFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", hash)
}
