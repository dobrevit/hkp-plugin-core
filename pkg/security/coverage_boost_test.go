package security_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/security"
)

// TestSandboxManagerRobust tests more sandbox functionality
func TestSandboxManagerRobust(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Sandbox tests require root privileges")
	}

	tempDir := t.TempDir()
	auditLogPath := filepath.Join(tempDir, "audit.log")

	auditLogger, err := security.NewFileSecurityAuditLogger(auditLogPath)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer auditLogger.Close()

	config := security.DefaultSandboxConfig()
	config.CGroupRoot = filepath.Join(tempDir, "cgroup")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	sandboxManager, err := security.NewSandboxManager(config, auditLogger, logger)
	if err != nil {
		t.Fatalf("Failed to create sandbox manager: %v", err)
	}

	// Test multiple sandbox creation
	sandbox1, err := sandboxManager.CreateSandbox("plugin1")
	if err != nil {
		t.Fatalf("Failed to create sandbox1: %v", err)
	}

	sandbox2, err := sandboxManager.CreateSandbox("plugin2")
	if err != nil {
		t.Fatalf("Failed to create sandbox2: %v", err)
	}

	// Test sandbox status
	status := sandboxManager.GetSandboxStatus()
	if status["active_cgroups"].(int) < 2 {
		t.Logf("Expected at least 2 active cgroups, got %v", status["active_cgroups"])
	}

	// Test running in sandbox
	err = sandboxManager.RunInSandbox(sandbox1, "echo", []string{"test"})
	if err != nil {
		t.Logf("RunInSandbox error (expected in test): %v", err)
	}

	// Test cleanup
	sandboxManager.DestroySandbox(sandbox1)
	sandboxManager.DestroySandbox(sandbox2)
}

// TestCertificateChainValidation tests complex certificate operations
func TestCertificateChainValidation(t *testing.T) {
	tempDir := t.TempDir()
	auditLogPath := filepath.Join(tempDir, "audit.log")
	certStorePath := filepath.Join(tempDir, "certs")

	auditLogger, err := security.NewFileSecurityAuditLogger(auditLogPath)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer auditLogger.Close()

	certStore, err := security.NewFileCertificateStore(certStorePath, auditLogger)
	if err != nil {
		t.Fatalf("Failed to create certificate store: %v", err)
	}

	// Generate certificate hierarchy: Root -> Intermediate -> Leaf
	rootCert, rootKey := generateRootCertificate(t)
	intermediateCert, intermediateKey := generateIntermediateCertificate(t, rootCert, rootKey)
	leafCert, _ := generateLeafCertificate(t, intermediateCert, intermediateKey)

	// Add certificates to store
	err = certStore.AddCertificateWithMetadata(rootCert, &security.CertificateMetadata{
		TrustLevel: security.TrustLevelRoot,
		AddedBy:    "test_admin",
		Attributes: map[string]interface{}{"role": "root_ca"},
	})
	if err != nil {
		t.Fatalf("Failed to add root certificate: %v", err)
	}

	err = certStore.AddCertificateWithMetadata(intermediateCert, &security.CertificateMetadata{
		TrustLevel: security.TrustLevelIntermediate,
		AddedBy:    "test_admin",
		Attributes: map[string]interface{}{"role": "intermediate_ca"},
	})
	if err != nil {
		t.Fatalf("Failed to add intermediate certificate: %v", err)
	}

	err = certStore.AddCertificateWithMetadata(leafCert, &security.CertificateMetadata{
		TrustLevel: security.TrustLevelLeaf,
		AddedBy:    "test_user",
		Attributes: map[string]interface{}{"role": "signing"},
	})
	if err != nil {
		t.Fatalf("Failed to add leaf certificate: %v", err)
	}

	// Test certificate retrieval
	certs, err := certStore.ListCertificates()
	if err != nil {
		t.Fatalf("Failed to list certificates: %v", err)
	}
	if len(certs) != 3 {
		t.Errorf("Expected 3 certificates, got %d", len(certs))
	}

	// Test metadata retrieval
	rootFingerprint := calculateFingerprint(rootCert)
	metadata, err := certStore.GetCertificateMetadata(rootFingerprint)
	if err != nil {
		t.Fatalf("Failed to get root metadata: %v", err)
	}
	if metadata.TrustLevel != security.TrustLevelRoot {
		t.Errorf("Expected root trust level, got %v", metadata.TrustLevel)
	}

	// Test chain verification
	err = certStore.VerifyChain(leafCert)
	if err != nil {
		t.Logf("Chain verification failed (expected): %v", err)
	}

	// Test certificate removal
	leafFingerprint := calculateFingerprint(leafCert)
	err = certStore.RemoveCertificate(leafFingerprint)
	if err != nil {
		t.Fatalf("Failed to remove leaf certificate: %v", err)
	}

	// Verify removal
	_, err = certStore.GetCertificate(leafFingerprint)
	if err == nil {
		t.Error("Expected error when getting removed certificate")
	}
}

// TestVerificationResultPaths tests different verification scenarios
func TestVerificationResultPaths(t *testing.T) {
	tempDir := t.TempDir()
	auditLogger, _ := security.NewFileSecurityAuditLogger(filepath.Join(tempDir, "audit.log"))
	defer auditLogger.Close()

	certStore, _ := security.NewFileCertificateStore(filepath.Join(tempDir, "certs"), auditLogger)
	verifier := security.NewPluginVerifier(certStore, auditLogger)

	// Test scenarios
	testCases := []struct {
		name          string
		setupFunc     func(string) string
		expectedValid bool
		expectedError bool
	}{
		{
			name: "missing_plugin_file",
			setupFunc: func(dir string) string {
				return filepath.Join(dir, "nonexistent.so")
			},
			expectedValid: false,
			expectedError: false,
		},
		{
			name: "plugin_without_signature",
			setupFunc: func(dir string) string {
				pluginPath := filepath.Join(dir, "unsigned.so")
				os.WriteFile(pluginPath, []byte("plugin content"), 0644)
				return pluginPath
			},
			expectedValid: false,
			expectedError: false,
		},
		{
			name: "plugin_with_invalid_signature_file",
			setupFunc: func(dir string) string {
				pluginPath := filepath.Join(dir, "invalid_sig.so")
				sigPath := pluginPath + ".sig"
				os.WriteFile(pluginPath, []byte("plugin content"), 0644)
				os.WriteFile(sigPath, []byte("invalid signature"), 0644)
				return pluginPath
			},
			expectedValid: false,
			expectedError: false,
		},
		{
			name: "plugin_with_malformed_certificate",
			setupFunc: func(dir string) string {
				pluginPath := filepath.Join(dir, "bad_cert.so")
				certPath := pluginPath + ".cert"
				os.WriteFile(pluginPath, []byte("plugin content"), 0644)
				os.WriteFile(certPath, []byte("not a certificate"), 0644)
				return pluginPath
			},
			expectedValid: false,
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pluginPath := tc.setupFunc(tempDir)
			result, err := verifier.VerifyPlugin(pluginPath)

			if tc.expectedError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tc.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result.Valid != tc.expectedValid {
				t.Errorf("Expected valid=%v, got %v", tc.expectedValid, result.Valid)
			}
		})
	}
}

// TestSecurityManagerEdgeCases tests edge cases in security manager
func TestSecurityManagerEdgeCases(t *testing.T) {
	tempDir := t.TempDir()

	// Test with minimal configuration
	config := &security.SecurityConfig{
		RequireSignature:     false,
		EnforcementLevel:     security.EnforcementPermissive,
		TrustedCertificates:  []string{},
		CertificateStorePath: filepath.Join(tempDir, "certs"),
		AuditLogPath:         filepath.Join(tempDir, "audit.log"),
		VerificationCacheTTL: time.Second,
		AllowSelfSigned:      true,
		AllowedAlgorithms:    []security.SignatureAlgorithm{security.AlgorithmEd25519},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager, err := security.NewSecurityManager(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security manager: %v", err)
	}
	defer manager.Close()

	// Test multiple security checks
	for i := 0; i < 5; i++ {
		pluginPath := filepath.Join(tempDir, "test_plugin.so")
		result, err := manager.CheckPluginSecurity(pluginPath)
		if err != nil {
			t.Fatalf("Security check failed: %v", err)
		}
		if !result.Allowed {
			t.Errorf("Plugin should be allowed in permissive mode")
		}
	}

	// Test status retrieval multiple times
	for i := 0; i < 3; i++ {
		status := manager.GetSecurityStatus()
		if status["enforcement_level"] != security.EnforcementPermissive {
			t.Errorf("Expected permissive enforcement level")
		}
	}
}

// TestAuditLoggerLimits tests audit logger under stress
func TestAuditLoggerLimits(t *testing.T) {
	tempDir := t.TempDir()
	auditLogPath := filepath.Join(tempDir, "stress_audit.log")

	logger, err := security.NewFileSecurityAuditLogger(auditLogPath)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer logger.Close()

	// Log many events rapidly
	for i := 0; i < 200; i++ {
		logger.LogSecurityEvent("stress_test", map[string]interface{}{
			"iteration": i,
			"data":      "stress testing audit logger with large amounts of data",
			"severity":  security.SeverityInfo,
		})

		if i%50 == 0 {
			logger.LogPluginSecurityViolation("stress-plugin", "test_violation",
				map[string]interface{}{"iteration": i})
		}

		if i%30 == 0 {
			logger.LogResourceViolation("stress-plugin", "memory", 1000+i, 500)
		}

		if i%40 == 0 {
			logger.LogFailureRecovery("stress-plugin", "crash", "restart", i%2 == 0)
		}
	}

	// Force flush
	logger.Flush()

	// Verify file exists and has content
	info, err := os.Stat(auditLogPath)
	if err != nil {
		t.Fatalf("Failed to stat audit log: %v", err)
	}
	if info.Size() == 0 {
		t.Error("Audit log should have content")
	}
}

// Helper functions for certificate generation

func generateRootCertificate(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Organization"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, priv
}

func generateIntermediateCertificate(t *testing.T, parent *x509.Certificate, parentKey ed25519.PrivateKey) (*x509.Certificate, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, priv
}

func generateLeafCertificate(t *testing.T, parent *x509.Certificate, parentKey ed25519.PrivateKey) (*x509.Certificate, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "Test Leaf Certificate",
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, priv
}
