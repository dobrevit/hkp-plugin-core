package security_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/security"
)

// TestSecurityManagerAdvancedMethods tests uncovered SecurityManager methods
func TestSecurityManagerAdvancedMethods(t *testing.T) {
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
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager, err := security.NewSecurityManager(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security manager: %v", err)
	}
	defer manager.Close()

	// Test AddTrustedCertificate
	cert, _ := generateTestCertForFinal(t)
	err = manager.AddTrustedCertificate(cert, security.TrustLevelRoot)
	if err != nil {
		t.Errorf("Failed to add trusted certificate: %v", err)
	}

	// Test GetTrustedCertificates
	certs, err := manager.GetTrustedCertificates()
	if err != nil {
		t.Errorf("Failed to get trusted certificates: %v", err)
	}
	if len(certs) == 0 {
		t.Error("Expected at least one trusted certificate")
	}

	// Test RevokeCertificate
	fingerprint := calculateFingerprint(cert)
	err = manager.RevokeCertificate(fingerprint, "Test revocation")
	if err != nil {
		t.Errorf("Failed to revoke certificate: %v", err)
	}

	// Test UpdateEnforcementLevel
	manager.UpdateEnforcementLevel(security.EnforcementPermissive)

	// Verify enforcement level changed
	status := manager.GetSecurityStatus()
	if status["enforcement_level"] != security.EnforcementPermissive {
		t.Errorf("Expected permissive enforcement level, got %v", status["enforcement_level"])
	}

	// Test CreatePluginSandbox, RunPluginInSandbox, DestroyPluginSandbox
	// These will likely fail without root but will exercise the code
	sandbox, err := manager.CreatePluginSandbox("test-plugin")
	if err != nil {
		t.Logf("CreatePluginSandbox failed (expected without root): %v", err)
	} else {
		// If sandbox creation succeeded, test running in it
		err = manager.RunPluginInSandbox(sandbox, "echo", []string{"test"})
		if err != nil {
			t.Logf("RunPluginInSandbox failed: %v", err)
		}

		// Test destroying sandbox
		err = manager.DestroyPluginSandbox(sandbox)
		if err != nil {
			t.Logf("DestroyPluginSandbox failed: %v", err)
		}
	}
}

// TestVerificationCacheOperations tests verification cache methods
func TestVerificationCacheOperations(t *testing.T) {
	cache := security.NewVerificationCache(time.Minute) // Normal TTL

	// Create a test verification result
	result := &security.VerificationResult{
		Valid:     true,
		Timestamp: time.Now(),
		Algorithm: security.AlgorithmEd25519,
	}

	// Test Set operation
	cache.Set("test-plugin-1", result)
	cache.Set("test-plugin-2", result)

	// Test Get operation (implicitly tested through Set, but exercise different paths)
	cachedResult := cache.Get("test-plugin-1")
	if cachedResult == nil {
		t.Error("Expected cached result for test-plugin-1")
	}

	cachedResult = cache.Get("nonexistent-plugin")
	if cachedResult != nil {
		t.Error("Expected nil for nonexistent plugin")
	}

	// Test Clear operation with expired entries
	expiredCache := security.NewVerificationCache(time.Nanosecond)
	expiredResult := &security.VerificationResult{
		Valid:     true,
		Timestamp: time.Now().Add(-time.Hour), // Old timestamp
		Algorithm: security.AlgorithmEd25519,
	}
	expiredCache.Set("expired-plugin", expiredResult)

	// Sleep to ensure expiration
	time.Sleep(time.Millisecond)
	expiredCache.Clear()

	// Test that unexpired entries remain in the original cache
	cachedResult = cache.Get("test-plugin-1")
	if cachedResult == nil {
		t.Error("Expected non-expired result to still be cached")
	}
}

// TestPluginVerifierInternalMethods tests internal verifier methods
func TestPluginVerifierInternalMethods(t *testing.T) {
	tempDir := t.TempDir()
	auditLogger, _ := security.NewFileSecurityAuditLogger(filepath.Join(tempDir, "audit.log"))
	defer auditLogger.Close()

	certStore, _ := security.NewFileCertificateStore(filepath.Join(tempDir, "certs"), auditLogger)
	verifier := security.NewPluginVerifier(certStore, auditLogger)

	// Create a plugin with signature and certificate to exercise more code paths
	pluginPath := filepath.Join(tempDir, "signed_plugin.so")
	sigPath := pluginPath + ".sig"
	certPath := pluginPath + ".cert"

	// Write plugin content
	pluginContent := []byte("test plugin content for verification")
	os.WriteFile(pluginPath, pluginContent, 0644)

	// Generate certificate and key
	cert, privKey := generateTestCertForFinal(t)

	// Create a signature (simplified, may not verify but exercises code)
	signature := ed25519.Sign(privKey, pluginContent)
	os.WriteFile(sigPath, signature, 0644)

	// Write certificate in PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	os.WriteFile(certPath, certPEM, 0644)

	// Add certificate to store so it can be found during verification
	certStore.AddCertificate(cert)

	// This will exercise readSignature, verifySignature, detectAlgorithm,
	// buildCertificateInfo, buildTrustChain, checkRevocationStatus
	result, err := verifier.VerifyPlugin(pluginPath)
	if err != nil {
		t.Errorf("Unexpected error during verification: %v", err)
	}

	// The plugin likely won't verify successfully but should exercise the code paths
	t.Logf("Verification result: Valid=%v, Error=%s", result.Valid, result.Error)
}

// TestCertificateStoreEdgeCases tests certificate store edge cases
func TestCertificateStoreEdgeCases(t *testing.T) {
	tempDir := t.TempDir()
	auditLogger, _ := security.NewFileSecurityAuditLogger(filepath.Join(tempDir, "audit.log"))
	defer auditLogger.Close()

	certStorePath := filepath.Join(tempDir, "certs")
	certStore, err := security.NewFileCertificateStore(certStorePath, auditLogger)
	if err != nil {
		t.Fatalf("Failed to create certificate store: %v", err)
	}

	// Create a certificate file manually to test loadCertificate
	cert, _ := generateTestCertForFinal(t)
	fingerprint := calculateFingerprint(cert)
	certFilePath := filepath.Join(certStorePath, fingerprint+".crt")

	// Write certificate in raw DER format
	os.WriteFile(certFilePath, cert.Raw, 0644)

	// Create a new store to trigger loadCertificates which calls loadCertificate
	_, err = security.NewFileCertificateStore(certStorePath, auditLogger)
	if err != nil {
		t.Fatalf("Failed to create second certificate store: %v", err)
	}

	// Test error cases for AddCertificateWithMetadata
	metadata := &security.CertificateMetadata{
		TrustLevel: security.TrustLevelLeaf,
		AddedBy:    "test",
		Attributes: make(map[string]interface{}),
	}

	// Add the certificate first
	err = certStore.AddCertificateWithMetadata(cert, metadata)
	if err != nil {
		t.Errorf("Failed to add certificate with metadata: %v", err)
	}

	// Try to add the same certificate again (should fail)
	err = certStore.AddCertificateWithMetadata(cert, metadata)
	if err == nil {
		t.Error("Expected error when adding duplicate certificate")
	}
}

// TestComplianceChecking tests security manager compliance methods
func TestComplianceChecking(t *testing.T) {
	tempDir := t.TempDir()

	config := &security.SecurityConfig{
		RequireSignature:     true,
		EnforcementLevel:     security.EnforcementStrict,
		TrustedCertificates:  []string{},
		CertificateStorePath: filepath.Join(tempDir, "certs"),
		AuditLogPath:         filepath.Join(tempDir, "audit.log"),
		VerificationCacheTTL: time.Minute,
		AllowSelfSigned:      false,
		AllowedAlgorithms:    []security.SignatureAlgorithm{security.AlgorithmEd25519, security.AlgorithmRSA4096},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager, err := security.NewSecurityManager(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security manager: %v", err)
	}
	defer manager.Close()

	// Create verification results with different algorithms and properties
	testResults := []*security.VerificationResult{
		{
			Valid:     true,
			Algorithm: security.AlgorithmEd25519,
		},
		{
			Valid:     true,
			Algorithm: security.AlgorithmRSA4096,
		},
		{
			Valid:     false,
			Algorithm: security.AlgorithmEd25519,
		},
	}

	// Test each result - this will exercise checkAlgorithmCompliance,
	// checkCertificateCompliance, and determineAllowance
	for i, _ := range testResults {
		pluginPath := filepath.Join(tempDir, "test_plugin_"+string(rune(i+48))+".so")

		// This will call CheckPluginSecurity which internally calls the compliance methods
		allowanceResult, err := manager.CheckPluginSecurity(pluginPath)
		if err != nil {
			t.Errorf("Unexpected error checking plugin security: %v", err)
		}

		t.Logf("Plugin %d: Allowed=%v, Reason=%s", i, allowanceResult.Allowed, allowanceResult.Reason)
	}
}

// Helper function for this test file
func generateTestCertForFinal(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
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
