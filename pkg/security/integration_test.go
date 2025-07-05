package security_test

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/security"
)

func TestSecurityManagerIntegration(t *testing.T) {
	// Create temporary directories for testing
	tempDir := t.TempDir()
	certStorePath := tempDir + "/certs"
	auditLogPath := tempDir + "/audit.log"

	// Create security configuration without sandbox for tests (requires root)
	config := &security.SecurityConfig{
		RequireSignature:     false, // Disable for test
		EnforcementLevel:     security.EnforcementPermissive,
		TrustedCertificates:  []string{},
		CertificateStorePath: certStorePath,
		AuditLogPath:         auditLogPath,
		VerificationCacheTTL: time.Minute,
		AllowSelfSigned:      true,
		AllowedAlgorithms:    []security.SignatureAlgorithm{security.AlgorithmEd25519},
		SandboxConfig:        nil, // Disable sandbox for tests
	}

	// Create security manager
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager, err := security.NewSecurityManager(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security manager: %v", err)
	}
	defer manager.Close()

	// Test security check with no signature requirement
	result, err := manager.CheckPluginSecurity("/nonexistent/plugin.so")
	if err != nil {
		t.Fatalf("Security check failed: %v", err)
	}

	if !result.Allowed {
		t.Errorf("Plugin should be allowed in permissive mode, got: %v", result.Reason)
	}

	// Test security status
	status := manager.GetSecurityStatus()
	if status["enforcement_level"] != security.EnforcementPermissive {
		t.Errorf("Expected permissive enforcement level, got: %v", status["enforcement_level"])
	}

	// Skip sandbox functionality tests since they require root privileges
	// Sandbox tests are handled separately in TestSandboxManagerBasic
}

func TestPluginVerifierBasic(t *testing.T) {
	// Create temporary audit logger
	tempDir := t.TempDir()
	auditLogPath := tempDir + "/audit.log"

	auditLogger, err := security.NewFileSecurityAuditLogger(auditLogPath)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer auditLogger.Close()

	// Create temporary certificate store
	certStorePath := tempDir + "/certs"
	certStore, err := security.NewFileCertificateStore(certStorePath, auditLogger)
	if err != nil {
		t.Fatalf("Failed to create certificate store: %v", err)
	}

	// Create plugin verifier
	verifier := security.NewPluginVerifier(certStore, auditLogger)

	// Test verification of non-existent plugin (should handle gracefully)
	result, err := verifier.VerifyPlugin("/nonexistent/plugin.so")
	if err != nil {
		t.Fatalf("VerifyPlugin should not error on non-existent file: %v", err)
	}

	if result.Valid {
		t.Error("Non-existent plugin should not be valid")
	}

	if result.Timestamp.IsZero() {
		t.Error("Result should have timestamp")
	}
}

func TestSandboxManagerBasic(t *testing.T) {
	// Skip if not running as root (required for cgroups)
	if os.Getuid() != 0 {
		t.Skip("Sandbox tests require root privileges to create cgroups")
	}

	// Create temporary directories for testing
	tempDir := t.TempDir()
	auditLogPath := tempDir + "/audit.log"

	auditLogger, err := security.NewFileSecurityAuditLogger(auditLogPath)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer auditLogger.Close()

	// Create sandbox config
	config := security.DefaultSandboxConfig()
	config.CGroupRoot = tempDir + "/cgroup"

	// Create sandbox manager
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	sandboxManager, err := security.NewSandboxManager(config, auditLogger, logger)
	if err != nil {
		t.Fatalf("Failed to create sandbox manager: %v", err)
	}

	// Create sandbox
	sandbox, err := sandboxManager.CreateSandbox("test-plugin")
	if err != nil {
		t.Fatalf("Failed to create sandbox: %v", err)
	}

	// Verify sandbox was created
	if sandbox.PluginName != "test-plugin" {
		t.Errorf("Expected plugin name 'test-plugin', got %s", sandbox.PluginName)
	}

	// Get sandbox status
	status := sandboxManager.GetSandboxStatus()
	if status["active_cgroups"].(int) != 1 {
		t.Errorf("Expected 1 active cgroup, got %v", status["active_cgroups"])
	}

	// Clean up sandbox
	if err := sandboxManager.DestroySandbox(sandbox); err != nil {
		t.Errorf("Failed to destroy sandbox: %v", err)
	}
}
