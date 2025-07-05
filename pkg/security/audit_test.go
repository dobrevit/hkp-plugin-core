package security_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dobrevit/hkp-plugin-core/pkg/security"
)

// TestAuditLoggerEdgeCases tests edge cases and error conditions
func TestAuditLoggerEdgeCases(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("InvalidPath", func(t *testing.T) {
		// Try to create logger with invalid path
		_, err := security.NewFileSecurityAuditLogger("/invalid\x00path/audit.log")
		if err == nil {
			t.Error("Expected error for invalid path")
		}
	})

	t.Run("BufferFlush", func(t *testing.T) {
		auditLogPath := filepath.Join(tempDir, "buffer_test.log")
		logger, err := security.NewFileSecurityAuditLogger(auditLogPath)
		if err != nil {
			t.Fatalf("Failed to create logger: %v", err)
		}
		defer logger.Close()

		// Log many events to trigger buffer flush
		for i := 0; i < 100; i++ {
			logger.LogSecurityEvent("test_event", map[string]interface{}{
				"index": i,
				"data":  "test data to fill buffer",
			})
		}

		// Explicitly flush
		logger.Flush()

		// Verify file has content
		info, err := os.Stat(auditLogPath)
		if err != nil {
			t.Errorf("Failed to stat audit log: %v", err)
		}
		if info.Size() == 0 {
			t.Error("Audit log should have content after flush")
		}
	})

	t.Run("ConcurrentLogging", func(t *testing.T) {
		auditLogPath := filepath.Join(tempDir, "concurrent_test.log")
		logger, err := security.NewFileSecurityAuditLogger(auditLogPath)
		if err != nil {
			t.Fatalf("Failed to create logger: %v", err)
		}
		defer logger.Close()

		// Test concurrent logging
		done := make(chan bool, 4)

		// Multiple goroutines logging different event types
		go func() {
			for i := 0; i < 10; i++ {
				logger.LogSecurityEvent("concurrent_test", map[string]interface{}{"goroutine": 1, "index": i})
			}
			done <- true
		}()

		go func() {
			for i := 0; i < 10; i++ {
				logger.LogPluginSecurityViolation("plugin1", "test_violation", map[string]interface{}{"reason": "concurrent test"})
			}
			done <- true
		}()

		go func() {
			for i := 0; i < 10; i++ {
				logger.LogResourceViolation("plugin2", "cpu", float64(i*10), 50.0)
			}
			done <- true
		}()

		go func() {
			for i := 0; i < 10; i++ {
				logger.LogFailureRecovery("plugin3", "crash", "restart", i%2 == 0)
			}
			done <- true
		}()

		// Wait for all goroutines
		for i := 0; i < 4; i++ {
			<-done
		}

		logger.Flush()
	})

	t.Run("SeverityLevels", func(t *testing.T) {
		auditLogPath := filepath.Join(tempDir, "severity_test.log")
		logger, err := security.NewFileSecurityAuditLogger(auditLogPath)
		if err != nil {
			t.Fatalf("Failed to create logger: %v", err)
		}
		defer logger.Close()

		// Test all severity levels
		severities := []security.SeverityLevel{
			security.SeverityInfo,
			security.SeverityWarning,
			security.SeverityError,
			security.SeverityCritical,
		}

		for _, sev := range severities {
			logger.LogSecurityEvent("severity_test", map[string]interface{}{
				"severity": sev,
				"message":  "Testing severity level",
			})
		}

		// Test with invalid severity (should default to info)
		logger.LogSecurityEvent("invalid_severity", map[string]interface{}{
			"severity": "invalid",
			"message":  "Testing invalid severity",
		})
	})
}

// TestAuditEventRetrieval tests retrieving audit events
func TestAuditEventRetrieval(t *testing.T) {
	tempDir := t.TempDir()
	auditLogPath := filepath.Join(tempDir, "retrieval_test.log")

	logger, err := security.NewFileSecurityAuditLogger(auditLogPath)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Log various events
	for i := 0; i < 20; i++ {
		logger.LogSecurityEvent("test_event", map[string]interface{}{
			"index": i,
			"type":  "retrieval_test",
		})

		if i%5 == 0 {
			logger.LogPluginSecurityViolation("test-plugin", "test_violation", map[string]interface{}{"reason": "Test violation"})
		}
	}

	// Flush to ensure events are available
	logger.Flush()

	t.Run("GetRecentEvents", func(t *testing.T) {
		events, err := logger.GetAuditEvents(10, nil)
		if err == nil {
			t.Error("Expected error for not implemented method")
		}
		if len(events) != 0 {
			t.Error("Expected no events due to not implemented method")
		}
	})

	t.Run("GetAllEvents", func(t *testing.T) {
		events, err := logger.GetAuditEvents(0, nil)
		if err == nil {
			t.Error("Expected error for not implemented method")
		}
		if len(events) != 0 {
			t.Error("Expected no events due to not implemented method")
		}
	})

	t.Run("GetMoreThanAvailable", func(t *testing.T) {
		events, err := logger.GetAuditEvents(1000, nil)
		if err == nil {
			t.Error("Expected error for not implemented method")
		}
		if len(events) != 0 {
			t.Error("Expected no events due to not implemented method")
		}
	})
}
