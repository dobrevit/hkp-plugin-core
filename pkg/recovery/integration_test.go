package recovery_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/pkg/recovery"
	"github.com/dobrevit/hkp-plugin-core/pkg/security"
)

// MockPluginManager implements PluginManagerInterface for testing
type MockPluginManager struct {
	plugins map[string]plugin.Plugin
}

func NewMockPluginManager() *MockPluginManager {
	return &MockPluginManager{
		plugins: make(map[string]plugin.Plugin),
	}
}

func (m *MockPluginManager) GetPlugin(name string) (plugin.Plugin, bool) {
	p, exists := m.plugins[name]
	return p, exists
}

func (m *MockPluginManager) ListPlugins() []plugin.Plugin {
	plugins := make([]plugin.Plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		plugins = append(plugins, p)
	}
	return plugins
}

func (m *MockPluginManager) LoadPlugin(ctx context.Context, p plugin.Plugin, config map[string]interface{}) error {
	m.plugins[p.Name()] = p
	return nil
}

// MockPlugin implements plugin.Plugin for testing
type MockPlugin struct {
	name        string
	shouldFail  bool
	initialized bool
}

func NewMockPlugin(name string) *MockPlugin {
	return &MockPlugin{
		name:        name,
		initialized: true,
	}
}

func (m *MockPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
	if m.shouldFail {
		return errors.New("mock initialization failure")
	}
	m.initialized = true
	return nil
}

func (m *MockPlugin) Name() string {
	return m.name
}

func (m *MockPlugin) Version() string {
	return "1.0.0-test"
}

func (m *MockPlugin) Description() string {
	return "Mock plugin for testing"
}

func (m *MockPlugin) Dependencies() []plugin.PluginDependency {
	return []plugin.PluginDependency{}
}

func (m *MockPlugin) Shutdown(ctx context.Context) error {
	m.initialized = false
	return nil
}

func (m *MockPlugin) SetShouldFail(fail bool) {
	m.shouldFail = fail
}

// MockAuditLogger implements SecurityAuditLogger for testing
type MockAuditLogger struct {
	events []string
}

func NewMockAuditLogger() *MockAuditLogger {
	return &MockAuditLogger{
		events: make([]string, 0),
	}
}

func (m *MockAuditLogger) LogVerification(pluginPath string, result *security.VerificationResult) {
	m.events = append(m.events, "verification")
}

func (m *MockAuditLogger) LogCertificateOperation(operation string, cert *security.CertificateInfo) {
	m.events = append(m.events, "certificate_operation")
}

func (m *MockAuditLogger) LogSecurityEvent(event string, details map[string]interface{}) {
	m.events = append(m.events, "security_event")
}

func (m *MockAuditLogger) LogPluginSecurityViolation(pluginName string, violation string, details map[string]interface{}) {
	m.events = append(m.events, "security_violation")
}

func (m *MockAuditLogger) LogResourceViolation(pluginName string, resource string, limit interface{}, actual interface{}) {
	m.events = append(m.events, "resource_violation")
}

func (m *MockAuditLogger) LogFailureRecovery(pluginName string, failureType string, recoveryAction string, success bool) {
	m.events = append(m.events, "failure_recovery")
}

func TestCircuitBreakerBasic(t *testing.T) {
	// Create circuit breaker with custom config
	config := &recovery.CircuitBreakerConfig{
		FailureThreshold: 5, // Set explicit threshold
		SuccessThreshold: 3,
		Timeout:          30 * time.Second,
	}
	cb := recovery.NewCircuitBreaker("test-circuit", config, nil)

	// Test initial state
	metrics := cb.GetMetrics()
	if metrics.State != recovery.StateClosed {
		t.Errorf("Expected initial state to be closed, got %s", metrics.State)
	}

	// Test successful execution
	err := cb.Execute(context.Background(), func(ctx context.Context) error {
		return nil
	})

	if err != nil {
		t.Errorf("Expected successful execution, got error: %v", err)
	}

	// Test failure execution - use exactly the failure threshold to open circuit
	for i := 0; i < 5; i++ { // Match the failure threshold
		cb.Execute(context.Background(), func(ctx context.Context) error {
			return errors.New("test failure")
		})
	}

	// Circuit should now be open
	metrics = cb.GetMetrics()
	if metrics.State != recovery.StateOpen {
		t.Errorf("Expected circuit to be open after failures, got %s", metrics.State)
	}

	// Test that requests are now rejected
	err = cb.Execute(context.Background(), func(ctx context.Context) error {
		return nil
	})

	if err == nil {
		t.Error("Expected circuit open error, got nil")
	}
}

func TestRecoveryManagerIntegration(t *testing.T) {
	// Create mocks
	pluginManager := NewMockPluginManager()
	auditLogger := NewMockAuditLogger()
	logger := slog.Default()

	// Create test plugin
	testPlugin := NewMockPlugin("test-plugin")
	pluginManager.LoadPlugin(context.Background(), testPlugin, nil)

	// Create recovery manager
	config := recovery.DefaultRecoveryConfig()
	config.EnableHealthChecking = false // Disable for test simplicity

	rm := recovery.NewRecoveryManager(pluginManager, auditLogger, config, logger)

	// Start recovery manager
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := rm.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start recovery manager: %v", err)
	}
	defer rm.Stop()

	// Register plugin
	err = rm.RegisterPlugin("test-plugin")
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Test successful execution
	err = rm.ExecuteWithRecovery(ctx, "test-plugin", func(ctx context.Context) error {
		return nil
	})

	if err != nil {
		t.Errorf("Expected successful execution, got error: %v", err)
	}

	// Test failure recording
	failure := &recovery.FailureInfo{
		Type:        recovery.FailureTypeError,
		Timestamp:   time.Now(),
		Message:     "Test failure",
		Recoverable: true,
		Severity:    "warning",
		Context:     make(map[string]interface{}),
	}

	rm.RecordFailure("test-plugin", failure)

	// Give some time for async recovery attempt
	time.Sleep(100 * time.Millisecond)

	// Check that audit events were logged
	if len(auditLogger.events) == 0 {
		t.Error("Expected audit events to be logged")
	}

	// Test status retrieval
	status := rm.GetRecoveryStatus()
	if !status["running"].(bool) {
		t.Error("Expected recovery manager to be running")
	}

	plugins := status["plugins"].(map[string]interface{})
	if _, exists := plugins["test-plugin"]; !exists {
		t.Error("Expected test-plugin to be in status")
	}
}

func TestRecoveryStrategies(t *testing.T) {
	// Test restart strategy
	restartStrategy := &recovery.RestartStrategy{}

	failure := &recovery.FailureInfo{
		Type:        recovery.FailureTypeError,
		Recoverable: true,
		Severity:    "warning",
	}

	if !restartStrategy.CanRecover(failure) {
		t.Error("Restart strategy should be able to recover from error")
	}

	if restartStrategy.GetName() != "restart" {
		t.Errorf("Expected restart strategy name, got %s", restartStrategy.GetName())
	}

	if restartStrategy.GetPriority() <= 0 {
		t.Error("Expected positive priority for restart strategy")
	}
}

func TestCircuitBreakerStateTransitions(t *testing.T) {
	config := &recovery.CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
		MinimumRequests:  1,
	}

	cb := recovery.NewCircuitBreaker("test-transitions", config, nil)

	// Initially closed
	if cb.GetMetrics().State != recovery.StateClosed {
		t.Error("Expected initial state to be closed")
	}

	// Cause failures to open circuit
	for i := 0; i < 4; i++ {
		cb.Execute(context.Background(), func(ctx context.Context) error {
			return errors.New("failure")
		})
	}

	// Should now be open
	if cb.GetMetrics().State != recovery.StateOpen {
		t.Error("Expected state to be open after failures")
	}

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Next request should transition to half-open
	cb.Execute(context.Background(), func(ctx context.Context) error {
		return nil // Success
	})

	metrics := cb.GetMetrics()
	if metrics.State != recovery.StateHalfOpen && metrics.State != recovery.StateClosed {
		t.Errorf("Expected state to be half-open or closed after timeout and success, got %s", metrics.State)
	}
}

func TestHealthChecking(t *testing.T) {
	// This test would be more comprehensive in a real implementation
	// For now, we just test basic functionality

	pluginManager := NewMockPluginManager()
	auditLogger := NewMockAuditLogger()

	// Add a test plugin
	testPlugin := NewMockPlugin("health-test-plugin")
	pluginManager.LoadPlugin(context.Background(), testPlugin, nil)

	config := recovery.DefaultRecoveryConfig()
	config.HealthCheckInterval = 50 * time.Millisecond
	config.EnableHealthChecking = true

	rm := recovery.NewRecoveryManager(pluginManager, auditLogger, config, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := rm.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start recovery manager: %v", err)
	}
	defer rm.Stop()

	// Register plugin for health checking
	rm.RegisterPlugin("health-test-plugin")

	// Wait for at least one health check cycle
	time.Sleep(100 * time.Millisecond)

	// Check status - health checking should have occurred
	status := rm.GetRecoveryStatus()
	if !status["health_checking"].(bool) {
		t.Error("Expected health checking to be enabled")
	}
}
