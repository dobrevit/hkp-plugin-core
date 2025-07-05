package versioning_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/pkg/security"
	"github.com/dobrevit/hkp-plugin-core/pkg/versioning"
)

// MockPlugin implements plugin.Plugin for testing
type MockPlugin struct {
	name         string
	version      string
	dependencies []plugin.PluginDependency
}

func NewMockPlugin(name, version string) *MockPlugin {
	return &MockPlugin{
		name:         name,
		version:      version,
		dependencies: []plugin.PluginDependency{},
	}
}

func (m *MockPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
	return nil
}

func (m *MockPlugin) Name() string {
	return m.name
}

func (m *MockPlugin) Version() string {
	return m.version
}

func (m *MockPlugin) Description() string {
	return "Mock plugin for testing"
}

func (m *MockPlugin) Dependencies() []plugin.PluginDependency {
	return m.dependencies
}

func (m *MockPlugin) Shutdown(ctx context.Context) error {
	return nil
}

// MockAuditLogger implements security.SecurityAuditLogger for testing
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

func TestVersionManagerBasic(t *testing.T) {
	auditLogger := NewMockAuditLogger()
	vm := versioning.NewVersionManager(auditLogger, nil, nil)

	// Start version manager
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := vm.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start version manager: %v", err)
	}
	defer vm.Stop()

	// Register a plugin version
	plugin1 := NewMockPlugin("test-plugin", "1.0.0")
	err = vm.RegisterPluginVersion("test-plugin", "1.0.0", plugin1, map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to register plugin version: %v", err)
	}

	// Get plugin version
	version, err := vm.GetPluginVersion("test-plugin", false)
	if err != nil {
		t.Fatalf("Failed to get plugin version: %v", err)
	}

	if version.Version != "1.0.0" {
		t.Errorf("Expected version 1.0.0, got %s", version.Version)
	}

	// Register second version
	plugin2 := NewMockPlugin("test-plugin", "2.0.0")
	err = vm.RegisterPluginVersion("test-plugin", "2.0.0", plugin2, map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to register second plugin version: %v", err)
	}

	// Check version status
	status, err := vm.GetVersionStatus("test-plugin")
	if err != nil {
		t.Fatalf("Failed to get version status: %v", err)
	}

	if status["current_version"] != "1.0.0" {
		t.Errorf("Expected current version 1.0.0, got %v", status["current_version"])
	}

	versions := status["versions"].(map[string]interface{})
	if len(versions) != 2 {
		t.Errorf("Expected 2 versions, got %d", len(versions))
	}
}

func TestCanaryDeployment(t *testing.T) {
	auditLogger := NewMockAuditLogger()
	config := versioning.DefaultVersionConfig()
	config.DefaultCanaryConfig.AutoPromote = false // Manual control for testing
	config.DefaultCanaryConfig.AutoRollback = false

	vm := versioning.NewVersionManager(auditLogger, config, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := vm.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start version manager: %v", err)
	}
	defer vm.Stop()

	// Register initial version
	plugin1 := NewMockPlugin("canary-plugin", "1.0.0")
	err = vm.RegisterPluginVersion("canary-plugin", "1.0.0", plugin1, map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to register initial version: %v", err)
	}

	// Register new version for canary
	plugin2 := NewMockPlugin("canary-plugin", "2.0.0")
	err = vm.RegisterPluginVersion("canary-plugin", "2.0.0", plugin2, map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to register new version: %v", err)
	}

	// Start canary deployment
	canaryConfig := &versioning.CanaryConfig{
		InitialPercent:    10.0,
		IncrementPercent:  10.0,
		IncrementInterval: time.Second,
		MaxPercent:        50.0,
		SuccessThreshold:  0.95,
		ErrorThreshold:    0.05,
		MinRequests:       5,
		ObservationPeriod: time.Second,
		AutoPromote:       false,
		AutoRollback:      false,
	}

	err = vm.StartCanaryDeployment("canary-plugin", "2.0.0", canaryConfig)
	if err != nil {
		t.Fatalf("Failed to start canary deployment: %v", err)
	}

	// Check status after canary start
	status, err := vm.GetVersionStatus("canary-plugin")
	if err != nil {
		t.Fatalf("Failed to get version status: %v", err)
	}

	if status["canary_version"] != "2.0.0" {
		t.Errorf("Expected canary version 2.0.0, got %v", status["canary_version"])
	}

	if status["canary_percent"] != 10.0 {
		t.Errorf("Expected canary percent 10.0, got %v", status["canary_percent"])
	}

	// Test traffic splitting
	canaryRequests := 0
	totalRequests := 100

	for i := 0; i < totalRequests; i++ {
		requestID := fmt.Sprintf("req-%d", i)
		if vm.ShouldUseCanary("canary-plugin", requestID) {
			canaryRequests++
		}
	}

	// Should be approximately 10% (allow some variance due to hashing)
	expectedMin := 5  // 5%
	expectedMax := 15 // 15%
	if canaryRequests < expectedMin || canaryRequests > expectedMax {
		t.Errorf("Expected canary requests between %d and %d, got %d", expectedMin, expectedMax, canaryRequests)
	}

	// Record some successful metrics
	for i := 0; i < 10; i++ {
		vm.RecordCanaryMetrics("canary-plugin", true, time.Millisecond*10)
	}

	// Promote canary
	err = vm.PromoteCanary("canary-plugin")
	if err != nil {
		t.Fatalf("Failed to promote canary: %v", err)
	}

	// Check status after promotion
	status, err = vm.GetVersionStatus("canary-plugin")
	if err != nil {
		t.Fatalf("Failed to get version status after promotion: %v", err)
	}

	if status["current_version"] != "2.0.0" {
		t.Errorf("Expected current version 2.0.0 after promotion, got %v", status["current_version"])
	}

	if status["canary_version"] != "" {
		t.Errorf("Expected no canary version after promotion, got %v", status["canary_version"])
	}
}

func TestCanaryRollback(t *testing.T) {
	auditLogger := NewMockAuditLogger()
	vm := versioning.NewVersionManager(auditLogger, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := vm.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start version manager: %v", err)
	}
	defer vm.Stop()

	// Register versions
	plugin1 := NewMockPlugin("rollback-plugin", "1.0.0")
	plugin2 := NewMockPlugin("rollback-plugin", "2.0.0")

	vm.RegisterPluginVersion("rollback-plugin", "1.0.0", plugin1, map[string]interface{}{})
	vm.RegisterPluginVersion("rollback-plugin", "2.0.0", plugin2, map[string]interface{}{})

	// Start canary deployment
	canaryConfig := &versioning.CanaryConfig{
		InitialPercent:   20.0,
		SuccessThreshold: 0.95,
		ErrorThreshold:   0.05,
		AutoPromote:      false,
		AutoRollback:     false,
	}

	err = vm.StartCanaryDeployment("rollback-plugin", "2.0.0", canaryConfig)
	if err != nil {
		t.Fatalf("Failed to start canary deployment: %v", err)
	}

	// Record some failed metrics
	for i := 0; i < 10; i++ {
		vm.RecordCanaryMetrics("rollback-plugin", false, time.Millisecond*100)
	}

	// Rollback canary
	err = vm.RollbackCanary("rollback-plugin", "high error rate detected")
	if err != nil {
		t.Fatalf("Failed to rollback canary: %v", err)
	}

	// Check status after rollback
	status, err := vm.GetVersionStatus("rollback-plugin")
	if err != nil {
		t.Fatalf("Failed to get version status after rollback: %v", err)
	}

	if status["current_version"] != "1.0.0" {
		t.Errorf("Expected current version 1.0.0 after rollback, got %v", status["current_version"])
	}

	if status["canary_version"] != "" {
		t.Errorf("Expected no canary version after rollback, got %v", status["canary_version"])
	}
}

func TestDeploymentStrategies(t *testing.T) {
	auditLogger := NewMockAuditLogger()
	vm := versioning.NewVersionManager(auditLogger, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := vm.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start version manager: %v", err)
	}
	defer vm.Stop()

	// Create deployment orchestrator
	orchestrator := versioning.NewDeploymentOrchestrator(vm, nil)

	// Test available strategies
	strategies := orchestrator.GetAvailableStrategies()
	expectedStrategies := []string{"blue-green", "rolling", "ab-testing"}

	for _, expected := range expectedStrategies {
		if _, exists := strategies[expected]; !exists {
			t.Errorf("Expected strategy %s not found", expected)
		}
	}

	// Test blue-green deployment spec validation
	spec := &versioning.DeploymentSpec{
		PluginName: "test-plugin",
		OldVersion: "1.0.0",
		NewVersion: "2.0.0",
		Strategy:   "blue-green",
		Timeout:    30 * time.Second,
	}

	strategy, exists := orchestrator.GetStrategy("blue-green")
	if !exists {
		t.Fatal("Blue-green strategy not found")
	}

	err = strategy.Validate(spec)
	if err != nil {
		t.Errorf("Valid spec failed validation: %v", err)
	}

	// Test invalid spec
	invalidSpec := &versioning.DeploymentSpec{
		Strategy: "blue-green",
		// Missing required fields
	}

	err = strategy.Validate(invalidSpec)
	if err == nil {
		t.Error("Invalid spec passed validation")
	}
}

func TestVersionHistory(t *testing.T) {
	auditLogger := NewMockAuditLogger()
	config := versioning.DefaultVersionConfig()
	config.EnableVersionHistory = true

	vm := versioning.NewVersionManager(auditLogger, config, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := vm.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start version manager: %v", err)
	}
	defer vm.Stop()

	// Register multiple versions to create history
	plugin1 := NewMockPlugin("history-plugin", "1.0.0")
	plugin2 := NewMockPlugin("history-plugin", "2.0.0")

	vm.RegisterPluginVersion("history-plugin", "1.0.0", plugin1, map[string]interface{}{})
	vm.RegisterPluginVersion("history-plugin", "2.0.0", plugin2, map[string]interface{}{})

	// Start and complete canary deployment
	canaryConfig := &versioning.CanaryConfig{
		InitialPercent: 10.0,
		AutoPromote:    false,
		AutoRollback:   false,
	}

	vm.StartCanaryDeployment("history-plugin", "2.0.0", canaryConfig)
	vm.PromoteCanary("history-plugin")

	// Check that history events were recorded
	if len(auditLogger.events) == 0 {
		t.Error("Expected audit events to be logged")
	}

	// History validation would require access to internal structures
	// In a real implementation, you'd add a GetVersionHistory method
}

func TestTrafficSplitting(t *testing.T) {
	auditLogger := NewMockAuditLogger()
	vm := versioning.NewVersionManager(auditLogger, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	vm.Start(ctx)
	defer vm.Stop()

	// Register versions
	plugin1 := NewMockPlugin("traffic-plugin", "1.0.0")
	plugin2 := NewMockPlugin("traffic-plugin", "2.0.0")

	vm.RegisterPluginVersion("traffic-plugin", "1.0.0", plugin1, map[string]interface{}{})
	vm.RegisterPluginVersion("traffic-plugin", "2.0.0", plugin2, map[string]interface{}{})

	// Start canary with 25% traffic
	canaryConfig := &versioning.CanaryConfig{
		InitialPercent: 25.0,
	}

	vm.StartCanaryDeployment("traffic-plugin", "2.0.0", canaryConfig)

	// Test traffic distribution over many requests
	canaryCount := 0
	totalRequests := 1000

	for i := 0; i < totalRequests; i++ {
		requestID := fmt.Sprintf("request-%d", i)
		if vm.ShouldUseCanary("traffic-plugin", requestID) {
			canaryCount++
			version, _ := vm.GetPluginVersion("traffic-plugin", true)
			if version.Version != "2.0.0" {
				t.Errorf("Expected canary version 2.0.0, got %s", version.Version)
			}
		} else {
			version, _ := vm.GetPluginVersion("traffic-plugin", false)
			if version.Version != "1.0.0" {
				t.Errorf("Expected current version 1.0.0, got %s", version.Version)
			}
		}
	}

	// Should be approximately 25% (allow 5% variance)
	expectedMin := int(float64(totalRequests) * 0.20) // 20%
	expectedMax := int(float64(totalRequests) * 0.30) // 30%

	if canaryCount < expectedMin || canaryCount > expectedMax {
		t.Errorf("Expected canary requests between %d and %d (25%% ±5%%), got %d (%0.1f%%)",
			expectedMin, expectedMax, canaryCount, float64(canaryCount)/float64(totalRequests)*100)
	}
}
