package resources_test

import (
	"context"
	"testing"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/resources"
)

func TestResourceMonitorIntegration(t *testing.T) {
	// Create monitor config
	config := &resources.MonitorConfig{
		CollectionInterval: 100 * time.Millisecond,
		AlertThresholds: map[resources.ResourceType]float64{
			resources.ResourceTypeMemory: 80.0,
		},
		RetentionPeriod: time.Hour,
		EnabledCollectors: []resources.ResourceType{
			resources.ResourceTypeMemory,
			resources.ResourceTypeGoroutines,
		},
		AlertingEnabled: true,
	}

	// Create resource monitor
	monitor := resources.NewResourceMonitor(config)

	// Start monitoring
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start monitor: %v", err)
	}
	defer monitor.Stop()

	// Track a test plugin
	limits := &resources.ResourceLimits{
		MaxMemoryMB:   100,
		MaxGoroutines: 50,
	}

	err = monitor.TrackPlugin("test-plugin", limits)
	if err != nil {
		t.Fatalf("Failed to track plugin: %v", err)
	}

	// Wait for at least one collection cycle
	time.Sleep(200 * time.Millisecond)

	// Check plugin usage
	usage, err := monitor.GetPluginUsage("test-plugin")
	if err != nil {
		t.Fatalf("Failed to get plugin usage: %v", err)
	}

	if len(usage) == 0 {
		t.Error("Expected some resource usage data")
	}

	// Check system summary
	summary := monitor.GetSystemSummary()
	if summary["plugins_tracked"].(int) != 1 {
		t.Errorf("Expected 1 tracked plugin, got %v", summary["plugins_tracked"])
	}

	// Untrack plugin
	err = monitor.UntrackPlugin("test-plugin")
	if err != nil {
		t.Fatalf("Failed to untrack plugin: %v", err)
	}
}

func TestResourceMetrics(t *testing.T) {
	metrics := resources.NewResourceMetrics()

	// Create test usage data
	usage := map[resources.ResourceType]*resources.ResourceUsage{
		resources.ResourceTypeMemory: {
			PluginName:   "test-plugin",
			ResourceType: resources.ResourceTypeMemory,
			Current:      50.0,
			Peak:         75.0,
			Average:      60.0,
			Unit:         "MB",
			Timestamp:    time.Now(),
		},
	}

	// Update metrics
	metrics.UpdatePluginMetrics("test-plugin", usage)

	// Get plugin metrics
	pluginMetrics, exists := metrics.GetPluginMetrics("test-plugin")
	if !exists {
		t.Fatal("Plugin metrics should exist")
	}

	if pluginMetrics.PluginName != "test-plugin" {
		t.Errorf("Expected plugin name 'test-plugin', got %s", pluginMetrics.PluginName)
	}

	if pluginMetrics.HealthScore < 0 || pluginMetrics.HealthScore > 100 {
		t.Errorf("Health score should be between 0-100, got %f", pluginMetrics.HealthScore)
	}

	// Test system metrics
	systemMetrics := metrics.GetSystemMetrics()
	if systemMetrics.TotalPlugins != 1 {
		t.Errorf("Expected 1 total plugin, got %d", systemMetrics.TotalPlugins)
	}
}

func TestAlertManager(t *testing.T) {
	alertManager := resources.NewAlertManager()

	// Create test violation
	violation := &resources.ResourceViolation{
		PluginName:   "test-plugin",
		ResourceType: resources.ResourceTypeMemory,
		Limit:        100.0,
		Actual:       150.0,
		Timestamp:    time.Now(),
		Severity:     resources.SeverityWarning,
		Action:       "logged",
	}

	// Send alert (should not error)
	alertManager.SendAlert(violation)

	// Test passes if no panic occurs
}
