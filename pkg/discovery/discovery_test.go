package discovery

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestDiscoverer(t *testing.T) {
	// Create temporary directory structure
	tmpDir, err := ioutil.TempDir("", "plugin-discovery-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test plugin structure
	plugin1Dir := filepath.Join(tmpDir, "plugin1")
	os.MkdirAll(plugin1Dir, 0755)

	// Create plugin manifest
	manifestContent := `[plugin]
name = "test-plugin"
version = "1.0.0"
executable = "test-plugin"
protocol_version = "1.0"
description = "Test plugin"
capabilities = ["http_middleware"]
`
	manifestPath := filepath.Join(plugin1Dir, "plugin.toml")
	if err := ioutil.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create executable
	execPath := filepath.Join(plugin1Dir, "test-plugin")
	if err := ioutil.WriteFile(execPath, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		t.Fatal(err)
	}

	// Test discovery
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	discoverer := NewDiscoverer([]string{tmpDir}, logger)
	plugins, err := discoverer.DiscoverPlugins()
	if err != nil {
		t.Fatal(err)
	}

	if len(plugins) != 1 {
		t.Fatalf("Expected 1 plugin, got %d", len(plugins))
	}

	plugin := plugins[0]
	if plugin.Info.Name != "test-plugin" {
		t.Errorf("Expected plugin name 'test-plugin', got '%s'", plugin.Info.Name)
	}
	if plugin.Info.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", plugin.Info.Version)
	}
}

func TestRegistry(t *testing.T) {
	logger := logrus.New()
	registry := NewRegistry(logger)

	// Test registration
	plugin := DiscoveredPlugin{
		Info: PluginInfo{
			Name:    "test-plugin",
			Version: "1.0.0",
		},
	}

	if err := registry.Register(plugin); err != nil {
		t.Fatal(err)
	}

	// Test duplicate registration
	if err := registry.Register(plugin); err == nil {
		t.Error("Expected error for duplicate registration")
	}

	// Test retrieval
	retrieved, exists := registry.Get("test-plugin")
	if !exists {
		t.Error("Plugin should exist")
	}
	if retrieved.Info.Name != "test-plugin" {
		t.Error("Retrieved wrong plugin")
	}

	// Test listing
	list := registry.List()
	if len(list) != 1 {
		t.Errorf("Expected 1 plugin in list, got %d", len(list))
	}

	// Test removal
	if !registry.Remove("test-plugin") {
		t.Error("Failed to remove plugin")
	}
	if registry.Remove("test-plugin") {
		t.Error("Should not remove non-existent plugin")
	}
}

func TestValidateProtocolVersion(t *testing.T) {
	tests := []struct {
		pluginVersion string
		hostVersion   string
		shouldError   bool
	}{
		{"1.0", "1.0", false},
		{"1.0", "2.0", true},
		{"2.0", "1.0", true},
	}

	for _, test := range tests {
		err := ValidateProtocolVersion(test.pluginVersion, test.hostVersion)
		if test.shouldError && err == nil {
			t.Errorf("Expected error for %s vs %s", test.pluginVersion, test.hostVersion)
		}
		if !test.shouldError && err != nil {
			t.Errorf("Unexpected error for %s vs %s: %v", test.pluginVersion, test.hostVersion, err)
		}
	}
}