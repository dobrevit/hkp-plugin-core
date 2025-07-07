// Package discovery provides plugin discovery and registration mechanisms
package discovery

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
)

// PluginManifest represents the plugin.toml file structure
type PluginManifest struct {
	Plugin PluginInfo `toml:"plugin"`
}

// PluginInfo contains plugin metadata
type PluginInfo struct {
	Name            string            `toml:"name" json:"name"`
	Version         string            `toml:"version" json:"version"`
	Executable      string            `toml:"executable" json:"executable"`
	ProtocolVersion string            `toml:"protocol_version" json:"protocol_version"`
	Description     string            `toml:"description" json:"description"`
	Author          string            `toml:"author" json:"author"`
	License         string            `toml:"license" json:"license"`
	Capabilities    []string          `toml:"capabilities" json:"capabilities"`
	Dependencies    []string          `toml:"dependencies" json:"dependencies"`
	Config          map[string]interface{} `toml:"config" json:"config"`
}

// DiscoveredPlugin represents a discovered plugin with its metadata and location
type DiscoveredPlugin struct {
	Info         PluginInfo
	ManifestPath string
	ExecutablePath string
	ConfigPath   string
}

// Discoverer handles plugin discovery
type Discoverer struct {
	pluginDirs []string
	logger     *logrus.Logger
}

// NewDiscoverer creates a new plugin discoverer
func NewDiscoverer(pluginDirs []string, logger *logrus.Logger) *Discoverer {
	return &Discoverer{
		pluginDirs: pluginDirs,
		logger:     logger,
	}
}

// DiscoverPlugins searches for plugins in configured directories
func (d *Discoverer) DiscoverPlugins() ([]DiscoveredPlugin, error) {
	var plugins []DiscoveredPlugin

	for _, dir := range d.pluginDirs {
		d.logger.WithField("directory", dir).Debug("Scanning for plugins")
		
		dirPlugins, err := d.scanDirectory(dir)
		if err != nil {
			d.logger.WithError(err).WithField("directory", dir).Warn("Failed to scan directory")
			continue
		}
		
		plugins = append(plugins, dirPlugins...)
	}

	d.logger.WithField("count", len(plugins)).Info("Plugin discovery completed")
	return plugins, nil
}

// scanDirectory scans a single directory for plugins
func (d *Discoverer) scanDirectory(dir string) ([]DiscoveredPlugin, error) {
	var plugins []DiscoveredPlugin

	// Check if directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return plugins, nil
	}

	// Walk through directory
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip on error
		}

		// Look for plugin.toml files
		if info.Name() == "plugin.toml" {
			plugin, err := d.loadPluginManifest(path)
			if err != nil {
				d.logger.WithError(err).WithField("path", path).Warn("Failed to load plugin manifest")
				return nil
			}
			plugins = append(plugins, *plugin)
		}

		return nil
	})

	return plugins, err
}

// loadPluginManifest loads and validates a plugin manifest
func (d *Discoverer) loadPluginManifest(manifestPath string) (*DiscoveredPlugin, error) {
	var manifest PluginManifest

	// Read manifest file
	data, err := ioutil.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	// Parse TOML
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	// Validate required fields
	if manifest.Plugin.Name == "" {
		return nil, fmt.Errorf("plugin name is required")
	}
	if manifest.Plugin.Version == "" {
		return nil, fmt.Errorf("plugin version is required")
	}
	if manifest.Plugin.Executable == "" {
		return nil, fmt.Errorf("plugin executable is required")
	}
	if manifest.Plugin.ProtocolVersion == "" {
		return nil, fmt.Errorf("protocol version is required")
	}

	// Resolve paths
	pluginDir := filepath.Dir(manifestPath)
	
	// Check for executable
	execPath := filepath.Join(pluginDir, manifest.Plugin.Executable)
	if !strings.HasPrefix(manifest.Plugin.Executable, "/") {
		// Relative path
		execPath = filepath.Join(pluginDir, manifest.Plugin.Executable)
	} else {
		// Absolute path
		execPath = manifest.Plugin.Executable
	}

	// Verify executable exists and is executable
	info, err := os.Stat(execPath)
	if err != nil {
		return nil, fmt.Errorf("plugin executable not found: %w", err)
	}
	if info.Mode()&0111 == 0 {
		return nil, fmt.Errorf("plugin file is not executable")
	}

	// Convert to absolute path
	absExecPath, err := filepath.Abs(execPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Look for config file
	configPath := filepath.Join(pluginDir, "config.toml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = ""
	}

	d.logger.WithFields(logrus.Fields{
		"name":    manifest.Plugin.Name,
		"version": manifest.Plugin.Version,
		"path":    absExecPath,
	}).Debug("Discovered plugin")

	return &DiscoveredPlugin{
		Info:           manifest.Plugin,
		ManifestPath:   manifestPath,
		ExecutablePath: absExecPath,
		ConfigPath:     configPath,
	}, nil
}

// Registry manages registered plugins
type Registry struct {
	plugins map[string]*DiscoveredPlugin
	logger  *logrus.Logger
}

// NewRegistry creates a new plugin registry
func NewRegistry(logger *logrus.Logger) *Registry {
	return &Registry{
		plugins: make(map[string]*DiscoveredPlugin),
		logger:  logger,
	}
}

// Register adds a plugin to the registry
func (r *Registry) Register(plugin DiscoveredPlugin) error {
	if _, exists := r.plugins[plugin.Info.Name]; exists {
		return fmt.Errorf("plugin %s already registered", plugin.Info.Name)
	}

	r.plugins[plugin.Info.Name] = &plugin
	r.logger.WithFields(logrus.Fields{
		"name":    plugin.Info.Name,
		"version": plugin.Info.Version,
	}).Info("Plugin registered")

	return nil
}

// Get retrieves a plugin by name
func (r *Registry) Get(name string) (*DiscoveredPlugin, bool) {
	plugin, exists := r.plugins[name]
	return plugin, exists
}

// List returns all registered plugins
func (r *Registry) List() []DiscoveredPlugin {
	var plugins []DiscoveredPlugin
	for _, plugin := range r.plugins {
		plugins = append(plugins, *plugin)
	}
	return plugins
}

// Remove unregisters a plugin
func (r *Registry) Remove(name string) bool {
	if _, exists := r.plugins[name]; exists {
		delete(r.plugins, name)
		r.logger.WithField("name", name).Info("Plugin unregistered")
		return true
	}
	return false
}

// ValidateProtocolVersion checks if a plugin's protocol version is compatible
func ValidateProtocolVersion(pluginVersion, hostVersion string) error {
	// Simple version check for now - can be enhanced later
	if pluginVersion != hostVersion {
		return fmt.Errorf("protocol version mismatch: plugin=%s, host=%s", pluginVersion, hostVersion)
	}
	return nil
}

// LoadPluginConfig loads additional configuration for a plugin
func LoadPluginConfig(configPath string) (map[string]interface{}, error) {
	config := make(map[string]interface{})
	
	if configPath == "" {
		return config, nil
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return config, nil
}