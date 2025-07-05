// Package integration provides simple Hockeypuck integration functions
package integration

import (
	"context"
	"fmt"
	"path/filepath"
	"plugin"

	log "github.com/sirupsen/logrus"

	"github.com/dobrevit/hkp-plugin-core/pkg/config"
	"github.com/dobrevit/hkp-plugin-core/pkg/events"
	pluginapi "github.com/dobrevit/hkp-plugin-core/pkg/plugin"
)

// PluginSystem represents the complete plugin system
type PluginSystem struct {
	manager  *pluginapi.PluginManager
	eventBus *events.EventBus
	plugins  map[string]pluginapi.Plugin
	logger   *log.Logger
}

// LoggerAdapter adapts logrus.Logger to the plugin.Logger interface
type LoggerAdapter struct {
	*log.Logger
}

func (l *LoggerAdapter) Info(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.Logger.Infof(msg, args...)
	} else {
		l.Logger.Info(msg)
	}
}

func (l *LoggerAdapter) Warn(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.Logger.Warnf(msg, args...)
	} else {
		l.Logger.Warn(msg)
	}
}

func (l *LoggerAdapter) Error(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.Logger.Errorf(msg, args...)
	} else {
		l.Logger.Error(msg)
	}
}

func (l *LoggerAdapter) Debug(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.Logger.Debugf(msg, args...)
	} else {
		l.Logger.Debug(msg)
	}
}

// InitializePlugins initializes the plugin system with a single call from Hockeypuck
func InitializePlugins(ctx context.Context, host pluginapi.PluginHost, settings *config.Settings) (*PluginSystem, error) {
	logger := host.Logger()

	if !settings.Plugins.Enabled {
		logger.Info("Plugin system disabled")
		return nil, nil
	}

	logger.WithFields(log.Fields{
		"directory": settings.Plugins.Directory,
		"enabled":   len(settings.Plugins.LoadOrder),
	}).Info("Initializing plugin system")

	// Create event bus
	eventBus := events.NewEventBus(logger)

	// Update host with event bus if it supports it
	if hostWithEvents, ok := host.(interface {
		SetEventBus(*events.EventBus)
	}); ok {
		hostWithEvents.SetEventBus(eventBus)
	}

	// Create plugin manager with logger adapter
	loggerAdapter := &LoggerAdapter{Logger: logger}
	manager := pluginapi.NewPluginManager(host, loggerAdapter)

	// Initialize system
	system := &PluginSystem{
		manager:  manager,
		eventBus: eventBus,
		plugins:  make(map[string]pluginapi.Plugin),
		logger:   logger,
	}

	// Load plugins in the specified order
	if err := system.loadPlugins(ctx, settings); err != nil {
		return nil, fmt.Errorf("failed to load plugins: %w", err)
	}

	logger.WithField("loaded", len(system.plugins)).Info("Plugin system initialized successfully")

	return system, nil
}

// loadPlugins loads all configured plugins
func (ps *PluginSystem) loadPlugins(ctx context.Context, settings *config.Settings) error {
	pluginDir := settings.Plugins.Directory

	for _, pluginName := range settings.Plugins.LoadOrder {
		if err := ps.loadPlugin(ctx, pluginDir, pluginName, settings); err != nil {
			ps.logger.WithFields(log.Fields{
				"plugin": pluginName,
				"error":  err,
			}).Error("Failed to load plugin")

			// Continue loading other plugins instead of failing completely
			continue
		}
	}

	return nil
}

// loadPlugin loads a single plugin
func (ps *PluginSystem) loadPlugin(ctx context.Context, pluginDir, pluginName string, settings *config.Settings) error {
	// Construct plugin path
	pluginPath := filepath.Join(pluginDir, pluginName+".so")

	ps.logger.WithFields(log.Fields{
		"plugin": pluginName,
		"path":   pluginPath,
	}).Debug("Loading plugin")

	// Load the plugin file
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to open plugin %s: %w", pluginPath, err)
	}

	// Look for the GetPlugin function
	getPluginSym, err := p.Lookup("GetPlugin")
	if err != nil {
		return fmt.Errorf("plugin %s missing GetPlugin function: %w", pluginName, err)
	}

	// Cast to the expected function type
	getPlugin, ok := getPluginSym.(func() pluginapi.Plugin)
	if !ok {
		return fmt.Errorf("plugin %s GetPlugin function has wrong signature", pluginName)
	}

	// Get the plugin instance
	pluginInstance := getPlugin()

	// Get plugin configuration
	pluginConfig := settings.GetPluginConfig(pluginName)

	// Initialize the plugin
	if err := ps.manager.LoadPlugin(ctx, pluginInstance, pluginConfig); err != nil {
		return fmt.Errorf("failed to initialize plugin %s: %w", pluginName, err)
	}

	// Store the plugin
	ps.plugins[pluginName] = pluginInstance

	ps.logger.WithFields(log.Fields{
		"plugin":  pluginName,
		"version": pluginInstance.Version(),
	}).Info("Plugin loaded successfully")

	return nil
}

// Shutdown gracefully shuts down all plugins
func (ps *PluginSystem) Shutdown(ctx context.Context) error {
	if ps == nil {
		return nil
	}

	ps.logger.Info("Shutting down plugin system")

	if err := ps.manager.Shutdown(ctx); err != nil {
		ps.logger.WithError(err).Error("Error during plugin shutdown")
		return err
	}

	ps.logger.Info("Plugin system shutdown complete")
	return nil
}

// GetPlugin returns a loaded plugin by name
func (ps *PluginSystem) GetPlugin(name string) (pluginapi.Plugin, bool) {
	if ps == nil {
		return nil, false
	}

	plugin, exists := ps.plugins[name]
	return plugin, exists
}

// ListPlugins returns all loaded plugin names
func (ps *PluginSystem) ListPlugins() []string {
	if ps == nil {
		return nil
	}

	names := make([]string, 0, len(ps.plugins))
	for name := range ps.plugins {
		names = append(names, name)
	}
	return names
}

// GetEventBus returns the event bus for external use
func (ps *PluginSystem) GetEventBus() *events.EventBus {
	if ps == nil {
		return nil
	}
	return ps.eventBus
}

// Simple integration example for Hockeypuck server.go:
//
// func (srv *Server) initPlugins(ctx context.Context) error {
//     host := NewServerPluginHost(srv)
//     settings := convertToPluginSettings(srv.settings)
//
//     pluginSystem, err := integration.InitializePlugins(ctx, host, settings)
//     if err != nil {
//         return err
//     }
//
//     srv.pluginSystem = pluginSystem
//     return nil
// }
//
// func (srv *Server) Start() error {
//     // ... existing startup code ...
//
//     if err := srv.initPlugins(context.Background()); err != nil {
//         log.WithError(err).Error("Failed to initialize plugins")
//         // Continue startup even if plugins fail
//     }
//
//     // ... rest of startup ...
// }
//
// func (srv *Server) Shutdown() error {
//     // ... existing shutdown code ...
//
//     if srv.pluginSystem != nil {
//         ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//         defer cancel()
//         srv.pluginSystem.Shutdown(ctx)
//     }
//
//     // ... rest of shutdown ...
// }
