package pluginapi

import (
	"context"
	"fmt"
	"net/http"

	"github.com/carbocation/interpose"
)

// PluginManager manages plugin lifecycle with Interpose
type PluginManager struct {
	plugins    map[string]Plugin
	middleware *interpose.Middleware
	routes     map[string]http.HandlerFunc
	eventBus   *EventBus
	logger     Logger
	shutdownCh chan struct{}
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(middleware *interpose.Middleware, logger Logger) *PluginManager {
	return &PluginManager{
		plugins:    make(map[string]Plugin),
		middleware: middleware,
		routes:     make(map[string]http.HandlerFunc),
		eventBus:   NewEventBus(),
		logger:     logger,
		shutdownCh: make(chan struct{}),
	}
}

// LoadPlugin loads and initializes a plugin
func (pm *PluginManager) LoadPlugin(ctx context.Context, plugin Plugin, config map[string]interface{}) error {
	// Check dependencies
	for _, dep := range plugin.Dependencies() {
		if _, exists := pm.plugins[dep.Name]; !exists {
			return fmt.Errorf("dependency %s not loaded", dep.Name)
		}
	}

	// Create plugin host
	host := &pluginHost{
		manager: pm,
		logger:  pm.logger,
	}

	// Initialize plugin
	if err := plugin.Initialize(ctx, host, config); err != nil {
		return fmt.Errorf("failed to initialize plugin %s: %w", plugin.Name(), err)
	}

	// If it's a middleware plugin, add to Interpose chain
	if mwPlugin, ok := plugin.(MiddlewarePlugin); ok {
		mwFunc, priority := mwPlugin.Middleware()
		// Interpose will handle the middleware chain properly
		pm.middleware.Use(mwFunc)
		pm.logger.Info("Added middleware from plugin", "plugin", plugin.Name(), "priority", priority)
	}

	// If it's a handler plugin, register routes
	if handlerPlugin, ok := plugin.(HandlerPlugin); ok {
		for _, route := range handlerPlugin.Routes() {
			pm.routes[route.Pattern] = route.Handler
			pm.logger.Info("Registered route from plugin", "plugin", plugin.Name(), "pattern", route.Pattern)
		}
	}

	// Store plugin
	pm.plugins[plugin.Name()] = plugin
	pm.logger.Info("Loaded plugin", "name", plugin.Name(), "version", plugin.Version())

	return nil
}

// GetRoutes returns all registered routes
func (pm *PluginManager) GetRoutes() map[string]http.HandlerFunc {
	return pm.routes
}

// Shutdown shuts down all plugins
func (pm *PluginManager) Shutdown(ctx context.Context) error {
	close(pm.shutdownCh)

	// Shutdown plugins in reverse order
	for name, plugin := range pm.plugins {
		if err := plugin.Shutdown(ctx); err != nil {
			pm.logger.Error("Failed to shutdown plugin", "plugin", name, "error", err)
		}
	}

	return nil
}
