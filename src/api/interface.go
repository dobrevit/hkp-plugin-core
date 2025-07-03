package pluginapi

import (
	"context"
	"net/http"
	"time"
)

// Plugin is the base interface that all plugins must implement
type Plugin interface {
	// Initialize the plugin with server context and configuration
	Initialize(ctx context.Context, host PluginHost, config map[string]interface{}) error

	// Name returns the unique plugin identifier
	Name() string

	// Version returns the plugin version
	Version() string

	// Description returns human-readable plugin description
	Description() string

	// Dependencies returns required plugin dependencies
	Dependencies() []PluginDependency

	// Shutdown gracefully stops the plugin
	Shutdown(ctx context.Context) error
}

// MiddlewarePlugin is implemented by plugins that provide HTTP middleware
type MiddlewarePlugin interface {
	Plugin

	// Middleware returns the middleware function for Interpose
	// Priority determines the order (lower numbers run first)
	Middleware() (func(http.Handler) http.Handler, int)
}

// HandlerPlugin is implemented by plugins that provide HTTP handlers
type HandlerPlugin interface {
	Plugin

	// Routes returns the routes this plugin wants to register
	Routes() []PluginRoute
}

// PluginHost provides server context and services to plugins
type PluginHost interface {
	// Access storage backend
	Storage() interface{}

	// Access configuration
	Config() interface{}

	// Access metrics system
	Metrics() interface{}

	// Register periodic tasks
	RegisterTask(name string, interval time.Duration, task func(context.Context) error) error

	// Publish events to plugin system
	PublishEvent(event PluginEvent) error

	// Subscribe to plugin events
	SubscribeEvent(eventType string, handler func(PluginEvent) error) error

	// Logger returns the plugin logger
	Logger() Logger
}

// Logger interface for plugin logging
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}
