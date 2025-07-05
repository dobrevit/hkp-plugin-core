// Package plugin provides the foundation for Hockeypuck's plugin system
package plugin

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/config"
	"github.com/dobrevit/hkp-plugin-core/pkg/events"
	"github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
	"github.com/dobrevit/hkp-plugin-core/pkg/metrics"
	log "github.com/sirupsen/logrus"
)

// Plugin represents a loadable module that extends Hockeypuck functionality
type Plugin interface {
	// Initialize the plugin with server context and configuration
	Initialize(ctx context.Context, server PluginHost, config map[string]interface{}) error

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

// PluginHost provides server context and services to plugins
type PluginHost interface {
	// Register middleware handlers
	RegisterMiddleware(path string, middleware func(http.Handler) http.Handler) error

	// Register API endpoints
	RegisterHandler(pattern string, handler http.HandlerFunc) error

	// Access storage backend
	Storage() hkpstorage.Storage

	// Access configuration
	Config() *config.Settings

	// Access metrics system
	Metrics() *metrics.Metrics

	// Access logger
	Logger() *log.Logger

	// Register periodic tasks
	RegisterTask(name string, interval time.Duration, task func(context.Context) error) error

	// Publish events to plugin system
	PublishEvent(event events.PluginEvent) error

	// Subscribe to plugin events
	SubscribeEvent(eventType string, handler events.PluginEventHandler) error

	// Subscribe to Hockeypuck-style key change notifications
	SubscribeKeyChanges(callback func(hkpstorage.KeyChange) error) error

	// Convenience methods for common events
	PublishThreatDetected(threat events.ThreatInfo) error
	PublishRateLimitViolation(violation events.RateLimitViolation) error
	PublishZTNAEvent(eventType string, ztnaEvent events.ZTNAEvent) error
}

// Legacy Settings type - deprecated, use config.Settings instead
// Kept for backward compatibility
type Settings = config.Settings

// PluginDependency represents a plugin dependency
type PluginDependency struct {
	Name     string         `json:"name"`
	Version  string         `json:"version"`
	Type     DependencyType `json:"type"`
	Optional bool           `json:"optional"`
}

// DependencyType represents the type of dependency
type DependencyType string

const (
	DependencyRequired DependencyType = "required"
	DependencyOptional DependencyType = "optional"
	DependencyConflict DependencyType = "conflict"
)

// Legacy types - use events package instead
type PluginEvent = events.PluginEvent
type PluginEventHandler = events.PluginEventHandler
type EndpointProtectionRequest = events.EndpointProtectionRequest

// Legacy constants - use events package instead
const (
	EventEndpointProtectionRequest = events.EventEndpointProtectionRequest
	EventEndpointProtectionUpdate  = events.EventEndpointProtectionUpdate
	EventEndpointAccessDenied      = events.EventEndpointAccessDenied
	EventEndpointAccessGranted     = events.EventEndpointAccessGranted
	EventSecurityThreatDetected    = events.EventSecurityThreatDetected
	EventSecurityAnomalyDetected   = events.EventSecurityAnomalyDetected
)

// Middleware plugins provide HTTP request/response processing
type MiddlewarePlugin interface {
	Plugin

	// Create middleware handler
	CreateMiddleware(config MiddlewareConfig) (func(http.Handler) http.Handler, error)

	// Middleware priority (lower numbers run first)
	Priority() int

	// Paths this middleware applies to
	ApplicablePaths() []string
}

// MiddlewareConfig provides configuration for middleware creation
type MiddlewareConfig struct {
	Path     string                 `json:"path"`
	Priority int                    `json:"priority"`
	Config   map[string]interface{} `json:"config"`
}

// CoreExtensionPlugin extends fundamental server capabilities
type CoreExtensionPlugin interface {
	Plugin

	// Extend server initialization
	ExtendServerInit(server *Server) error

	// Modify server configuration
	ModifyConfig(config *Settings) error

	// Register custom services
	RegisterServices(host PluginHost) error
}

// StoragePlugin provides custom storage implementations
type StoragePlugin interface {
	Plugin

	// Create storage backend instance
	CreateStorage(config StorageConfig) (hkpstorage.Storage, error)

	// Backend type identifier
	BackendType() string

	// Required configuration schema
	ConfigSchema() map[string]interface{}
}

// StorageConfig provides configuration for storage backend creation
type StorageConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// SecurityPlugin provides security enhancements
type SecurityPlugin interface {
	Plugin

	// Authentication providers
	CreateAuthProvider(config AuthConfig) (AuthProvider, error)

	// Audit logging enhancements
	CreateAuditLogger(config AuditConfig) (AuditLogger, error)

	// Encryption providers
	CreateEncryptionProvider(config EncryptionConfig) (EncryptionProvider, error)
}

// AuthConfig provides configuration for authentication providers
type AuthConfig struct {
	Type     string                 `json:"type"`
	Provider string                 `json:"provider"`
	Config   map[string]interface{} `json:"config"`
}

// AuthProvider interface for authentication providers
type AuthProvider interface {
	Authenticate(username, password string) (bool, error)
	ValidateToken(token string) (bool, error)
}

// AuditConfig provides configuration for audit logging
type AuditConfig struct {
	Level  string                 `json:"level"`
	Output string                 `json:"output"`
	Config map[string]interface{} `json:"config"`
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogEvent(event AuditEvent) error
}

// AuditEvent represents an audit event
type AuditEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	User      string                 `json:"user"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Result    string                 `json:"result"`
	Details   map[string]interface{} `json:"details"`
}

// EncryptionConfig provides configuration for encryption providers
type EncryptionConfig struct {
	Algorithm string                 `json:"algorithm"`
	KeySize   int                    `json:"key_size"`
	Config    map[string]interface{} `json:"config"`
}

// EncryptionProvider interface for encryption providers
type EncryptionProvider interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

// MonitoringPlugin provides observability enhancements
type MonitoringPlugin interface {
	Plugin

	// Custom metrics collectors
	CreateMetricsCollector(config MetricsConfig) (MetricsCollector, error)

	// Alert providers
	CreateAlertProvider(config AlertConfig) (AlertProvider, error)

	// Dashboard providers
	CreateDashboardProvider(config DashboardConfig) (DashboardProvider, error)
}

// MetricsConfig provides configuration for metrics collectors
type MetricsConfig struct {
	Type     string                 `json:"type"`
	Endpoint string                 `json:"endpoint"`
	Config   map[string]interface{} `json:"config"`
}

// MetricsCollector interface for custom metrics
type MetricsCollector interface {
	Collect() (map[string]interface{}, error)
	Name() string
}

// AlertConfig provides configuration for alert providers
type AlertConfig struct {
	Provider string                 `json:"provider"`
	Webhook  string                 `json:"webhook"`
	Config   map[string]interface{} `json:"config"`
}

// AlertProvider interface for alerting
type AlertProvider interface {
	SendAlert(alert Alert) error
}

// Alert represents an alert
type Alert struct {
	Level       string                 `json:"level"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Tags        map[string]string      `json:"tags"`
	Data        map[string]interface{} `json:"data"`
}

// DashboardConfig provides configuration for dashboard providers
type DashboardConfig struct {
	Type     string                 `json:"type"`
	Endpoint string                 `json:"endpoint"`
	Config   map[string]interface{} `json:"config"`
}

// DashboardProvider interface for dashboard providers
type DashboardProvider interface {
	CreateDashboard(config DashboardConfig) error
	UpdateDashboard(id string, config DashboardConfig) error
}

// BasePlugin provides a base implementation for plugins
type BasePlugin struct {
	name        string
	version     string
	description string
	initialized bool
	mu          sync.RWMutex
}

// Name returns the plugin name
func (p *BasePlugin) Name() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.name
}

// Version returns the plugin version
func (p *BasePlugin) Version() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.version
}

// Description returns the plugin description
func (p *BasePlugin) Description() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.description
}

// SetInfo sets the plugin information
func (p *BasePlugin) SetInfo(name, version, description string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.name = name
	p.version = version
	p.description = description
}

// IsInitialized returns whether the plugin is initialized
func (p *BasePlugin) IsInitialized() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.initialized
}

// SetInitialized sets the initialization status
func (p *BasePlugin) SetInitialized(initialized bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initialized = initialized
}

// Dependencies returns an empty dependency list by default
func (p *BasePlugin) Dependencies() []PluginDependency {
	return []PluginDependency{}
}

// Default implementation of Shutdown
func (p *BasePlugin) Shutdown(ctx context.Context) error {
	p.SetInitialized(false)
	return nil
}

// Plugin registry for managing plugins
type PluginRegistry struct {
	plugins   map[string]Plugin
	order     []string
	mu        sync.RWMutex
	host      PluginHost
	lifecycle *PluginLifecycle
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry(host PluginHost) *PluginRegistry {
	registry := &PluginRegistry{
		plugins: make(map[string]Plugin),
		host:    host,
	}
	registry.lifecycle = NewPluginLifecycle(registry)
	return registry
}

// Register registers a plugin
func (r *PluginRegistry) Register(plugin Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := plugin.Name()
	if name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	r.plugins[name] = plugin
	r.order = append(r.order, name)

	return nil
}

// Get retrieves a plugin by name
func (r *PluginRegistry) Get(name string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	plugin, exists := r.plugins[name]
	return plugin, exists
}

// List returns all registered plugins
func (r *PluginRegistry) List() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugins := make([]Plugin, 0, len(r.plugins))
	for _, name := range r.order {
		if plugin, exists := r.plugins[name]; exists {
			plugins = append(plugins, plugin)
		}
	}
	return plugins
}

// Initialize initializes all plugins
func (r *PluginRegistry) Initialize(ctx context.Context, configs map[string]map[string]interface{}) error {
	return r.lifecycle.Initialize(ctx, configs)
}

// Shutdown shuts down all plugins
func (r *PluginRegistry) Shutdown(ctx context.Context) error {
	return r.lifecycle.Shutdown(ctx)
}

// Plugin lifecycle management
type PluginLifecycle struct {
	registry     *PluginRegistry
	dependencies *DependencyGraph
}

// NewPluginLifecycle creates a new plugin lifecycle manager
func NewPluginLifecycle(registry *PluginRegistry) *PluginLifecycle {
	return &PluginLifecycle{
		registry:     registry,
		dependencies: NewDependencyGraph(),
	}
}

// Initialize initializes plugins in dependency order
func (l *PluginLifecycle) Initialize(ctx context.Context, configs map[string]map[string]interface{}) error {
	plugins := l.registry.List()

	// Build dependency graph
	for _, plugin := range plugins {
		l.dependencies.AddNode(plugin.Name())
		for _, dep := range plugin.Dependencies() {
			if dep.Type != DependencyConflict {
				l.dependencies.AddEdge(dep.Name, plugin.Name())
			}
		}
	}

	// Get initialization order
	order, err := l.dependencies.TopologicalSort()
	if err != nil {
		return fmt.Errorf("failed to resolve plugin dependencies: %w", err)
	}

	// Initialize plugins in order
	for _, name := range order {
		plugin, exists := l.registry.Get(name)
		if !exists {
			continue // Skip missing dependencies
		}

		config := configs[name]
		if config == nil {
			config = make(map[string]interface{})
		}

		if err := plugin.Initialize(ctx, l.registry.host, config); err != nil {
			return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
		}
	}

	return nil
}

// Shutdown shuts down plugins in reverse dependency order
func (l *PluginLifecycle) Shutdown(ctx context.Context) error {
	plugins := l.registry.List()

	// Shutdown in reverse order
	for i := len(plugins) - 1; i >= 0; i-- {
		plugin := plugins[i]
		if err := plugin.Shutdown(ctx); err != nil {
			// Log error but continue shutdown
			log.WithFields(log.Fields{
				"plugin": plugin.Name(),
				"error":  err,
			}).Error("Failed to shutdown plugin")
		}
	}

	return nil
}

// DependencyGraph represents a dependency graph for plugins
type DependencyGraph struct {
	nodes map[string]bool
	edges map[string][]string
	mu    sync.RWMutex
}

// NewDependencyGraph creates a new dependency graph
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		nodes: make(map[string]bool),
		edges: make(map[string][]string),
	}
}

// AddNode adds a node to the graph
func (g *DependencyGraph) AddNode(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[name] = true
	if g.edges[name] == nil {
		g.edges[name] = make([]string, 0)
	}
}

// AddEdge adds an edge from 'from' to 'to'
func (g *DependencyGraph) AddEdge(from, to string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges[from] = append(g.edges[from], to)
}

// TopologicalSort returns a topologically sorted list of nodes
func (g *DependencyGraph) TopologicalSort() ([]string, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	inDegree := make(map[string]int)
	for node := range g.nodes {
		inDegree[node] = 0
	}

	for _, neighbors := range g.edges {
		for _, neighbor := range neighbors {
			inDegree[neighbor]++
		}
	}

	queue := make([]string, 0)
	for node, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, node)
		}
	}

	result := make([]string, 0, len(g.nodes))
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		result = append(result, current)

		for _, neighbor := range g.edges[current] {
			inDegree[neighbor]--
			if inDegree[neighbor] == 0 {
				queue = append(queue, neighbor)
			}
		}
	}

	if len(result) != len(g.nodes) {
		return nil, fmt.Errorf("circular dependency detected")
	}

	return result, nil
}

// Server represents the Hockeypuck server (placeholder interface)
type Server struct {
	// Server implementation details would go here
}

// PluginManager manages the entire plugin system
type PluginManager struct {
	registry *PluginRegistry
	host     PluginHost
	logger   Logger
	mu       sync.RWMutex
}

// Logger interface for plugin logging
type Logger interface {
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(host PluginHost, logger Logger) *PluginManager {
	registry := NewPluginRegistry(host)
	return &PluginManager{
		registry: registry,
		host:     host,
		logger:   logger,
	}
}

// Register registers a plugin with the manager
func (pm *PluginManager) Register(plugin Plugin) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.registry.Register(plugin)
}

// Initialize initializes all registered plugins
func (pm *PluginManager) Initialize(ctx context.Context, configs map[string]map[string]interface{}) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.registry.Initialize(ctx, configs)
}

// Shutdown shuts down all plugins
func (pm *PluginManager) Shutdown(ctx context.Context) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.registry.Shutdown(ctx)
}

// GetPlugin gets a plugin by name
func (pm *PluginManager) GetPlugin(name string) (Plugin, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.registry.Get(name)
}

// ListPlugins lists all registered plugins
func (pm *PluginManager) ListPlugins() []Plugin {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.registry.List()
}

// LoadPlugin loads and initializes a plugin
func (pm *PluginManager) LoadPlugin(ctx context.Context, plugin Plugin, config map[string]interface{}) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Register the plugin
	if err := pm.registry.Register(plugin); err != nil {
		return err
	}

	// Initialize the plugin
	return plugin.Initialize(ctx, pm.host, config)
}

// GetRoutes returns HTTP routes from all plugins
func (pm *PluginManager) GetRoutes() map[string]http.HandlerFunc {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	routes := make(map[string]http.HandlerFunc)
	// This is a simplified implementation
	// In practice, you'd collect routes from plugins that implement HTTP interfaces
	return routes
}

// Global plugin registry
var globalRegistry *PluginRegistry

// Register registers a plugin globally
func Register(plugin Plugin) {
	if globalRegistry == nil {
		// Initialize with a nil host - will be set when server starts
		globalRegistry = NewPluginRegistry(nil)
	}
	if err := globalRegistry.Register(plugin); err != nil {
		panic(fmt.Sprintf("Failed to register plugin %s: %v", plugin.Name(), err))
	}
}

// GetRegistry returns the global plugin registry
func GetRegistry() *PluginRegistry {
	return globalRegistry
}

// SetHost sets the plugin host for the global registry
func SetHost(host PluginHost) {
	if globalRegistry != nil {
		globalRegistry.host = host
	}
}
