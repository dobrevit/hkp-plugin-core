// Example integration showing how all the components work together
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"plugin"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dobrevit/hkp-plugin-core/config"
	"github.com/dobrevit/hkp-plugin-core/internal/metrics"
	pluginapi "github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/pkg/ratelimit"
	"github.com/dobrevit/hkp-plugin-core/pkg/storage"
	// Plugins will be loaded dynamically from .so files
)

// Server represents the main Hockeypuck server
type Server struct {
	config      *config.Config
	rateLimiter *ratelimit.RateLimiter
	storage     storage.Storage
	metrics     *metrics.Metrics
	pluginHost  pluginapi.PluginHost
	httpServer  *http.Server
	logger      *slog.Logger
	startTime   time.Time

	// Plugin system
	pluginRegistry *pluginapi.PluginRegistry

	// Enhanced plugin management
	pluginStates   map[string]PluginState
	rollbackStates map[string]*PluginSnapshot
	activeRequests map[string]map[string]*ActiveRequest
	requestDrainer *RequestDrainer
	stateMutex     sync.RWMutex
	acceptingReqs  map[string]bool
	drainMutex     sync.RWMutex
}

// Plugin state management
type PluginState int

const (
	PluginStateLoading PluginState = iota
	PluginStateActive
	PluginStateReloading
	PluginStateUnloading
	PluginStateFailed
	PluginStateDisabled
)

type PluginSnapshot struct {
	PluginName    string
	Configuration map[string]any
	State         PluginState
	Timestamp     time.Time
	Version       int
}

type ActiveRequest struct {
	ID         string
	StartTime  time.Time
	Context    context.Context
	Cancel     context.CancelFunc
	PluginName string
}

// Request draining for graceful plugin transitions
type RequestDrainer struct {
	activeRequests map[string]*ActiveRequest
	drainTimeout   time.Duration
	pollInterval   time.Duration
	mutex          sync.RWMutex
}

func NewRequestDrainer() *RequestDrainer {
	return &RequestDrainer{
		activeRequests: make(map[string]*ActiveRequest),
		drainTimeout:   60 * time.Second,
		pollInterval:   500 * time.Millisecond,
	}
}

// ServerPluginHost implements the PluginHost interface for the server
type ServerPluginHost struct {
	server        *Server
	middlewares   []func(http.Handler) http.Handler // Changed to slice to allow multiple middlewares
	handlers      map[string]http.HandlerFunc
	tasks         map[string]TaskInfo
	eventHandlers map[string][]pluginapi.PluginEventHandler
}

type TaskInfo struct {
	Name     string
	Interval time.Duration
	Task     func(context.Context) error
	Cancel   context.CancelFunc
}

// NewServerPluginHost creates a new server plugin host
func NewServerPluginHost(server *Server) *ServerPluginHost {
	return &ServerPluginHost{
		server:        server,
		middlewares:   make([]func(http.Handler) http.Handler, 0),
		handlers:      make(map[string]http.HandlerFunc),
		tasks:         make(map[string]TaskInfo),
		eventHandlers: make(map[string][]pluginapi.PluginEventHandler),
	}
}

// Implement PluginHost interface
func (ph *ServerPluginHost) RegisterMiddleware(path string, middleware func(http.Handler) http.Handler) error {
	ph.server.logger.Debug("Registering middleware", "path", path)
	ph.middlewares = append(ph.middlewares, middleware)
	ph.server.logger.Debug("Total middlewares registered", "count", len(ph.middlewares))
	return nil
}

func (ph *ServerPluginHost) RegisterHandler(pattern string, handler http.HandlerFunc) error {
	ph.handlers[pattern] = handler
	return nil
}

func (ph *ServerPluginHost) Storage() storage.Storage {
	return ph.server.storage
}

func (ph *ServerPluginHost) Config() *pluginapi.Settings {
	// Convert from our config.Config to pluginapi.Settings
	return &pluginapi.Settings{
		Bind:    ph.server.config.Server.Bind,
		DataDir: ph.server.config.Server.DataDir,
	}
}

func (ph *ServerPluginHost) Metrics() *metrics.Metrics {
	return ph.server.metrics
}

func (ph *ServerPluginHost) Logger() *slog.Logger {
	return ph.server.logger
}

func (ph *ServerPluginHost) RegisterTask(name string, interval time.Duration, task func(context.Context) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	ph.tasks[name] = TaskInfo{
		Name:     name,
		Interval: interval,
		Task:     task,
		Cancel:   cancel,
	}

	// Start the task
	go ph.runTask(ctx, name, interval, task)
	return nil
}

func (ph *ServerPluginHost) runTask(ctx context.Context, name string, interval time.Duration, task func(context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := task(ctx); err != nil {
				slog.Error("Task error", "task", name, "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (ph *ServerPluginHost) PublishEvent(event pluginapi.PluginEvent) error {
	handlers := ph.eventHandlers[event.Type]
	for _, handler := range handlers {
		if err := handler(event); err != nil {
			slog.Error("Event handler error", "event_type", event.Type, "error", err)
		}
	}
	return nil
}

func (ph *ServerPluginHost) SubscribeEvent(eventType string, handler pluginapi.PluginEventHandler) error {
	ph.eventHandlers[eventType] = append(ph.eventHandlers[eventType], handler)
	return nil
}

// NewServer creates a new server instance
func NewServer(cfg *config.Config) *Server {
	// Initialize metrics
	metricsSystem := metrics.NewMetrics()

	// Initialize storage (using no-op for this example)
	storageSystem := &storage.NoOpStorage{}

	// Initialize structured logger
	var level slog.Level
	switch cfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     level,
		AddSource: false,
	}))

	server := &Server{
		config:         cfg,
		storage:        storageSystem,
		metrics:        metricsSystem,
		logger:         logger,
		startTime:      time.Now(),
		pluginStates:   make(map[string]PluginState),
		rollbackStates: make(map[string]*PluginSnapshot),
		activeRequests: make(map[string]map[string]*ActiveRequest),
		acceptingReqs:  make(map[string]bool),
		requestDrainer: NewRequestDrainer(),
	}

	// Initialize plugin host
	server.pluginHost = NewServerPluginHost(server)

	// Initialize plugin registry with the host
	server.pluginRegistry = pluginapi.NewPluginRegistry(server.pluginHost)

	return server
}

// Initialize the server
func (s *Server) Initialize() error {
	// Initialize rate limiter from config
	rateLimitConfig := ratelimit.DefaultConfig()
	rateLimitConfig.Backend.Type = s.config.RateLimit.Backend.Type

	rateLimiter, err := ratelimit.New(rateLimitConfig)
	if err != nil {
		return err
	}
	s.rateLimiter = rateLimiter

	// Set plugin host on global registry
	pluginapi.SetHost(s.pluginHost)

	// Load plugins from .so files
	pluginDir := s.config.Plugins.Directory
	s.logger.Info("Loading dynamic plugins", "directory", pluginDir)
	if err := s.loadDynamicPlugins(pluginDir); err != nil {
		s.logger.Warn("Failed to load some plugins", "error", err)
	}

	// List all registered plugins
	if s.pluginRegistry != nil {
		s.logger.Info("Plugins registered in server registry after dynamic loading:")
		for _, p := range s.pluginRegistry.List() {
			s.logger.Info("Plugin registered", "name", p.Name(), "version", p.Version())
		}
	}

	// Use plugin configurations from config file
	pluginConfigs := s.config.Plugins.Config

	// Initialize plugins with configuration
	s.logger.Info("Initializing plugins with configuration")

	// Try to initialize plugins individually to bypass dependency issues
	ctx := context.Background()
	for _, p := range s.pluginRegistry.List() {
		s.logger.Info("Initializing plugin", "name", p.Name())

		// Initialize plugin state tracking
		s.stateMutex.Lock()
		s.pluginStates[p.Name()] = PluginStateLoading
		s.activeRequests[p.Name()] = make(map[string]*ActiveRequest)
		s.acceptingReqs[p.Name()] = false
		s.stateMutex.Unlock()

		// Get config for this plugin
		var config map[string]interface{}
		if cfg, exists := pluginConfigs[p.Name()]; exists {
			config = cfg
		} else {
			config = make(map[string]interface{})
		}

		if err := p.Initialize(ctx, s.pluginHost, config); err != nil {
			s.logger.Error("Failed to initialize plugin", "name", p.Name(), "error", err)
			s.stateMutex.Lock()
			s.pluginStates[p.Name()] = PluginStateFailed
			s.stateMutex.Unlock()
		} else {
			s.logger.Info("Successfully initialized plugin", "name", p.Name())
			s.stateMutex.Lock()
			s.pluginStates[p.Name()] = PluginStateActive
			s.acceptingReqs[p.Name()] = true
			s.stateMutex.Unlock()
		}
	}

	// Log registered handlers
	if hostImpl, ok := s.pluginHost.(*ServerPluginHost); ok {
		s.logger.Info("Registered plugin handlers", "count", len(hostImpl.handlers))
		for pattern := range hostImpl.handlers {
			s.logger.Info("Plugin handler registered", "pattern", pattern)
		}
	}

	return nil
}

// loadDynamicPlugins loads plugins from .so files in the specified directory
func (s *Server) loadDynamicPlugins(pluginDir string) error {
	// Check if plugin directory exists
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		slog.Info("Plugin directory does not exist, skipping dynamic plugin loading", "dir", pluginDir)
		return nil
	}

	// Find all .so files in the plugin directory
	pattern := filepath.Join(pluginDir, "*.so")
	pluginFiles, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to search for plugin files: %w", err)
	}

	if len(pluginFiles) == 0 {
		slog.Info("No plugin files found", "dir", pluginDir, "pattern", "*.so")
		return nil
	}

	// Load each plugin
	for _, pluginFile := range pluginFiles {
		if err := s.loadPlugin(pluginFile); err != nil {
			slog.Error("Failed to load plugin", "file", pluginFile, "error", err)
			continue // Continue loading other plugins
		}
		slog.Info("Successfully loaded plugin", "file", pluginFile)
	}

	return nil
}

// loadPlugin loads a single plugin from a .so file
func (s *Server) loadPlugin(pluginFile string) error {
	// Load the plugin .so file
	p, err := plugin.Open(pluginFile)
	if err != nil {
		return fmt.Errorf("failed to open plugin file %s: %w", pluginFile, err)
	}

	// Look for the GetPlugin function
	getPluginSymbol, err := p.Lookup("GetPlugin")
	if err != nil {
		return fmt.Errorf("plugin %s does not export GetPlugin function: %w", pluginFile, err)
	}

	// Cast to the expected function type
	getPlugin, ok := getPluginSymbol.(func() pluginapi.Plugin)
	if !ok {
		return fmt.Errorf("plugin %s GetPlugin function has wrong signature", pluginFile)
	}

	// Get the plugin instance
	pluginInstance := getPlugin()
	if pluginInstance == nil {
		return fmt.Errorf("plugin %s GetPlugin returned nil", pluginFile)
	}

	// Register the plugin
	if err := s.pluginRegistry.Register(pluginInstance); err != nil {
		return fmt.Errorf("failed to register plugin from %s: %w", pluginFile, err)
	}

	return nil
}

// Start the server
func (s *Server) Start() error {
	// Start rate limiter
	s.rateLimiter.Start()

	// Create HTTP handler with middleware chain
	handler := s.createHandler()

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:    s.config.Server.Bind,
		Handler: handler,
	}

	// Start HTTP server
	go func() {
		s.logger.Info("Starting HTTP server", "addr", s.config.Server.Bind)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server error", "error", err)
		}
	}()

	return nil
}

// Create the HTTP handler with middleware chain
func (s *Server) createHandler() http.Handler {
	mux := http.NewServeMux()

	// Register core endpoints
	mux.HandleFunc("/pks/add", s.handleKeyAdd)
	mux.HandleFunc("/pks/lookup", s.handleKeyLookup)
	mux.HandleFunc("/pks/stats", s.handleStats)
	mux.Handle("/metrics", s.metrics.PrometheusHandler())

	// Register plugin management endpoints
	mux.HandleFunc("/plugins/status", s.handlePluginsStatus)
	mux.HandleFunc("/plugins/list", s.handlePluginsList)
	mux.HandleFunc("/plugins/health", s.handlePluginsHealth)
	mux.HandleFunc("/plugins/reload", s.handlePluginReload)
	mux.HandleFunc("/plugins/config", s.handlePluginConfig)

	// Register plugin handlers
	if hostImpl, ok := s.pluginHost.(*ServerPluginHost); ok {
		for pattern, handler := range hostImpl.handlers {
			mux.HandleFunc(pattern, handler)
		}
	}

	// Build middleware chain
	var handler http.Handler = mux

	// Apply plugin middlewares with request tracking
	var middlewares []func(http.Handler) http.Handler
	if hostImpl, ok := s.pluginHost.(*ServerPluginHost); ok {
		middlewares = hostImpl.middlewares
		if len(middlewares) > 0 {
			s.logger.Debug("Applying registered middlewares", "count", len(middlewares))
		}
	}

	// Apply request tracking middleware first
	handler = s.requestTrackingMiddleware(handler)

	// Apply plugin middlewares (in reverse order so they execute in registration order)
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}

	// Apply core rate limiting middleware
	handler = s.rateLimiter.Middleware()(handler)

	// Apply metrics middleware
	handler = s.metricsMiddleware(handler)

	// Apply HTTP request logging middleware
	handler = s.loggingMiddleware(handler)

	return handler
}

// Core HTTP handlers
func (s *Server) handleKeyAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Key submission logic would go here
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Key submitted successfully"))
}

func (s *Server) handleKeyLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Key lookup logic would go here
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Key lookup results"))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	// Get rate limiting stats
	rlStats, err := s.rateLimiter.GetStats()
	if err != nil {
		http.Error(w, "Failed to get stats", http.StatusInternalServerError)
		return
	}

	// Get metrics
	metricsData, err := s.metrics.Collect()
	if err != nil {
		http.Error(w, "Failed to get metrics", http.StatusInternalServerError)
		return
	}

	// Combine stats
	stats := map[string]interface{}{
		"rateLimit": rlStats,
		"metrics":   metricsData,
		"server": map[string]interface{}{
			"uptime":  time.Since(s.startTime).String(),
			"version": "2.0.0",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	// In a real implementation, you'd use json.NewEncoder(w).Encode(stats)
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, "Failed to encode stats", http.StatusInternalServerError)
		return
	}
}

// Plugin management endpoints

// handlePluginsStatus provides overall plugin system status
func (s *Server) handlePluginsStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Enhanced status with state information
	s.stateMutex.RLock()
	stateInfo := make(map[string]string)
	for pluginName, state := range s.pluginStates {
		stateInfo[pluginName] = s.getStateString(state)
	}
	s.stateMutex.RUnlock()

	status := map[string]any{
		"plugin_system": map[string]any{
			"enabled":         true,
			"total_plugins":   len(s.pluginRegistry.List()),
			"active_plugins":  s.countActivePlugins(),
			"plugin_dir":      s.config.Plugins.Directory,
			"active_requests": s.getActiveRequestCount(),
			"plugin_states":   stateInfo,
		},
		"health_status": s.getPluginHealthSummary(),
		"uptime":        time.Since(s.startTime).String(),
		"timestamp":     time.Now().Unix(),
		"draining": map[string]any{
			"timeout":       s.requestDrainer.drainTimeout.String(),
			"poll_interval": s.requestDrainer.pollInterval.String(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, "Failed to encode plugin status", http.StatusInternalServerError)
		return
	}
}

// handlePluginsList provides detailed list of all plugins
func (s *Server) handlePluginsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	plugins := []map[string]any{}
	for _, plugin := range s.pluginRegistry.List() {
		pluginInfo := map[string]any{
			"name":        plugin.Name(),
			"version":     plugin.Version(),
			"description": plugin.Description(),
			"status":      "active", // All loaded plugins are considered active
			"health":      s.getPluginHealth(plugin.Name()),
		}
		plugins = append(plugins, pluginInfo)
	}

	response := map[string]any{
		"plugins":     plugins,
		"total_count": len(plugins),
		"timestamp":   time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode plugins list", http.StatusInternalServerError)
		return
	}
}

// handlePluginsHealth provides health check for all plugins
func (s *Server) handlePluginsHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]any{
		"overall_status": "healthy", // Will be determined by individual plugin health
		"plugins":        map[string]any{},
		"timestamp":      time.Now().Unix(),
	}

	overallHealthy := true
	pluginHealthMap := make(map[string]any)

	for _, plugin := range s.pluginRegistry.List() {
		pluginHealth := s.getPluginHealth(plugin.Name())
		pluginHealthMap[plugin.Name()] = pluginHealth

		if status, ok := pluginHealth["status"].(string); ok && status != "healthy" {
			overallHealthy = false
		}
	}

	health["plugins"] = pluginHealthMap
	if !overallHealthy {
		health["overall_status"] = "degraded"
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		http.Error(w, "Failed to encode health status", http.StatusInternalServerError)
		return
	}
}

// Helper methods for plugin management

func (s *Server) countActivePlugins() int {
	// All loaded plugins are considered active
	return len(s.pluginRegistry.List())
}

func (s *Server) getPluginHealthSummary() map[string]any {
	healthy := 0
	total := len(s.pluginRegistry.List())

	for _, plugin := range s.pluginRegistry.List() {
		health := s.getPluginHealth(plugin.Name())
		if status, ok := health["status"].(string); ok && status == "healthy" {
			healthy++
		}
	}

	return map[string]any{
		"healthy_count":   healthy,
		"unhealthy_count": total - healthy,
		"total_count":     total,
		"overall_status": func() string {
			if healthy == total {
				return "healthy"
			} else if healthy > 0 {
				return "degraded"
			}
			return "unhealthy"
		}(),
	}
}

func (s *Server) getPluginHealth(pluginName string) map[string]any {
	// Enhanced health check with state tracking
	s.stateMutex.RLock()
	state, stateExists := s.pluginStates[pluginName]
	accepting, acceptingExists := s.acceptingReqs[pluginName]
	s.stateMutex.RUnlock()

	status := "healthy"
	if !stateExists || state == PluginStateFailed {
		status = "unhealthy"
	} else if state == PluginStateReloading || state == PluginStateLoading {
		status = "transitioning"
	} else if !acceptingExists || !accepting {
		status = "degraded"
	}

	health := map[string]any{
		"status":             status,
		"state":              s.getStateString(state),
		"accepting_requests": accepting,
		"last_check":         time.Now().Unix(),
		"checks":             map[string]any{},
	}

	// Check if plugin has registered handlers
	if hostImpl, ok := s.pluginHost.(*ServerPluginHost); ok {
		handlerCount := 0
		for pattern := range hostImpl.handlers {
			// Count handlers that might belong to this plugin
			if strings.Contains(pattern, strings.ToLower(pluginName)) {
				handlerCount++
			}
		}
		health["checks"].(map[string]any)["handlers_registered"] = handlerCount > 0
		health["checks"].(map[string]any)["handler_count"] = handlerCount
	}

	// Check if plugin has active tasks
	if hostImpl, ok := s.pluginHost.(*ServerPluginHost); ok {
		taskCount := 0
		for taskName := range hostImpl.tasks {
			if strings.Contains(taskName, pluginName) {
				taskCount++
			}
		}
		health["checks"].(map[string]any)["background_tasks"] = taskCount
	}

	// Add active request count
	s.stateMutex.RLock()
	if activeReqs, exists := s.activeRequests[pluginName]; exists {
		health["checks"].(map[string]any)["active_requests"] = len(activeReqs)
	} else {
		health["checks"].(map[string]any)["active_requests"] = 0
	}
	s.stateMutex.RUnlock()

	return health
}

func (s *Server) getStateString(state PluginState) string {
	switch state {
	case PluginStateLoading:
		return "loading"
	case PluginStateActive:
		return "active"
	case PluginStateReloading:
		return "reloading"
	case PluginStateUnloading:
		return "unloading"
	case PluginStateFailed:
		return "failed"
	case PluginStateDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

// handlePluginReload provides hot reload capability for individual plugins with graceful draining
func (s *Server) handlePluginReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pluginName := r.URL.Query().Get("plugin")
	if pluginName == "" {
		http.Error(w, "Plugin name is required", http.StatusBadRequest)
		return
	}

	result := map[string]any{
		"plugin":    pluginName,
		"timestamp": time.Now().Unix(),
	}

	// Find the plugin
	var targetPlugin pluginapi.Plugin
	for _, plugin := range s.pluginRegistry.List() {
		if plugin.Name() == pluginName {
			targetPlugin = plugin
			break
		}
	}

	if targetPlugin == nil {
		result["status"] = "error"
		result["message"] = "Plugin not found"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(result)
		return
	}

	s.logger.Info("Attempting to reload plugin with graceful draining", "plugin", pluginName)

	// Create rollback state before making changes
	if err := s.createRollbackSnapshot(pluginName); err != nil {
		s.logger.Warn("Failed to create rollback snapshot", "plugin", pluginName, "error", err)
	}

	// Transition to reloading state and drain requests
	if err := s.transitionToReloading(pluginName); err != nil {
		result["status"] = "error"
		result["message"] = "Failed to transition to reloading: " + err.Error()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(result)
		return
	}

	// Graceful shutdown with request draining
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := targetPlugin.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("Failed to shutdown plugin for reload", "plugin", pluginName, "error", err)
		// Attempt rollback
		s.rollbackPlugin(pluginName)
		result["status"] = "error"
		result["message"] = "Failed to shutdown plugin: " + err.Error()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(result)
		return
	}

	// Re-initialize the plugin with current configuration
	var config map[string]any
	if cfg, exists := s.config.Plugins.Config[pluginName]; exists {
		config = cfg
	} else {
		config = make(map[string]any)
	}

	if err := targetPlugin.Initialize(context.Background(), s.pluginHost, config); err != nil {
		s.logger.Error("Failed to reinitialize plugin after reload", "plugin", pluginName, "error", err)
		// Attempt rollback
		s.rollbackPlugin(pluginName)
		result["status"] = "error"
		result["message"] = "Failed to reinitialize plugin: " + err.Error()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(result)
		return
	}

	// Transition back to active state
	s.stateMutex.Lock()
	s.pluginStates[pluginName] = PluginStateActive
	s.acceptingReqs[pluginName] = true
	s.stateMutex.Unlock()

	s.logger.Info("Plugin reloaded successfully", "plugin", pluginName)
	result["status"] = "success"
	result["message"] = "Plugin reloaded successfully with graceful draining"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handlePluginConfig provides configuration management for plugins
func (s *Server) handlePluginConfig(w http.ResponseWriter, r *http.Request) {
	pluginName := r.URL.Query().Get("plugin")
	if pluginName == "" {
		http.Error(w, "Plugin name is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Get current plugin configuration
		config, exists := s.config.Plugins.Config[pluginName]
		if !exists {
			config = make(map[string]any)
		}

		response := map[string]any{
			"plugin":    pluginName,
			"config":    config,
			"timestamp": time.Now().Unix(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	case http.MethodPut:
		// Update plugin configuration
		var newConfig map[string]any
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, "Invalid JSON configuration", http.StatusBadRequest)
			return
		}

		// Update configuration
		s.config.Plugins.Config[pluginName] = newConfig

		// Find and reinitialize the plugin with new config
		var targetPlugin pluginapi.Plugin
		for _, plugin := range s.pluginRegistry.List() {
			if plugin.Name() == pluginName {
				targetPlugin = plugin
				break
			}
		}

		result := map[string]any{
			"plugin":    pluginName,
			"timestamp": time.Now().Unix(),
		}

		if targetPlugin != nil {
			// Shutdown and reinitialize with new config
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := targetPlugin.Shutdown(shutdownCtx); err != nil {
				s.logger.Error("Failed to shutdown plugin for config update", "plugin", pluginName, "error", err)
			}

			if err := targetPlugin.Initialize(context.Background(), s.pluginHost, newConfig); err != nil {
				s.logger.Error("Failed to reinitialize plugin with new config", "plugin", pluginName, "error", err)
				result["status"] = "error"
				result["message"] = "Failed to apply new configuration: " + err.Error()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(result)
				return
			}

			s.logger.Info("Plugin configuration updated successfully", "plugin", pluginName)
			result["status"] = "success"
			result["message"] = "Configuration updated and plugin reloaded"
		} else {
			result["status"] = "warning"
			result["message"] = "Configuration updated but plugin not found for reload"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Metrics middleware
func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response recorder to capture status code
		recorder := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request
		next.ServeHTTP(recorder, r)

		// Record metrics
		duration := time.Since(start)
		s.metrics.HTTPMetrics.RequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration.Seconds())
		s.metrics.HTTPMetrics.RequestsTotal.WithLabelValues(r.Method, r.URL.Path, statusClass(recorder.statusCode)).Inc()
	})
}

// loggingMiddleware provides HTTP request logging similar to Hockeypuck
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Extract client IP
		clientIP := s.extractClientIP(r)

		// Create response recorder to capture status code and size
		recorder := &loggingResponseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			responseSize:   0,
		}

		// Process request
		next.ServeHTTP(recorder, r)

		// Log the request in a format similar to Apache/Nginx access logs
		duration := time.Since(start)

		s.logger.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"query", r.URL.RawQuery,
			"status", recorder.statusCode,
			"size", recorder.responseSize,
			"duration", duration.String(),
			"client_ip", clientIP,
			"user_agent", r.UserAgent(),
			"referer", r.Referer(),
			"proto", r.Proto,
		)
	})
}

// loggingResponseRecorder extends responseRecorder to capture response size
type loggingResponseRecorder struct {
	http.ResponseWriter
	statusCode   int
	responseSize int64
}

func (r *loggingResponseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *loggingResponseRecorder) Write(data []byte) (int, error) {
	n, err := r.ResponseWriter.Write(data)
	r.responseSize += int64(n)
	return n, err
}

// extractClientIP extracts the real client IP from request headers
func (s *Server) extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies/load balancers)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header (nginx proxy)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}

// Response recorder for capturing status codes
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// Helper function to get status class
func statusClass(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "2xx"
	case statusCode >= 300 && statusCode < 400:
		return "3xx"
	case statusCode >= 400 && statusCode < 500:
		return "4xx"
	case statusCode >= 500:
		return "5xx"
	default:
		return "unknown"
	}
}

// Request tracking middleware for graceful plugin transitions
func (s *Server) requestTrackingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate unique request ID
		requestID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), r.RemoteAddr)

		// Create request context with cancellation
		reqCtx, cancel := context.WithCancel(r.Context())
		defer cancel()

		// Track request in drainer
		req := &ActiveRequest{
			ID:        requestID,
			StartTime: time.Now(),
			Context:   reqCtx,
			Cancel:    cancel,
		}

		s.requestDrainer.mutex.Lock()
		s.requestDrainer.activeRequests[requestID] = req
		s.requestDrainer.mutex.Unlock()

		// Remove request when done
		defer func() {
			s.requestDrainer.mutex.Lock()
			delete(s.requestDrainer.activeRequests, requestID)
			s.requestDrainer.mutex.Unlock()
		}()

		// Update request context
		r = r.WithContext(reqCtx)

		next.ServeHTTP(w, r)
	})
}

// Enhanced state management functions
func (s *Server) transitionToReloading(pluginName string) error {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()

	// Stop accepting new requests for this plugin
	s.acceptingReqs[pluginName] = false
	s.pluginStates[pluginName] = PluginStateReloading

	// Drain active requests
	return s.drainPluginRequests(pluginName)
}

func (s *Server) drainPluginRequests(pluginName string) error {
	s.logger.Info("Draining requests for plugin", "plugin", pluginName)

	// Wait for active requests to complete
	deadline := time.Now().Add(s.requestDrainer.drainTimeout)

	for time.Now().Before(deadline) {
		activeCount := s.getActiveRequestCount()
		if activeCount == 0 {
			break
		}

		s.logger.Debug("Waiting for active requests", "count", activeCount, "plugin", pluginName)
		time.Sleep(s.requestDrainer.pollInterval)
	}

	// Force-cancel remaining requests if needed
	remaining := s.getActiveRequestCount()
	if remaining > 0 {
		s.logger.Warn("Force-canceling remaining requests", "count", remaining, "plugin", pluginName)
		s.requestDrainer.mutex.Lock()
		for _, req := range s.requestDrainer.activeRequests {
			req.Cancel()
		}
		s.requestDrainer.mutex.Unlock()
	}

	return nil
}

func (s *Server) getActiveRequestCount() int {
	s.requestDrainer.mutex.RLock()
	defer s.requestDrainer.mutex.RUnlock()
	return len(s.requestDrainer.activeRequests)
}

func (s *Server) createRollbackSnapshot(pluginName string) error {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()

	currentState, exists := s.pluginStates[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not found in state map", pluginName)
	}

	snapshot := &PluginSnapshot{
		PluginName:    pluginName,
		State:         currentState,
		Timestamp:     time.Now(),
		Version:       1, // Simplified versioning for now
		Configuration: make(map[string]any),
	}

	// Copy current configuration
	if cfg, exists := s.config.Plugins.Config[pluginName]; exists {
		for k, v := range cfg {
			snapshot.Configuration[k] = v
		}
	}

	s.rollbackStates[pluginName] = snapshot
	s.logger.Debug("Created rollback snapshot", "plugin", pluginName)
	return nil
}

func (s *Server) rollbackPlugin(pluginName string) error {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()

	snapshot, exists := s.rollbackStates[pluginName]
	if !exists {
		s.logger.Warn("No rollback snapshot available", "plugin", pluginName)
		return fmt.Errorf("no rollback snapshot for plugin %s", pluginName)
	}

	s.logger.Info("Rolling back plugin to previous state", "plugin", pluginName)

	// Restore previous state
	s.pluginStates[pluginName] = snapshot.State
	s.acceptingReqs[pluginName] = (snapshot.State == PluginStateActive)

	// Clean up snapshot
	delete(s.rollbackStates, pluginName)

	return nil
}

// Stop the server
func (s *Server) Stop() error {
	// Stop HTTP server
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx)
	}

	// Stop rate limiter
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}

	// Stop plugin tasks
	if hostImpl, ok := s.pluginHost.(*ServerPluginHost); ok {
		for _, task := range hostImpl.tasks {
			task.Cancel()
		}
	}
	// Shutdown plugins with timeout
	if s.pluginRegistry != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.pluginRegistry.Shutdown(shutdownCtx); err != nil {
			slog.Error("Error shutting down plugins", "error", err)
		}
	}

	return nil
}

// Main function
func main() {
	// Parse command line flags
	configFile := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		slog.Error("Failed to load configuration", "error", err, "file", *configFile)
		os.Exit(1)
	}

	// Create server with configuration
	server := NewServer(cfg)

	// Initialize server
	if err := server.Initialize(); err != nil {
		slog.Error("Failed to initialize server", "error", err)
		os.Exit(1)
	}

	// Start server
	if err := server.Start(); err != nil {
		slog.Error("Failed to start server", "error", err)
		os.Exit(1)
	}

	slog.Info("Hockeypuck server started with plugin system", "bind", cfg.Server.Bind, "config", *configFile)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	slog.Info("Shutting down server...")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Create a channel to signal when shutdown is complete
	shutdownComplete := make(chan error, 1)

	// Perform shutdown in a goroutine
	go func() {
		shutdownComplete <- server.Stop()
	}()

	// Wait for shutdown to complete or timeout
	select {
	case err := <-shutdownComplete:
		if err != nil {
			slog.Error("Error during shutdown", "error", err)
			os.Exit(1)
		}
		slog.Info("Server stopped gracefully")
	case <-shutdownCtx.Done():
		slog.Error("Shutdown timed out, forcing exit")
		os.Exit(1)
	}
}

/*
Example configuration file (hockeypuck.toml):

[server]
bind = ":11371"
dataDir = "/var/lib/hockeypuck"

[plugins]
enabled = true
directory = "/etc/hkp-plugin-code/plugins"

[plugins.config.ratelimit-geo]
enabled = true
geoip_database_path = "/usr/share/GeoIP/GeoLite2-City.mmdb"
tracking_ttl = "24h"
cleanup_interval = "1h"
max_locations = 100

# Impossible travel detection
impossible_travel_enabled = true
max_travel_speed_kmh = 1000.0

# Geographic clustering detection
clustering_enabled = true
cluster_radius_km = 50.0
cluster_size_threshold = 5
cluster_time_window = "1h"

# ASN analysis
asn_analysis_enabled = true
max_asns_per_ip = 3

# Ban durations
ban_duration = "1h"
impossible_travel_ban = "6h"
clustering_ban = "2h"
asn_jumping_ban = "30m"

[rateLimit]
enabled = true
maxConcurrentConnections = 80
connectionRate = 40
httpRequestRate = 100
httpErrorRate = 20
crawlerBlockDuration = "24h"

[rateLimit.backend]
type = "memory"

[rateLimit.tor]
enabled = true
maxRequestsPerConnection = 2
maxConcurrentConnections = 1
connectionRate = 1
connectionRateWindow = "10s"
banDuration = "24h"
repeatOffenderBanDuration = "576h"
exitNodeListURL = "https://www.dan.me.uk/torlist/?exit"
updateInterval = "1h"
cacheFilePath = "tor_exit_nodes.cache"
globalRateLimit = true
globalRequestRate = 1
globalRateWindow = "10s"
globalBanDuration = "1h"

[rateLimit.headers]
enabled = true
torHeader = "X-Tor-Exit"
banHeader = "X-RateLimit-Ban"

[rateLimit.whitelist]
ips = [
    "127.0.0.1",
    "::1",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]
*/
