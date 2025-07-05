// Example Hockeypuck-compatible server with plugin system integration
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"plugin"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"

	"github.com/dobrevit/hkp-plugin-core/pkg/config"
	"github.com/dobrevit/hkp-plugin-core/pkg/events"
	"github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
	"github.com/dobrevit/hkp-plugin-core/pkg/integration"
	"github.com/dobrevit/hkp-plugin-core/pkg/management"
	"github.com/dobrevit/hkp-plugin-core/pkg/metrics"
	pluginapi "github.com/dobrevit/hkp-plugin-core/pkg/plugin"
)

// HockeypuckConfig represents a minimal Hockeypuck-style configuration
// This deliberately avoids copying AGPL Hockeypuck config structures
type HockeypuckConfig struct {
	Server  ServerConfig  `toml:"server"`
	Logging LoggingConfig `toml:"logging"`
	Plugins PluginConfig  `toml:"plugins"`
}

type ServerConfig struct {
	Bind    string `toml:"bind"`
	DataDir string `toml:"dataDir"`
}

type LoggingConfig struct {
	Level string `toml:"level"`
}

type PluginConfig struct {
	Enabled   bool                              `toml:"enabled"`
	Directory string                            `toml:"directory"`
	LoadOrder []string                          `toml:"loadOrder"`
	Config    map[string]map[string]interface{} `toml:"config"`
}

// Server represents a Hockeypuck-style server with plugin support
type Server struct {
	config        *HockeypuckConfig
	logger        *log.Logger
	httpServer    *http.Server
	storage       hkpstorage.Storage
	metrics       *metrics.Metrics
	pluginSystem  *integration.PluginSystem
	pluginManager *management.PluginManager
	startTime     time.Time
	mu            sync.RWMutex
}

// ServerPluginHost implements the PluginHost interface for Hockeypuck-style server
type ServerPluginHost struct {
	server      *Server
	middlewares []func(http.Handler) http.Handler
	handlers    map[string]http.HandlerFunc
	tasks       map[string]TaskInfo
	mu          sync.RWMutex
}

type TaskInfo struct {
	Name     string
	Interval time.Duration
	Task     func(context.Context) error
	Cancel   context.CancelFunc
}

// NewServerPluginHost creates a new Hockeypuck-style plugin host
func NewServerPluginHost(server *Server) *ServerPluginHost {
	return &ServerPluginHost{
		server:      server,
		middlewares: make([]func(http.Handler) http.Handler, 0),
		handlers:    make(map[string]http.HandlerFunc),
		tasks:       make(map[string]TaskInfo),
	}
}

// Implement PluginHost interface with Hockeypuck-compatible methods
func (ph *ServerPluginHost) RegisterMiddleware(path string, middleware func(http.Handler) http.Handler) error {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	ph.middlewares = append(ph.middlewares, middleware)
	ph.server.logger.WithFields(log.Fields{
		"path":  path,
		"count": len(ph.middlewares),
	}).Debug("Plugin middleware registered")
	return nil
}

func (ph *ServerPluginHost) RegisterHandler(pattern string, handler http.HandlerFunc) error {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	ph.handlers[pattern] = handler
	ph.server.logger.WithField("pattern", pattern).Debug("Plugin handler registered")
	return nil
}

func (ph *ServerPluginHost) Storage() hkpstorage.Storage {
	return ph.server.storage
}

func (ph *ServerPluginHost) Config() *config.Settings {
	// Convert Hockeypuck config to plugin config safely
	settings := config.DefaultSettings()
	settings.DataDir = ph.server.config.Server.DataDir
	settings.Plugins.Enabled = ph.server.config.Plugins.Enabled
	settings.Plugins.Directory = ph.server.config.Plugins.Directory
	settings.Plugins.LoadOrder = ph.server.config.Plugins.LoadOrder
	settings.Plugins.Config = ph.server.config.Plugins.Config
	return &settings
}

func (ph *ServerPluginHost) Metrics() *metrics.Metrics {
	return ph.server.metrics
}

func (ph *ServerPluginHost) Logger() *log.Logger {
	return ph.server.logger
}

func (ph *ServerPluginHost) RegisterTask(name string, interval time.Duration, task func(context.Context) error) error {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	ph.tasks[name] = TaskInfo{
		Name:     name,
		Interval: interval,
		Task:     task,
		Cancel:   cancel,
	}

	// Start the task
	go ph.runTask(ctx, name, interval, task)
	ph.server.logger.WithFields(log.Fields{
		"task":     name,
		"interval": interval,
	}).Debug("Plugin task registered")
	return nil
}

func (ph *ServerPluginHost) runTask(ctx context.Context, name string, interval time.Duration, task func(context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := task(ctx); err != nil {
				ph.server.logger.WithFields(log.Fields{
					"task":  name,
					"error": err,
				}).Error("Plugin task error")
			}
		case <-ctx.Done():
			return
		}
	}
}

// Event system methods - delegated to plugin system's event bus
func (ph *ServerPluginHost) PublishEvent(event pluginapi.PluginEvent) error {
	if ph.server.pluginSystem != nil {
		if eventBus := ph.server.pluginSystem.GetEventBus(); eventBus != nil {
			return eventBus.PublishEvent(event)
		}
	}
	return nil
}

func (ph *ServerPluginHost) SubscribeEvent(eventType string, handler pluginapi.PluginEventHandler) error {
	if ph.server.pluginSystem != nil {
		if eventBus := ph.server.pluginSystem.GetEventBus(); eventBus != nil {
			return eventBus.SubscribeEvent(eventType, handler)
		}
	}
	return nil
}

func (ph *ServerPluginHost) SubscribeKeyChanges(callback func(hkpstorage.KeyChange) error) error {
	if ph.server.pluginSystem != nil {
		if eventBus := ph.server.pluginSystem.GetEventBus(); eventBus != nil {
			return eventBus.SubscribeKeyChanges(callback)
		}
	}
	return nil
}

// Convenience methods for common events
func (ph *ServerPluginHost) PublishThreatDetected(threat events.ThreatInfo) error {
	return ph.PublishEvent(pluginapi.PluginEvent{
		Type:      pluginapi.EventSecurityThreatDetected,
		Source:    "server",
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"threat": threat},
	})
}

func (ph *ServerPluginHost) PublishRateLimitViolation(violation events.RateLimitViolation) error {
	return ph.PublishEvent(pluginapi.PluginEvent{
		Type:      "rate_limit_violation",
		Source:    "server",
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"violation": violation},
	})
}

func (ph *ServerPluginHost) PublishZTNAEvent(eventType string, ztnaEvent events.ZTNAEvent) error {
	return ph.PublishEvent(pluginapi.PluginEvent{
		Type:      eventType,
		Source:    "ztna",
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"ztna": ztnaEvent},
	})
}

// NewServer creates a new Hockeypuck-style server
func NewServer(cfg *HockeypuckConfig) *Server {
	// Initialize logger with Hockeypuck-style logging
	logger := log.StandardLogger()

	// Set log level
	switch cfg.Logging.Level {
	case "debug":
		logger.SetLevel(log.DebugLevel)
	case "warn":
		logger.SetLevel(log.WarnLevel)
	case "error":
		logger.SetLevel(log.ErrorLevel)
	default:
		logger.SetLevel(log.InfoLevel)
	}

	// Use JSON formatter like Hockeypuck
	logger.SetFormatter(&log.JSONFormatter{})

	// Initialize components
	storage := &MockStorage{} // Mock storage for this example
	metricsSystem := metrics.NewMetrics()

	server := &Server{
		config:    cfg,
		logger:    logger,
		storage:   storage,
		metrics:   metricsSystem,
		startTime: time.Now(),
	}

	return server
}

// MockStorage provides a mock storage implementation
type MockStorage struct{}

func (s *MockStorage) Close() error                          { return nil }
func (s *MockStorage) HealthCheck(ctx context.Context) error { return nil }

// Queryer interface methods
func (s *MockStorage) MatchMD5([]string) ([]string, error)       { return nil, nil }
func (s *MockStorage) Resolve([]string) ([]string, error)        { return nil, nil }
func (s *MockStorage) MatchKeyword([]string) ([]string, error)   { return nil, nil }
func (s *MockStorage) ModifiedSince(time.Time) ([]string, error) { return nil, nil }
func (s *MockStorage) FetchKeys([]string, ...string) ([]*hkpstorage.PrimaryKey, error) {
	return nil, nil
}
func (s *MockStorage) FetchRecords([]string, ...string) ([]*hkpstorage.Record, error) {
	return nil, nil
}

// Updater interface methods
func (s *MockStorage) Insert([]*hkpstorage.PrimaryKey) (int, int, error) { return 0, 0, nil }
func (s *MockStorage) Update(pubkey *hkpstorage.PrimaryKey, priorID string, priorMD5 string) error {
	return nil
}
func (s *MockStorage) Replace(pubkey *hkpstorage.PrimaryKey) (string, error) { return "", nil }

// Deleter interface methods
func (s *MockStorage) Delete(fp string) (string, error) { return "", nil }

// Notifier interface methods
func (s *MockStorage) Subscribe(callback func(hkpstorage.KeyChange) error) { /* no-op */ }
func (s *MockStorage) Notify(change hkpstorage.KeyChange) error            { return nil }
func (s *MockStorage) RenotifyAll() error                                  { return nil }

// Reindexer interface methods
func (s *MockStorage) StartReindex() { /* no-op */ }

func (s *MockStorage) Stats(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"keys": 0}, nil
}

// Initialize initializes the server and plugin system
func (s *Server) Initialize() error {
	s.logger.Info("Initializing Hockeypuck-style server with plugin system")

	// Initialize plugin system if enabled
	if s.config.Plugins.Enabled {
		ctx := context.Background()
		host := NewServerPluginHost(s)

		// Convert to plugin settings
		settings := host.Config()

		// Initialize plugin manager
		s.pluginManager = management.NewPluginManager(host, settings, s.logger)

		// Initialize plugin system using the new integration package
		pluginSystem, err := integration.InitializePlugins(ctx, host, settings)
		if err != nil {
			s.logger.WithError(err).Error("Failed to initialize plugin system")
			return err
		}

		s.pluginSystem = pluginSystem
		s.pluginManager.SetPluginSystem(pluginSystem)
		s.logger.WithField("plugins", len(pluginSystem.ListPlugins())).Info("Plugin system initialized")
	}

	return nil
}

// Start starts the server
func (s *Server) Start() error {
	// Create HTTP handler
	handler := s.createHandler()

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:    s.config.Server.Bind,
		Handler: handler,
	}

	// Start server in goroutine
	go func() {
		s.logger.WithField("addr", s.config.Server.Bind).Info("Starting HTTP server")
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.WithError(err).Error("HTTP server error")
		}
	}()

	return nil
}

// createHandler creates the HTTP handler with middleware chain
func (s *Server) createHandler() http.Handler {
	mux := http.NewServeMux()

	// Register core Hockeypuck-style endpoints
	mux.HandleFunc("/pks/lookup", s.handleLookup)
	mux.HandleFunc("/pks/add", s.handleAdd)
	mux.HandleFunc("/pks/stats", s.handleStats)
	mux.Handle("/metrics", s.metrics.PrometheusHandler())

	// Register plugin management endpoints
	mux.HandleFunc("/plugins/status", s.handlePluginsStatus)
	mux.HandleFunc("/plugins/list", s.handlePluginsList)
	mux.HandleFunc("/plugins/health", s.handlePluginsHealth)
	mux.HandleFunc("/plugins/reload", s.handlePluginReload)
	mux.HandleFunc("/plugins/config", s.handlePluginConfig)

	// Register plugin handlers if plugin system is active
	if s.pluginSystem != nil {
		// This is a simplified way to get plugin handlers
		// In a real implementation, you'd have a proper way to access them
		s.logger.Debug("Plugin handlers would be registered here")
	}

	// Build middleware chain
	var handler http.Handler = mux

	// Apply plugin middlewares if available
	// This would be implemented properly in a real Hockeypuck integration

	// Apply core middleware
	handler = s.loggingMiddleware(handler)
	handler = s.metricsMiddleware(handler)

	return handler
}

// Core HTTP handlers (simplified Hockeypuck-style)
func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	// Simplified HKP lookup implementation
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n(Mock key data)\n\n-----END PGP PUBLIC KEY BLOCK-----\n"))
}

func (s *Server) handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Simplified key submission
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Key submitted successfully"))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"server": map[string]interface{}{
			"version": "hkp-plugin-example-1.0.0",
			"uptime":  time.Since(s.startTime).String(),
			"plugins": s.getPluginStats(),
		},
		"timestamp": time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) getPluginStats() map[string]interface{} {
	if s.pluginSystem == nil {
		return map[string]interface{}{
			"enabled": false,
			"count":   0,
		}
	}

	return map[string]interface{}{
		"enabled": true,
		"count":   len(s.pluginSystem.ListPlugins()),
		"plugins": s.pluginSystem.ListPlugins(),
	}
}

// Plugin management HTTP handlers - delegate to plugin manager

func (s *Server) handlePluginsStatus(w http.ResponseWriter, r *http.Request) {
	if s.pluginManager == nil {
		http.Error(w, "Plugin management not initialized", http.StatusServiceUnavailable)
		return
	}
	s.pluginManager.StatusHandler(w, r)
}

func (s *Server) handlePluginsList(w http.ResponseWriter, r *http.Request) {
	if s.pluginManager == nil {
		http.Error(w, "Plugin management not initialized", http.StatusServiceUnavailable)
		return
	}
	s.pluginManager.ListHandler(w, r)
}

func (s *Server) handlePluginsHealth(w http.ResponseWriter, r *http.Request) {
	if s.pluginManager == nil {
		http.Error(w, "Plugin management not initialized", http.StatusServiceUnavailable)
		return
	}
	s.pluginManager.HealthHandler(w, r)
}

func (s *Server) handlePluginReload(w http.ResponseWriter, r *http.Request) {
	if s.pluginManager == nil {
		http.Error(w, "Plugin management not initialized", http.StatusServiceUnavailable)
		return
	}
	s.pluginManager.ReloadHandler(w, r)
}

func (s *Server) handlePluginConfig(w http.ResponseWriter, r *http.Request) {
	if s.pluginManager == nil {
		http.Error(w, "Plugin management not initialized", http.StatusServiceUnavailable)
		return
	}
	s.pluginManager.ConfigHandler(w, r)
}

// Middleware implementations
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status
		wrapper := &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapper, r)

		duration := time.Since(start)
		s.logger.WithFields(log.Fields{
			"method":   r.Method,
			"path":     r.URL.Path,
			"status":   wrapper.statusCode,
			"duration": duration,
			"remote":   r.RemoteAddr,
		}).Info("HTTP request")
	})
}

func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapper := &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapper, r)

		duration := time.Since(start)
		s.metrics.HTTPMetrics.RequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration.Seconds())
		s.metrics.HTTPMetrics.RequestsTotal.WithLabelValues(r.Method, r.URL.Path, statusClass(wrapper.statusCode)).Inc()
	})
}

type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

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

// Stop gracefully stops the server
func (s *Server) Stop() error {
	s.logger.Info("Stopping server")

	// Stop HTTP server
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.WithError(err).Error("Error stopping HTTP server")
		}
	}

	// Shutdown plugin system
	if s.pluginSystem != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.pluginSystem.Shutdown(ctx); err != nil {
			s.logger.WithError(err).Error("Error shutting down plugin system")
		}
	}

	return nil
}

// loadDynamicPlugins loads plugins from .so files (similar to the integration example)
func (s *Server) loadDynamicPlugins(pluginDir string) error {
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		s.logger.WithField("dir", pluginDir).Info("Plugin directory does not exist")
		return nil
	}

	pattern := filepath.Join(pluginDir, "*.so")
	pluginFiles, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to search for plugin files: %w", err)
	}

	for _, pluginFile := range pluginFiles {
		if err := s.loadPlugin(pluginFile); err != nil {
			s.logger.WithFields(log.Fields{
				"file":  pluginFile,
				"error": err,
			}).Error("Failed to load plugin")
			continue
		}
		s.logger.WithField("file", pluginFile).Info("Plugin loaded successfully")
	}

	return nil
}

func (s *Server) loadPlugin(pluginFile string) error {
	p, err := plugin.Open(pluginFile)
	if err != nil {
		return fmt.Errorf("failed to open plugin file: %w", err)
	}

	getPluginSym, err := p.Lookup("GetPlugin")
	if err != nil {
		return fmt.Errorf("plugin missing GetPlugin function: %w", err)
	}

	getPlugin, ok := getPluginSym.(func() pluginapi.Plugin)
	if !ok {
		return fmt.Errorf("GetPlugin function has wrong signature")
	}

	pluginInstance := getPlugin()
	if pluginInstance == nil {
		return fmt.Errorf("GetPlugin returned nil")
	}

	// Plugin would be registered with the plugin system here
	s.logger.WithField("plugin", pluginInstance.Name()).Info("Plugin discovered")

	return nil
}

// Main function
func main() {
	configFile := flag.String("config", "hockeypuck.toml", "Configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.WithError(err).Fatal("Failed to load configuration")
	}

	// Create and initialize server
	server := NewServer(cfg)
	if err := server.Initialize(); err != nil {
		log.WithError(err).Fatal("Failed to initialize server")
	}

	// Start server
	if err := server.Start(); err != nil {
		log.WithError(err).Fatal("Failed to start server")
	}

	log.WithField("bind", cfg.Server.Bind).Info("Hockeypuck-style server started")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info("Shutdown signal received")
	if err := server.Stop(); err != nil {
		log.WithError(err).Error("Error during shutdown")
	}
	log.Info("Server stopped")
}

// loadConfig loads configuration from TOML file
func loadConfig(filename string) (*HockeypuckConfig, error) {
	// Default configuration
	cfg := &HockeypuckConfig{
		Server: ServerConfig{
			Bind:    ":11371",
			DataDir: "/var/lib/hockeypuck",
		},
		Logging: LoggingConfig{
			Level: "info",
		},
		Plugins: PluginConfig{
			Enabled:   false,
			Directory: "/etc/hockeypuck/plugins",
			Config:    make(map[string]map[string]interface{}),
		},
	}

	// Try to load from file
	if _, err := os.Stat(filename); err == nil {
		if _, err := toml.DecodeFile(filename, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
		log.WithField("file", filename).Info("Configuration loaded from file")
	} else {
		log.WithField("file", filename).Info("Config file not found, using defaults")
	}

	return cfg, nil
}
