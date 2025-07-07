// Example server with gRPC-based plugin system
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"

	"github.com/dobrevit/hkp-plugin-core/pkg/discovery"
	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
	"github.com/dobrevit/hkp-plugin-core/pkg/lifecycle"
)

// GRPCServerConfig represents server configuration for gRPC plugin system
type GRPCServerConfig struct {
	Server  GRPCServerSettings  `toml:"server"`
	Logging GRPCLoggingSettings `toml:"logging"`
	Plugins GRPCPluginConfig    `toml:"plugins"`
}

type GRPCServerSettings struct {
	Bind    string `toml:"bind"`
	DataDir string `toml:"datadir"`
}

type GRPCLoggingSettings struct {
	Level string `toml:"level"`
}

type GRPCPluginConfig struct {
	Enabled        bool     `toml:"enabled"`
	Directories    []string `toml:"directories"`
	StartTimeout   string   `toml:"start_timeout"`
	HealthInterval string   `toml:"health_interval"`
}

// GRPCServer represents the main server with gRPC plugin support
type GRPCServer struct {
	config           *GRPCServerConfig
	logger           *logrus.Logger
	httpServer       *http.Server
	lifecycleManager *lifecycle.Manager
	discoverer       *discovery.Discoverer
	registry         *discovery.Registry
	plugins          map[string]*lifecycle.PluginProcess
	pluginsMutex     sync.RWMutex
	startTime        time.Time
}

// NewGRPCServer creates a new server with gRPC plugin system
func NewGRPCServer(cfg *GRPCServerConfig) *GRPCServer {
	// Initialize logger
	logger := logrus.New()

	// Set log level
	switch cfg.Logging.Level {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	// Use JSON formatter
	logger.SetFormatter(&logrus.JSONFormatter{})

	return &GRPCServer{
		config:    cfg,
		logger:    logger,
		plugins:   make(map[string]*lifecycle.PluginProcess),
		startTime: time.Now(),
	}
}

// Initialize initializes the server and plugin system
func (s *GRPCServer) Initialize() error {
	s.logger.Info("Initializing server with gRPC plugin system")

	if !s.config.Plugins.Enabled {
		s.logger.Info("Plugin system disabled")
		return nil
	}

	// Create plugin discoverer
	s.discoverer = discovery.NewDiscoverer(s.config.Plugins.Directories, s.logger)
	s.registry = discovery.NewRegistry(s.logger)

	// Create lifecycle manager
	lifecycleConfig := lifecycle.DefaultConfig()

	// Parse timeout values
	if s.config.Plugins.StartTimeout != "" {
		if timeout, err := time.ParseDuration(s.config.Plugins.StartTimeout); err == nil {
			lifecycleConfig.StartupTimeout = timeout
		}
	}
	if s.config.Plugins.HealthInterval != "" {
		if interval, err := time.ParseDuration(s.config.Plugins.HealthInterval); err == nil {
			lifecycleConfig.HealthCheckInterval = interval
		}
	}

	s.lifecycleManager = lifecycle.NewManager(lifecycleConfig, s.logger)

	// Start lifecycle manager
	if err := s.lifecycleManager.Start(); err != nil {
		return fmt.Errorf("failed to start lifecycle manager: %w", err)
	}

	// Discover plugins
	discoveredPlugins, err := s.discoverer.DiscoverPlugins()
	if err != nil {
		return fmt.Errorf("failed to discover plugins: %w", err)
	}

	// Register and start plugins
	for _, plugin := range discoveredPlugins {
		if err := s.registry.Register(plugin); err != nil {
			s.logger.WithError(err).WithField("plugin", plugin.Info.Name).Warn("Failed to register plugin")
			continue
		}

		// Start the plugin
		if err := s.lifecycleManager.StartPlugin(plugin); err != nil {
			s.logger.WithError(err).WithField("plugin", plugin.Info.Name).Error("Failed to start plugin")
			continue
		}

		// Store reference
		if proc, exists := s.lifecycleManager.GetPlugin(plugin.Info.Name); exists {
			s.pluginsMutex.Lock()
			s.plugins[plugin.Info.Name] = proc
			s.pluginsMutex.Unlock()
		}
	}

	s.logger.WithField("plugin_count", len(s.plugins)).Info("Plugin system initialized")
	return nil
}

// Start starts the HTTP server
func (s *GRPCServer) Start() error {
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

// createHandler creates the HTTP handler with plugin integration
func (s *GRPCServer) createHandler() http.Handler {
	mux := http.NewServeMux()

	// Register core endpoints
	mux.HandleFunc("/pks/lookup", s.handleLookup)
	mux.HandleFunc("/pks/add", s.handleAdd)
	mux.HandleFunc("/pks/stats", s.handleStats)

	// Register plugin management endpoints
	mux.HandleFunc("/plugins/status", s.handlePluginsStatus)
	mux.HandleFunc("/plugins/list", s.handlePluginsList)
	mux.HandleFunc("/plugins/health", s.handlePluginsHealth)
	mux.HandleFunc("/plugins/restart", s.handlePluginRestart)

	// Apply middleware
	var handler http.Handler = mux
	handler = s.loggingMiddleware(handler)
	handler = s.pluginMiddleware(handler)

	return handler
}

// pluginMiddleware integrates with gRPC plugins for HTTP request processing
func (s *GRPCServer) pluginMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Call plugins for HTTP request processing
		if err := s.callPluginsForHTTPRequest(w, r); err != nil {
			s.logger.WithError(err).Debug("Plugin HTTP processing error")
		}

		// Continue to next handler
		next.ServeHTTP(w, r)
	})
}

// callPluginsForHTTPRequest calls all plugins for HTTP request processing
func (s *GRPCServer) callPluginsForHTTPRequest(w http.ResponseWriter, r *http.Request) error {
	s.pluginsMutex.RLock()
	plugins := make([]*lifecycle.PluginProcess, 0, len(s.plugins))
	for _, proc := range s.plugins {
		plugins = append(plugins, proc)
	}
	s.pluginsMutex.RUnlock()

	// Create protobuf request
	httpReq := &proto.HTTPRequest{
		Id:          fmt.Sprintf("req_%d", time.Now().UnixNano()),
		Method:      r.Method,
		Path:        r.URL.Path,
		Headers:     make(map[string]string),
		RemoteAddr:  r.RemoteAddr,
		QueryParams: make(map[string]string),
	}

	// Copy headers
	for key, values := range r.Header {
		if len(values) > 0 {
			httpReq.Headers[key] = values[0]
		}
	}

	// Copy query parameters
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			httpReq.QueryParams[key] = values[0]
		}
	}

	// Call each plugin
	for _, proc := range plugins {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		resp, err := proc.Client.HandleHTTPRequest(ctx, httpReq)
		cancel()

		if err != nil {
			s.logger.WithError(err).WithField("plugin", proc.Plugin.Info.Name).Debug("Plugin HTTP call failed")
			continue
		}

		// Process response
		if resp.StatusCode != 200 {
			// Plugin wants to modify the response
			for key, value := range resp.Headers {
				w.Header().Set(key, value)
			}
			w.WriteHeader(int(resp.StatusCode))
			w.Write(resp.Body)
			return nil
		}

		// Continue to next plugin if ContinueChain is true
		if !resp.ContinueChain {
			break
		}
	}

	return nil
}

// Core HTTP handlers
func (s *GRPCServer) handleLookup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n(Mock key data)\n\n-----END PGP PUBLIC KEY BLOCK-----\n"))
}

func (s *GRPCServer) handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Key submitted successfully"))
}

func (s *GRPCServer) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"server": map[string]interface{}{
			"version": "hkp-grpc-plugin-1.0.0",
			"uptime":  time.Since(s.startTime).String(),
			"plugins": s.getPluginStats(),
		},
		"timestamp": time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *GRPCServer) getPluginStats() map[string]interface{} {
	if s.lifecycleManager == nil {
		return map[string]interface{}{
			"enabled": false,
			"count":   0,
		}
	}

	s.pluginsMutex.RLock()
	pluginList := make([]map[string]interface{}, 0, len(s.plugins))
	for name, proc := range s.plugins {
		pluginList = append(pluginList, map[string]interface{}{
			"name":        name,
			"version":     proc.Plugin.Info.Version,
			"started":     proc.Started,
			"last_health": proc.LastHealth,
		})
	}
	s.pluginsMutex.RUnlock()

	return map[string]interface{}{
		"enabled": true,
		"count":   len(pluginList),
		"plugins": pluginList,
	}
}

// Plugin management handlers
func (s *GRPCServer) handlePluginsStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"enabled":         s.config.Plugins.Enabled,
		"manager_running": s.lifecycleManager != nil,
		"plugins":         s.getPluginStats(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *GRPCServer) handlePluginsList(w http.ResponseWriter, r *http.Request) {
	s.pluginsMutex.RLock()
	plugins := make([]map[string]interface{}, 0, len(s.plugins))
	for _, proc := range s.plugins {
		plugins = append(plugins, map[string]interface{}{
			"name":        proc.Plugin.Info.Name,
			"version":     proc.Plugin.Info.Version,
			"description": proc.Plugin.Info.Description,
			"executable":  proc.Plugin.ExecutablePath,
			"address":     proc.Address,
			"started":     proc.Started,
			"last_health": proc.LastHealth,
		})
	}
	s.pluginsMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"plugins": plugins,
	})
}

func (s *GRPCServer) handlePluginsHealth(w http.ResponseWriter, r *http.Request) {
	s.pluginsMutex.RLock()
	healthStatus := make(map[string]interface{})
	for name, proc := range s.plugins {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		status, err := proc.Client.HealthCheck(ctx, &proto.Empty{})
		cancel()

		if err != nil {
			healthStatus[name] = map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
			}
		} else {
			healthStatus[name] = map[string]interface{}{
				"status":    status.Status.String(),
				"message":   status.Message,
				"timestamp": status.Timestamp,
				"details":   status.Details,
			}
		}
	}
	s.pluginsMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"health": healthStatus,
	})
}

func (s *GRPCServer) handlePluginRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pluginName := r.URL.Query().Get("plugin")
	if pluginName == "" {
		http.Error(w, "Plugin name required", http.StatusBadRequest)
		return
	}

	s.pluginsMutex.RLock()
	proc, exists := s.plugins[pluginName]
	s.pluginsMutex.RUnlock()

	if !exists {
		http.Error(w, "Plugin not found", http.StatusNotFound)
		return
	}

	// Stop the plugin
	if err := s.lifecycleManager.StopPlugin(pluginName); err != nil {
		http.Error(w, fmt.Sprintf("Failed to stop plugin: %v", err), http.StatusInternalServerError)
		return
	}

	// Remove from our map
	s.pluginsMutex.Lock()
	delete(s.plugins, pluginName)
	s.pluginsMutex.Unlock()

	// Wait a moment
	time.Sleep(1 * time.Second)

	// Start it again
	if err := s.lifecycleManager.StartPlugin(proc.Plugin); err != nil {
		http.Error(w, fmt.Sprintf("Failed to restart plugin: %v", err), http.StatusInternalServerError)
		return
	}

	// Add back to our map
	if newProc, exists := s.lifecycleManager.GetPlugin(pluginName); exists {
		s.pluginsMutex.Lock()
		s.plugins[pluginName] = newProc
		s.pluginsMutex.Unlock()
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Plugin restarted successfully",
		"plugin":  pluginName,
	})
}

// Middleware
func (s *GRPCServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapper := &grpcResponseWrapper{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapper, r)

		duration := time.Since(start)
		s.logger.WithFields(logrus.Fields{
			"method":   r.Method,
			"path":     r.URL.Path,
			"status":   wrapper.statusCode,
			"duration": duration,
			"remote":   r.RemoteAddr,
		}).Info("HTTP request")
	})
}

type grpcResponseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *grpcResponseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Stop gracefully stops the server
func (s *GRPCServer) Stop() error {
	s.logger.Info("Stopping server")

	// Stop HTTP server
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.WithError(err).Error("Error stopping HTTP server")
		}
	}

	// Stop lifecycle manager (this will stop all plugins)
	if s.lifecycleManager != nil {
		if err := s.lifecycleManager.Stop(); err != nil {
			s.logger.WithError(err).Warn("Error stopping lifecycle manager")
		}
	}

	return nil
}

// Main function for gRPC version
func main() {
	configFile := flag.String("config", "grpc-server.toml", "Configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := loadGRPCConfig(*configFile)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration")
	}

	// Create and initialize server
	server := NewGRPCServer(cfg)
	if err := server.Initialize(); err != nil {
		logrus.WithError(err).Fatal("Failed to initialize server")
	}

	// Start server
	if err := server.Start(); err != nil {
		logrus.WithError(err).Fatal("Failed to start server")
	}

	logrus.WithField("bind", cfg.Server.Bind).Info("gRPC plugin server started")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logrus.Info("Shutdown signal received")
	if err := server.Stop(); err != nil {
		logrus.WithError(err).Error("Error during shutdown")
	}
	logrus.Info("Server stopped")
}

// loadGRPCConfig loads configuration for gRPC server
func loadGRPCConfig(filename string) (*GRPCServerConfig, error) {
	// Default configuration
	cfg := &GRPCServerConfig{
		Server: GRPCServerSettings{
			Bind:    ":11371",
			DataDir: "/var/lib/hockeypuck",
		},
		Logging: GRPCLoggingSettings{
			Level: "info",
		},
		Plugins: GRPCPluginConfig{
			Enabled:        true,
			Directories:    []string{"./plugins"},
			StartTimeout:   "30s",
			HealthInterval: "10s",
		},
	}

	// Try to load from file
	if _, err := os.Stat(filename); err == nil {
		if _, err := toml.DecodeFile(filename, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
		logrus.WithField("file", filename).Info("Configuration loaded from file")
	} else {
		logrus.WithField("file", filename).Info("Config file not found, using defaults")
	}

	return cfg, nil
}
