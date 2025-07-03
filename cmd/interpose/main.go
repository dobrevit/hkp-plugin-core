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
	"syscall"
	"time"

	"hkp-plugin-core/config"
	"hkp-plugin-core/internal/metrics"
	pluginapi "hkp-plugin-core/pkg/plugin"
	"hkp-plugin-core/pkg/ratelimit"
	"hkp-plugin-core/pkg/storage"
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
		config:    cfg,
		storage:   storageSystem,
		metrics:   metricsSystem,
		logger:    logger,
		startTime: time.Now(),
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

		// Get config for this plugin
		var config map[string]interface{}
		if cfg, exists := pluginConfigs[p.Name()]; exists {
			config = cfg
		} else {
			config = make(map[string]interface{})
		}

		if err := p.Initialize(ctx, s.pluginHost, config); err != nil {
			s.logger.Error("Failed to initialize plugin", "name", p.Name(), "error", err)
		} else {
			s.logger.Info("Successfully initialized plugin", "name", p.Name())
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

	// Register plugin handlers
	if hostImpl, ok := s.pluginHost.(*ServerPluginHost); ok {
		for pattern, handler := range hostImpl.handlers {
			mux.HandleFunc(pattern, handler)
		}
	}

	// Build middleware chain
	var handler http.Handler = mux

	// Apply plugin middlewares (in reverse order so they execute in registration order)
	var middlewares []func(http.Handler) http.Handler
	if hostImpl, ok := s.pluginHost.(*ServerPluginHost); ok {
		middlewares = hostImpl.middlewares
		if len(middlewares) > 0 {
			s.logger.Debug("Applying registered middlewares", "count", len(middlewares))
		}
	}

	// Apply middlewares
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
