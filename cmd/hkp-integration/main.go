// Example Hockeypuck integration with gRPC plugins
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/client"
	"github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
)

// HockeypuckIntegrationConfig represents Hockeypuck-style configuration with plugin support
type HockeypuckIntegrationConfig struct {
	Server  HockeypuckServerSettings  `toml:"server"`
	Logging HockeypuckLoggingSettings `toml:"logging"`
	Plugins HockeypuckPluginSettings  `toml:"plugins"`
}

type HockeypuckServerSettings struct {
	Bind    string `toml:"bind"`
	DataDir string `toml:"datadir"`
}

type HockeypuckLoggingSettings struct {
	Level string `toml:"level"`
}

type HockeypuckPluginSettings struct {
	Enabled   bool   `toml:"enabled"`
	Directory string `toml:"directory"`
}

// HockeypuckServer represents a Hockeypuck-style server with gRPC plugin integration
type HockeypuckServer struct {
	config        *HockeypuckIntegrationConfig
	logger        *logrus.Logger
	httpServer    *http.Server
	pluginAdapter *client.SimplePluginAdapter
	startTime     time.Time
}

// NewHockeypuckServer creates a new Hockeypuck-style server with plugin support
func NewHockeypuckServer(cfg *HockeypuckIntegrationConfig) *HockeypuckServer {
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

	// Use JSON formatter like Hockeypuck
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Create plugin adapter if enabled
	var pluginAdapter *client.SimplePluginAdapter
	if cfg.Plugins.Enabled {
		pluginAdapter = client.NewSimplePluginAdapter(cfg.Plugins.Directory, logger)
	}

	return &HockeypuckServer{
		config:        cfg,
		logger:        logger,
		pluginAdapter: pluginAdapter,
		startTime:     time.Now(),
	}
}

// Initialize initializes the server and plugin system
func (s *HockeypuckServer) Initialize() error {
	s.logger.Info("Initializing Hockeypuck server with gRPC plugin integration")

	// Initialize plugin system if enabled
	if s.pluginAdapter != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.pluginAdapter.Start(ctx); err != nil {
			s.logger.WithError(err).Error("Failed to start plugin system")
			return err
		}

		s.logger.Info("Plugin system started successfully")
	}

	return nil
}

// Start starts the HTTP server
func (s *HockeypuckServer) Start() error {
	// Create HTTP handler with plugin integration
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

// createHandler creates the HTTP handler with plugin middleware integration
func (s *HockeypuckServer) createHandler() http.Handler {
	mux := http.NewServeMux()

	// Register core HKP endpoints
	mux.HandleFunc("/pks/lookup", s.handleLookup)
	mux.HandleFunc("/pks/add", s.handleAdd)
	mux.HandleFunc("/pks/stats", s.handleStats)

	// Register plugin management endpoints
	if s.pluginAdapter != nil {
		mux.HandleFunc("/plugins/status", s.pluginAdapter.HandleManagement)
		mux.HandleFunc("/plugins/health", s.pluginAdapter.HandleManagement)
		mux.HandleFunc("/plugins/restart", s.pluginAdapter.HandleManagement)
	}

	// Build middleware chain
	var handler http.Handler = mux

	// Apply plugin middleware (rate limiting, abuse detection, etc.)
	if s.pluginAdapter != nil {
		handler = s.pluginAdapter.HTTPMiddleware()(handler)
	}

	// Apply core middleware
	handler = s.loggingMiddleware(handler)

	return handler
}

// Core HTTP handlers with plugin integration
func (s *HockeypuckServer) handleLookup(w http.ResponseWriter, r *http.Request) {
	// Check rate limits through plugins
	if s.pluginAdapter != nil {
		if allowed, retryAfter, reason := s.pluginAdapter.CheckRateLimit(r.RemoteAddr, "lookup"); !allowed {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			w.Header().Set("X-Rate-Limit-Reason", reason)
			http.Error(w, fmt.Sprintf("Rate limited: %s", reason), http.StatusTooManyRequests)
			return
		}
	}

	// Simulate key lookup
	search := r.URL.Query().Get("search")
	if search == "" {
		http.Error(w, "Missing search parameter", http.StatusBadRequest)
		return
	}

	// Check for suspicious patterns and report to plugins
	if s.pluginAdapter != nil && (search == "spam" || search == "test" || search == "bot") {
		s.pluginAdapter.ReportSuspiciousActivity(r.RemoteAddr,
			fmt.Sprintf("Suspicious search term: %s", search), "medium")
	}

	// Return mock key data
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n(Mock key data for search: %s)\n\n-----END PGP PUBLIC KEY BLOCK-----\n", search)))
}

func (s *HockeypuckServer) handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check rate limits for key submission
	if s.pluginAdapter != nil {
		if allowed, retryAfter, reason := s.pluginAdapter.CheckRateLimit(r.RemoteAddr, "submit"); !allowed {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			http.Error(w, fmt.Sprintf("Rate limited: %s", reason), http.StatusTooManyRequests)
			return
		}
	}

	// Simulate key submission and notify plugins
	if s.pluginAdapter != nil {
		// Simulate a key change notification
		keyChange := hkpstorage.KeyAdded{
			ID:     fmt.Sprintf("ABCD1234%08d", time.Now().Unix()),
			Digest: fmt.Sprintf("digest_%d", time.Now().Unix()),
		}

		if err := s.pluginAdapter.OnKeyChange(keyChange); err != nil {
			s.logger.WithError(err).Warn("Failed to notify plugins of key change")
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Key submitted successfully"))
}

func (s *HockeypuckServer) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"server": map[string]interface{}{
			"version": "hockeypuck-grpc-integration-1.0.0",
			"uptime":  time.Since(s.startTime).String(),
		},
		"plugins":   s.getPluginStats(),
		"timestamp": time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *HockeypuckServer) getPluginStats() map[string]interface{} {
	if s.pluginAdapter == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	return s.pluginAdapter.GetStatus()
}

// Middleware
func (s *HockeypuckServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapper := &hockeypuckResponseWrapper{ResponseWriter: w, statusCode: http.StatusOK}
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

type hockeypuckResponseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *hockeypuckResponseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Stop gracefully stops the server
func (s *HockeypuckServer) Stop() error {
	s.logger.Info("Stopping Hockeypuck server")

	// Stop HTTP server
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.WithError(err).Error("Error stopping HTTP server")
		}
	}

	// Stop plugin system
	if s.pluginAdapter != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.pluginAdapter.Stop(ctx); err != nil {
			s.logger.WithError(err).Warn("Error stopping plugin system")
		}
	}

	return nil
}

// Main function for Hockeypuck integration example
func main() {
	configFile := flag.String("config", "hockeypuck-integration.toml", "Configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := loadHockeypuckIntegrationConfig(*configFile)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration")
	}

	// Create and initialize server
	server := NewHockeypuckServer(cfg)
	if err := server.Initialize(); err != nil {
		logrus.WithError(err).Fatal("Failed to initialize server")
	}

	// Start server
	if err := server.Start(); err != nil {
		logrus.WithError(err).Fatal("Failed to start server")
	}

	logrus.WithField("bind", cfg.Server.Bind).Info("Hockeypuck server with gRPC plugins started")

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

// loadHockeypuckIntegrationConfig loads configuration for Hockeypuck integration
func loadHockeypuckIntegrationConfig(filename string) (*HockeypuckIntegrationConfig, error) {
	// Default configuration
	cfg := &HockeypuckIntegrationConfig{
		Server: HockeypuckServerSettings{
			Bind:    ":11371",
			DataDir: "/var/lib/hockeypuck",
		},
		Logging: HockeypuckLoggingSettings{
			Level: "info",
		},
		Plugins: HockeypuckPluginSettings{
			Enabled:   true,
			Directory: "./plugins",
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
