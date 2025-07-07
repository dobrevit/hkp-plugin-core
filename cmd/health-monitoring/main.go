// Health monitoring example for gRPC plugin system
package main

import (
	"context"
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
)

// HealthMonitoringConfig represents configuration for health monitoring demo
type HealthMonitoringConfig struct {
	Server  HealthServerSettings  `toml:"server"`
	Logging HealthLoggingSettings `toml:"logging"`
	Plugins HealthPluginSettings  `toml:"plugins"`
}

type HealthServerSettings struct {
	Bind string `toml:"bind"`
}

type HealthLoggingSettings struct {
	Level string `toml:"level"`
}

type HealthPluginSettings struct {
	Enabled   bool   `toml:"enabled"`
	Directory string `toml:"directory"`
}

// HealthMonitoringServer demonstrates health monitoring features
type HealthMonitoringServer struct {
	config        *HealthMonitoringConfig
	logger        *logrus.Logger
	httpServer    *http.Server
	pluginAdapter *client.SimplePluginAdapter
	startTime     time.Time
}

// NewHealthMonitoringServer creates a new health monitoring demo server
func NewHealthMonitoringServer(cfg *HealthMonitoringConfig) *HealthMonitoringServer {
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

	// Create plugin adapter if enabled
	var pluginAdapter *client.SimplePluginAdapter
	if cfg.Plugins.Enabled {
		pluginAdapter = client.NewSimplePluginAdapter(cfg.Plugins.Directory, logger)
	}

	return &HealthMonitoringServer{
		config:        cfg,
		logger:        logger,
		pluginAdapter: pluginAdapter,
		startTime:     time.Now(),
	}
}

// Initialize initializes the server and plugin system
func (s *HealthMonitoringServer) Initialize() error {
	s.logger.Info("Initializing health monitoring demo server")

	// Initialize plugin system if enabled
	if s.pluginAdapter != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.pluginAdapter.Start(ctx); err != nil {
			s.logger.WithError(err).Error("Failed to start plugin system")
			return err
		}

		s.logger.Info("Plugin system with health monitoring started successfully")
	}

	return nil
}

// Start starts the HTTP server with health monitoring endpoints
func (s *HealthMonitoringServer) Start() error {
	// Create HTTP handler with health monitoring
	handler := s.createHandler()

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:    s.config.Server.Bind,
		Handler: handler,
	}

	// Start server in goroutine
	go func() {
		s.logger.WithField("addr", s.config.Server.Bind).Info("Starting health monitoring demo server")
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.WithError(err).Error("HTTP server error")
		}
	}()

	return nil
}

// createHandler creates the HTTP handler with comprehensive health monitoring
func (s *HealthMonitoringServer) createHandler() http.Handler {
	mux := http.NewServeMux()

	// Register core demo endpoints
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/simulate/load", s.handleSimulateLoad)
	mux.HandleFunc("/simulate/failure", s.handleSimulateFailure)

	// Register health monitoring endpoints
	if s.pluginAdapter != nil {
		// Plugin management and health
		mux.HandleFunc("/plugins/", s.pluginAdapter.HandleManagement)
		mux.HandleFunc("/health", s.pluginAdapter.HandleManagement)
		mux.HandleFunc("/health/", s.pluginAdapter.HandleManagement)
		mux.HandleFunc("/health/liveness", s.pluginAdapter.HandleManagement)
		mux.HandleFunc("/health/readiness", s.pluginAdapter.HandleManagement)
	}

	// Build middleware chain
	var handler http.Handler = mux

	// Apply plugin middleware (includes health checking)
	if s.pluginAdapter != nil {
		handler = s.pluginAdapter.HTTPMiddleware()(handler)
	}

	// Apply logging middleware
	handler = s.loggingMiddleware(handler)

	return handler
}

// Demo HTTP handlers
func (s *HealthMonitoringServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html := `<!DOCTYPE html>
<html>
<head>
    <title>Health Monitoring Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ccc; }
        .endpoint { margin: 10px 0; padding: 10px; background: #f5f5f5; }
        .endpoint a { text-decoration: none; color: #0066cc; }
        .endpoint a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>gRPC Plugin Health Monitoring Demo</h1>
    
    <div class="section">
        <h2>Health Monitoring Endpoints</h2>
        <div class="endpoint">
            <strong><a href="/health">/health</a></strong> - Overall system health
        </div>
        <div class="endpoint">
            <strong><a href="/health/liveness">/health/liveness</a></strong> - Kubernetes liveness probe
        </div>
        <div class="endpoint">
            <strong><a href="/health/readiness">/health/readiness</a></strong> - Kubernetes readiness probe
        </div>
        <div class="endpoint">
            <strong><a href="/health/antiabuse">/health/antiabuse</a></strong> - Specific plugin health
        </div>
    </div>

    <div class="section">
        <h2>Plugin Management</h2>
        <div class="endpoint">
            <strong><a href="/plugins/status">/plugins/status</a></strong> - Plugin status overview
        </div>
        <div class="endpoint">
            <strong><a href="/plugins/health">/plugins/health</a></strong> - Plugin health details
        </div>
        <div class="endpoint">
            <strong>POST /plugins/restart?plugin=antiabuse</strong> - Restart specific plugin
        </div>
    </div>

    <div class="section">
        <h2>Simulation Tools</h2>
        <div class="endpoint">
            <strong><a href="/simulate/load">/simulate/load</a></strong> - Simulate high load
        </div>
        <div class="endpoint">
            <strong><a href="/simulate/failure">/simulate/failure</a></strong> - Simulate plugin failure
        </div>
    </div>

    <div class="section">
        <h2>How Health Monitoring Works</h2>
        <p><strong>Automatic Health Checks:</strong> The system performs health checks every 30 seconds on all plugins.</p>
        <p><strong>Failure Detection:</strong> After 3 consecutive failures, a plugin is marked unhealthy.</p>
        <p><strong>Automatic Restart:</strong> Unhealthy plugins are automatically restarted with exponential backoff.</p>
        <p><strong>HTTP Integration:</strong> Health status affects HTTP responses and Kubernetes probes.</p>
        <p><strong>Monitoring:</strong> Comprehensive metrics and status information available via REST API.</p>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func (s *HealthMonitoringServer) handleSimulateLoad(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("Simulating high load for health monitoring demonstration")

	// Simulate multiple requests to trigger rate limiting and health monitoring
	for i := 0; i < 50; i++ {
		if s.pluginAdapter != nil {
			allowed, retryAfter, reason := s.pluginAdapter.CheckRateLimit(
				fmt.Sprintf("127.0.0.1:%d", 50000+i), "lookup")
			
			if !allowed {
				s.logger.WithFields(logrus.Fields{
					"iteration":  i,
					"retryAfter": retryAfter,
					"reason":     reason,
				}).Info("Rate limit triggered during load simulation")
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Load simulation completed", "requests": 50}`))
}

func (s *HealthMonitoringServer) handleSimulateFailure(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("Simulating plugin failure for health monitoring demonstration")

	// Report suspicious activity to trigger plugin responses
	if s.pluginAdapter != nil {
		err := s.pluginAdapter.ReportSuspiciousActivity(
			r.RemoteAddr, 
			"Simulated security incident for health monitoring demo", 
			"high")
		
		if err != nil {
			s.logger.WithError(err).Warn("Failed to report simulated incident")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Failure simulation triggered", "type": "security_incident"}`))
}

// Middleware
func (s *HealthMonitoringServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapper := &healthResponseWrapper{ResponseWriter: w, statusCode: http.StatusOK}
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

type healthResponseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *healthResponseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Stop gracefully stops the server
func (s *HealthMonitoringServer) Stop() error {
	s.logger.Info("Stopping health monitoring demo server")

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

// Main function for health monitoring demo
func main() {
	configFile := flag.String("config", "health-monitoring.toml", "Configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := loadHealthMonitoringConfig(*configFile)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration")
	}

	// Create and initialize server
	server := NewHealthMonitoringServer(cfg)
	if err := server.Initialize(); err != nil {
		logrus.WithError(err).Fatal("Failed to initialize server")
	}

	// Start server
	if err := server.Start(); err != nil {
		logrus.WithError(err).Fatal("Failed to start server")
	}

	logrus.WithField("bind", cfg.Server.Bind).Info("Health monitoring demo server started")
	logrus.Info("Visit http://localhost:8080 for the demo interface")
	logrus.Info("Health monitoring endpoints:")
	logrus.Info("  - GET /health - Overall system health")
	logrus.Info("  - GET /health/liveness - Kubernetes liveness probe")
	logrus.Info("  - GET /health/readiness - Kubernetes readiness probe")
	logrus.Info("  - GET /plugins/status - Plugin status information")
	logrus.Info("  - POST /plugins/restart?plugin=<name> - Restart specific plugin")

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

// loadHealthMonitoringConfig loads configuration for health monitoring demo
func loadHealthMonitoringConfig(filename string) (*HealthMonitoringConfig, error) {
	// Default configuration
	cfg := &HealthMonitoringConfig{
		Server: HealthServerSettings{
			Bind: ":8080",
		},
		Logging: HealthLoggingSettings{
			Level: "info",
		},
		Plugins: HealthPluginSettings{
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