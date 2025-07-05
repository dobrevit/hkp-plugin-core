// Example of how to set up plugins in Hockeypuck with Interpose
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/carbocation/interpose"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/dobrevit/hkp-plugin-core/pkg/config"
	"github.com/dobrevit/hkp-plugin-core/pkg/events"
	"github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
	"github.com/dobrevit/hkp-plugin-core/pkg/metrics"
	"github.com/dobrevit/hkp-plugin-core/pkg/middleware"
	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/mlabuse/mlabuse"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/ratelimit-geo/ratelimitgeo"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/ratelimit-ml/ratelimitml"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/ratelimit-tarpit/ratelimittarpit"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/ratelimit-threat/ratelimitthreat"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/zerotrust/zerotrust"
)

// Server represents the Hockeypuck server with plugin support
type Server struct {
	middleware      *interpose.Middleware
	router          *mux.Router
	pluginManager   *plugin.PluginManager
	eventBus        *events.EventBus
	middlewareChain *middleware.MiddlewareChain
	settings        *config.Settings
	logger          *log.Logger
}

// ServerPluginHost implements the PluginHost interface for the server
type ServerPluginHost struct {
	server *Server
}

// RegisterMiddleware registers middleware handlers
func (h *ServerPluginHost) RegisterMiddleware(path string, middlewareFunc func(http.Handler) http.Handler) error {
	// Use the new middleware chain system
	mw := middleware.Middleware{
		Name:     "plugin-middleware",
		Priority: middleware.PriorityMedium,
		Handler:  middlewareFunc,
		Path:     path,
	}
	h.server.middlewareChain.Add(mw)
	return nil
}

// RegisterHandler registers API endpoints
func (h *ServerPluginHost) RegisterHandler(pattern string, handler http.HandlerFunc) error {
	h.server.router.HandleFunc(pattern, handler)
	return nil
}

// Storage returns storage backend
func (h *ServerPluginHost) Storage() hkpstorage.Storage {
	// Return mock storage for now - in real Hockeypuck this would be the actual storage
	return nil
}

// Config returns configuration
func (h *ServerPluginHost) Config() *config.Settings {
	return h.server.settings
}

// Metrics returns metrics system
func (h *ServerPluginHost) Metrics() *metrics.Metrics {
	return metrics.NewMetrics()
}

// Logger returns logger
func (h *ServerPluginHost) Logger() *log.Logger {
	return h.server.logger
}

// RegisterTask registers periodic tasks
func (h *ServerPluginHost) RegisterTask(name string, interval time.Duration, task func(context.Context) error) error {
	// In a real implementation, this would register with a task scheduler
	h.server.logger.WithFields(log.Fields{
		"task":     name,
		"interval": interval,
	}).Debug("Task registered")
	return nil
}

// Event system methods
func (h *ServerPluginHost) PublishEvent(event events.PluginEvent) error {
	return h.server.eventBus.PublishEvent(event)
}

func (h *ServerPluginHost) SubscribeEvent(eventType string, handler events.PluginEventHandler) error {
	return h.server.eventBus.SubscribeEvent(eventType, handler)
}

func (h *ServerPluginHost) SubscribeKeyChanges(callback func(hkpstorage.KeyChange) error) error {
	return h.server.eventBus.SubscribeKeyChanges(callback)
}

// Convenience methods
func (h *ServerPluginHost) PublishThreatDetected(threat events.ThreatInfo) error {
	return h.server.eventBus.PublishThreatDetected(threat)
}

func (h *ServerPluginHost) PublishRateLimitViolation(violation events.RateLimitViolation) error {
	return h.server.eventBus.PublishRateLimitViolation(violation)
}

func (h *ServerPluginHost) PublishZTNAEvent(eventType string, ztnaEvent events.ZTNAEvent) error {
	return h.server.eventBus.PublishZTNAEvent(eventType, ztnaEvent)
}

// logrusLoggerAdapter adapts *log.Logger to plugin.Logger interface
type logrusLoggerAdapter struct {
	*log.Logger
}

func (l *logrusLoggerAdapter) Debug(msg string, args ...interface{}) {
	l.Logger.Debugf(msg, args...)
}
func (l *logrusLoggerAdapter) Info(msg string, args ...interface{}) {
	l.Logger.Infof(msg, args...)
}
func (l *logrusLoggerAdapter) Warn(msg string, args ...interface{}) {
	l.Logger.Warnf(msg, args...)
}
func (l *logrusLoggerAdapter) Error(msg string, args ...interface{}) {
	l.Logger.Errorf(msg, args...)
}

// NewServer creates a new server instance
func NewServer() *Server {
	// Create logger
	logger := log.StandardLogger()

	// Create default settings
	settings := config.DefaultSettings()

	// Create event bus
	eventBus := events.NewEventBus(logger)

	// Create middleware chain
	middlewareChain := middleware.NewMiddlewareChain(logger)

	// Create Interpose middleware chain
	middle := interpose.New()

	// Create router
	router := mux.NewRouter()

	// Create server
	server := &Server{
		middleware:      middle,
		router:          router,
		eventBus:        eventBus,
		middlewareChain: middlewareChain,
		settings:        &settings,
		logger:          logger,
	}

	// Create plugin host
	host := &ServerPluginHost{
		server: server,
	}

	// Wrap logger for plugin manager
	pluginLogger := &logrusLoggerAdapter{Logger: logger}

	// Create plugin manager
	pluginManager := plugin.NewPluginManager(host, pluginLogger)
	server.pluginManager = pluginManager

	// Add basic middleware to interpose chain
	middle.Use(loggingMiddleware())
	middle.Use(recoveryMiddleware(logger))

	return server
}

// LoadPlugins loads all configured plugins in the correct order
func (s *Server) LoadPlugins(ctx context.Context, config map[string]interface{}) error {
	// Plugin loading order matters! Load dependencies first
	pluginConfigs := []struct {
		plugin plugin.Plugin
		config map[string]interface{}
	}{
		// 1. Rate limiting base (priority 10) - DISABLED: Missing implementation
		// {
		//	plugin: &RateLimitPlugin{}, // Base rate limiting plugin
		//	config: config["ratelimit"].(map[string]interface{}),
		// },
		// 2. Threat Intelligence (priority 15)
		{
			plugin: &ratelimitthreat.ThreatIntelPlugin{},
			config: config["ratelimit-threat-intel"].(map[string]interface{}),
		},
		// 3. Geographic Analysis (priority 20)
		{
			plugin: &ratelimitgeo.RateLimitGeoPlugin{},
			config: config["ratelimit-geo"].(map[string]interface{}),
		},
		// 4. ML Rate Limiting (priority 25)
		{
			plugin: &ratelimitml.RateLimitMLPlugin{},
			config: config["ratelimit-ml"].(map[string]interface{}),
		},
		// 5. ML Abuse Detection (priority 30)
		{
			plugin: &mlabuse.MLAbusePlugin{},
			config: config["ml-abuse-detector"].(map[string]interface{}),
		},
		// 6. Zero Trust (priority 40)
		{
			plugin: &zerotrust.ZeroTrustPlugin{},
			config: config["zero-trust-security"].(map[string]interface{}),
		},
		// 7. Tarpit (priority 50)
		{
			plugin: &ratelimittarpit.TarpitPlugin{},
			config: config["ratelimit-tarpit"].(map[string]interface{}),
		},
	}

	// Load plugins in order
	for _, pc := range pluginConfigs {
		if err := s.pluginManager.LoadPlugin(ctx, pc.plugin, pc.config); err != nil {
			return fmt.Errorf("failed to load plugin %s: %w", pc.plugin.Name(), err)
		}
	}

	// Register plugin routes with the router
	for pattern, handler := range s.pluginManager.GetRoutes() {
		s.router.HandleFunc(pattern, handler)
		s.logger.Info("Registered route", "pattern", pattern)
	}

	// Register core Hockeypuck routes
	s.registerCoreRoutes()

	// Finally, use the router as the final handler
	s.middleware.UseHandler(s.router)

	return nil
}

// registerCoreRoutes registers the core Hockeypuck routes
func (s *Server) registerCoreRoutes() {
	// HKP routes
	s.router.HandleFunc("/pks/lookup", s.handleLookup).Methods("GET")
	s.router.HandleFunc("/pks/add", s.handleAdd).Methods("POST")
	s.router.HandleFunc("/pks/hashquery", s.handleHashQuery).Methods("POST")

	// Stats and health
	s.router.HandleFunc("/pks/stats", s.handleStats).Methods("GET")
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")

	// API routes
	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/keys/{keyid}", s.handleAPILookup).Methods("GET")
	api.HandleFunc("/keys", s.handleAPIAdd).Methods("POST")
}

// Start starts the server
func (s *Server) Start(addr string) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.middleware,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		s.logger.Info("Starting server", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Server error", "error", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// Shutdown gracefully
	s.logger.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown plugins first
	if err := s.pluginManager.Shutdown(ctx); err != nil {
		s.logger.Error("Error shutting down plugins", "error", err)
	}

	// Shutdown server
	return srv.Shutdown(ctx)
}

// Core route handlers (simplified examples)
func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	// HKP lookup implementation
	w.Write([]byte("HKP Lookup"))
}

func (s *Server) handleAdd(w http.ResponseWriter, r *http.Request) {
	// HKP add implementation
	w.Write([]byte("HKP Add"))
}

func (s *Server) handleHashQuery(w http.ResponseWriter, r *http.Request) {
	// HKP hashquery implementation
	w.Write([]byte("HKP HashQuery"))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	// Stats implementation
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Health check
	w.Write([]byte("OK"))
}

func (s *Server) handleAPILookup(w http.ResponseWriter, r *http.Request) {
	// API lookup implementation
	vars := mux.Vars(r)
	keyID := vars["keyid"]
	w.Write([]byte(fmt.Sprintf("API Lookup: %s", keyID)))
}

func (s *Server) handleAPIAdd(w http.ResponseWriter, r *http.Request) {
	// API add implementation
	w.Write([]byte("API Add"))
}

// Middleware functions
func loggingMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			log.WithFields(log.Fields{
				"method":   r.Method,
				"path":     r.URL.Path,
				"status":   wrapped.statusCode,
				"duration": time.Since(start),
				"remote":   r.RemoteAddr,
			}).Info("Request completed")
		})
	}
}

func recoveryMiddleware(logger *log.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					log.WithFields(log.Fields{
						"error": err,
						"path":  r.URL.Path,
					}).Error("Panic recovered")
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Legacy simpleLogger removed - using logrus directly now

// Base rate limiting plugin (simplified)
type RateLimitPlugin struct {
	config map[string]interface{}
}

func (p *RateLimitPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
	p.config = config
	return nil
}

func (p *RateLimitPlugin) Name() string                            { return "ratelimit" }
func (p *RateLimitPlugin) Version() string                         { return "1.0.0" }
func (p *RateLimitPlugin) Description() string                     { return "Base rate limiting" }
func (p *RateLimitPlugin) Dependencies() []plugin.PluginDependency { return nil }
func (p *RateLimitPlugin) Shutdown(ctx context.Context) error      { return nil }

func (p *RateLimitPlugin) Middleware() (func(next http.Handler) http.Handler, int) {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Basic rate limiting logic
			next.ServeHTTP(w, r)
		})
	}, 10 // Priority 10 (runs first)
}

// Main function
func main() {
	// Load configuration
	config := loadConfig()

	// Create server
	server := NewServer()

	// Load plugins
	ctx := context.Background()
	if err := server.LoadPlugins(ctx, config); err != nil {
		log.Fatal("Failed to load plugins:", err)
	}

	// Start server
	if err := server.Start(":11371"); err != nil {
		log.Fatal("Server error:", err)
	}
}

func loadConfig() map[string]interface{} {
	// In production, load from TOML file
	return map[string]interface{}{
		"ratelimit": map[string]interface{}{
			"enabled": true,
		},
		"ml-abuse-detector": map[string]interface{}{
			"enabled":          true,
			"anomalyThreshold": 0.85,
		},
		"zero-trust-security": map[string]interface{}{
			"enabled": true,
		},
		"ratelimit-geo": map[string]interface{}{
			"enabled": true,
		},
		"ratelimit-ml": map[string]interface{}{
			"enabled": true,
		},
		"ratelimit-threat-intel": map[string]interface{}{
			"enabled": true,
		},
		"ratelimit-tarpit": map[string]interface{}{
			"enabled": true,
		},
	}
}
