// Example of how to set up plugins in Hockeypuck with Interpose
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/carbocation/interpose"
	"github.com/gorilla/mux"

	"hkp-plugin-core/pkg/plugin"
	"hkp-plugin-core/src/plugins/mlabuse/mlabuse"
	"hkp-plugin-core/src/plugins/ratelimit-geo/ratelimitgeo"
	"hkp-plugin-core/src/plugins/ratelimit-ml/ratelimitml"
	"hkp-plugin-core/src/plugins/ratelimit-tarpit/ratelimittarpit"
	"hkp-plugin-core/src/plugins/ratelimit-threat/ratelimitthreat"
	"hkp-plugin-core/src/plugins/zerotrust/zerotrust"
)

// Server represents the Hockeypuck server with plugin support
type Server struct {
	middleware    *interpose.Middleware
	router        *mux.Router
	pluginManager *plugin.PluginManager
	logger        plugin.Logger
}

// NewServer creates a new server instance
func NewServer() *Server {
	// Create logger
	logger := &simpleLogger{}

	// Create Interpose middleware chain
	middle := interpose.New()

	// Add basic middleware
	middle.Use(loggingMiddleware(logger))
	middle.Use(recoveryMiddleware(logger))

	// Create router
	router := mux.NewRouter()

	// Create plugin manager
	pluginManager := plugin.NewPluginManager(middle, logger)

	return &Server{
		middleware:    middle,
		router:        router,
		pluginManager: pluginManager,
		logger:        logger,
	}
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
func loggingMiddleware(logger plugin.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			logger.Info("Request completed",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration", time.Since(start),
				"remote", r.RemoteAddr,
			)
		})
	}
}

func recoveryMiddleware(logger plugin.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("Panic recovered", "error", err, "path", r.URL.Path)
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

// simpleLogger implements the Logger interface
type simpleLogger struct{}

func (l *simpleLogger) Debug(msg string, args ...interface{}) {
	log.Printf("[DEBUG] %s %v", msg, args)
}

func (l *simpleLogger) Info(msg string, args ...interface{}) {
	log.Printf("[INFO] %s %v", msg, args)
}

func (l *simpleLogger) Warn(msg string, args ...interface{}) {
	log.Printf("[WARN] %s %v", msg, args)
}

func (l *simpleLogger) Error(msg string, args ...interface{}) {
	log.Printf("[ERROR] %s %v", msg, args)
}

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
