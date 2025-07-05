// Package middleware provides Hockeypuck-compatible middleware patterns
// This ensures plugins work seamlessly with interpose middleware chains
package middleware

import (
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// InterposePriority defines middleware execution order
type InterposePriority int

const (
	// High priority - runs first (security, auth)
	PriorityHigh InterposePriority = 100

	// Medium priority - runs in middle (rate limiting, validation)
	PriorityMedium InterposePriority = 50

	// Low priority - runs last (logging, metrics)
	PriorityLow InterposePriority = 10
)

// Middleware represents a plugin middleware with priority
type Middleware struct {
	Name     string
	Priority InterposePriority
	Handler  func(http.Handler) http.Handler
	Path     string // Path pattern this middleware applies to
}

// MiddlewareChain manages ordered middleware execution compatible with interpose
type MiddlewareChain struct {
	middlewares []Middleware
	logger      *log.Logger
}

// NewMiddlewareChain creates a new middleware chain
func NewMiddlewareChain(logger *log.Logger) *MiddlewareChain {
	return &MiddlewareChain{
		middlewares: make([]Middleware, 0),
		logger:      logger,
	}
}

// Add adds middleware to the chain
func (mc *MiddlewareChain) Add(middleware Middleware) {
	mc.middlewares = append(mc.middlewares, middleware)

	// Sort by priority (higher priority runs first)
	for i := len(mc.middlewares) - 1; i > 0; i-- {
		if mc.middlewares[i].Priority > mc.middlewares[i-1].Priority {
			mc.middlewares[i], mc.middlewares[i-1] = mc.middlewares[i-1], mc.middlewares[i]
		} else {
			break
		}
	}

	mc.logger.WithFields(log.Fields{
		"middleware": middleware.Name,
		"priority":   middleware.Priority,
		"path":       middleware.Path,
		"total":      len(mc.middlewares),
	}).Debug("Middleware added to chain")
}

// Build creates the final middleware handler compatible with interpose
func (mc *MiddlewareChain) Build() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		// Apply middlewares in reverse order (last to first)
		// so they execute in priority order
		for i := len(mc.middlewares) - 1; i >= 0; i-- {
			middleware := mc.middlewares[i]
			handler = middleware.Handler(handler)
		}

		return handler
	}
}

// GetMiddlewares returns all registered middlewares for inspection
func (mc *MiddlewareChain) GetMiddlewares() []Middleware {
	return mc.middlewares
}

// PluginMiddlewareWrapper wraps plugin middleware for interpose compatibility
type PluginMiddlewareWrapper struct {
	pluginName string
	logger     *log.Logger
}

// NewPluginMiddlewareWrapper creates a wrapper for plugin middleware
func NewPluginMiddlewareWrapper(pluginName string, logger *log.Logger) *PluginMiddlewareWrapper {
	return &PluginMiddlewareWrapper{
		pluginName: pluginName,
		logger:     logger,
	}
}

// WrapMiddleware wraps plugin middleware with logging and error handling
func (pmw *PluginMiddlewareWrapper) WrapMiddleware(
	middleware func(http.Handler) http.Handler,
	priority InterposePriority,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Add plugin context to request
			r.Header.Set("X-Plugin-Source", pmw.pluginName)

			defer func() {
				if err := recover(); err != nil {
					pmw.logger.WithFields(log.Fields{
						"plugin": pmw.pluginName,
						"path":   r.URL.Path,
						"error":  err,
					}).Error("Plugin middleware panic")
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()

			// Track middleware execution
			pmw.logger.WithFields(log.Fields{
				"plugin":   pmw.pluginName,
				"path":     r.URL.Path,
				"priority": priority,
			}).Debug("Plugin middleware executing")

			// Execute the actual middleware
			wrappedNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pmw.logger.WithFields(log.Fields{
					"plugin":   pmw.pluginName,
					"path":     r.URL.Path,
					"duration": time.Since(start),
				}).Debug("Plugin middleware completed")
				next.ServeHTTP(w, r)
			})

			middleware(wrappedNext).ServeHTTP(w, r)
		})
	}
}

// Common middleware helpers for plugins

// SecurityMiddleware provides common security patterns
func SecurityMiddleware(pluginName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add security headers
			w.Header().Set("X-Plugin-Security", pluginName)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")

			next.ServeHTTP(w, r)
		})
	}
}

// MetricsMiddleware provides request metrics
func MetricsMiddleware(pluginName string, logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
			logger.WithFields(log.Fields{
				"plugin":   pluginName,
				"method":   r.Method,
				"path":     r.URL.Path,
				"status":   wrapped.statusCode,
				"duration": duration,
				"size":     wrapped.size,
			}).Info("Plugin request completed")
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture metrics
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// PathMatcher provides path-based middleware application
type PathMatcher struct {
	patterns map[string]func(http.Handler) http.Handler
	logger   *log.Logger
}

// NewPathMatcher creates a new path matcher
func NewPathMatcher(logger *log.Logger) *PathMatcher {
	return &PathMatcher{
		patterns: make(map[string]func(http.Handler) http.Handler),
		logger:   logger,
	}
}

// AddPath adds a path-specific middleware
func (pm *PathMatcher) AddPath(pattern string, middleware func(http.Handler) http.Handler) {
	pm.patterns[pattern] = middleware
	pm.logger.WithField("pattern", pattern).Debug("Path-specific middleware added")
}

// Middleware returns a middleware that applies path-specific handlers
func (pm *PathMatcher) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for matching patterns
			for pattern, middleware := range pm.patterns {
				if matchPath(r.URL.Path, pattern) {
					pm.logger.WithFields(log.Fields{
						"path":    r.URL.Path,
						"pattern": pattern,
					}).Debug("Applying path-specific middleware")
					middleware(next).ServeHTTP(w, r)
					return
				}
			}

			// No pattern matched, continue normally
			next.ServeHTTP(w, r)
		})
	}
}

// matchPath checks if a path matches a pattern (simple prefix matching)
func matchPath(path, pattern string) bool {
	if pattern == "/" {
		return true // Root pattern matches everything
	}
	if pattern == path {
		return true // Exact match
	}
	if len(pattern) < len(path) && path[:len(pattern)] == pattern {
		// Prefix match - ensure it's a clean boundary
		if path[len(pattern)] == '/' {
			return true
		}
	}
	return false
}
