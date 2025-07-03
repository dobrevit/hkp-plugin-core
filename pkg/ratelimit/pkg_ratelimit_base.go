// Package ratelimit provides rate limiting functionality for Hockeypuck
package ratelimit

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"gopkg.in/tomb.v2"
)

// Backend interface for rate limiting storage
type Backend interface {
	// Connection tracking
	GetConnectionCount(ip string) (int, error)
	IncrementConnectionCount(ip string, ttl time.Duration) error
	DecrementConnectionCount(ip string) error

	// Request rate tracking
	GetRequestCount(ip string, window time.Duration) (int, error)
	IncrementRequestCount(ip string, window time.Duration) error

	// Error rate tracking
	GetErrorCount(ip string, window time.Duration) (int, error)
	IncrementErrorCount(ip string, window time.Duration) error

	// Ban management
	IsBanned(ip string) (bool, time.Time, string, error)
	BanIP(ip string, duration time.Duration, reason string) error
	UnbanIP(ip string) error

	// Tor exit node management
	IsTorExit(ip string) (bool, error)
	SetTorExits(ips []string, ttl time.Duration) error
	GetTorExitCount() (int, error)

	// Global Tor rate limiting
	GetGlobalTorRequestCount(window time.Duration) (int, error)
	IncrementGlobalTorRequestCount(window time.Duration) error

	// Statistics
	GetStats() (BackendStats, error)

	// Cleanup
	Cleanup(ctx context.Context) error

	// Close
	Close() error
}

// BackendStats represents backend statistics
type BackendStats struct {
	TrackedIPs    int       `json:"tracked_ips"`
	BannedIPs     int       `json:"banned_ips"`
	TorBanned     int       `json:"tor_banned"`
	BackendType   string    `json:"backend_type"`
	TorExitCount  int       `json:"tor_exits_count"`
	TorLastUpdate time.Time `json:"tor_last_updated"`
}

// Config represents rate limiting configuration
type Config struct {
	Enabled                  bool          `toml:"enabled"`
	MaxConcurrentConnections int           `toml:"maxConcurrentConnections"`
	ConnectionRate           int           `toml:"connectionRate"`
	HTTPRequestRate          int           `toml:"httpRequestRate"`
	HTTPErrorRate            int           `toml:"httpErrorRate"`
	CrawlerBlockDuration     time.Duration `toml:"crawlerBlockDuration"`
	TrustProxyHeaders        bool          `toml:"trustProxyHeaders"`

	// Backend configuration
	Backend BackendConfig `toml:"backend"`

	// Tor configuration
	Tor TorConfig `toml:"tor"`

	// Whitelist configuration
	Whitelist WhitelistConfig `toml:"whitelist"`

	// Keyserver sync configuration
	KeyserverSync KeyserverSyncConfig `toml:"keyserverSync"`

	// Header configuration
	Headers HeaderConfig `toml:"headers"`
}

// BackendConfig represents backend configuration
type BackendConfig struct {
	Type   string       `toml:"type"`
	Memory MemoryConfig `toml:"memory"`
	Redis  RedisConfig  `toml:"redis"`
}

// MemoryConfig represents memory backend configuration
type MemoryConfig struct {
	// No specific configuration needed for memory backend
}

// RedisConfig represents Redis backend configuration
type RedisConfig struct {
	Addr         string        `toml:"addr"`
	Password     string        `toml:"password"`
	DB           int           `toml:"db"`
	PoolSize     int           `toml:"poolSize"`
	DialTimeout  time.Duration `toml:"dialTimeout"`
	ReadTimeout  time.Duration `toml:"readTimeout"`
	WriteTimeout time.Duration `toml:"writeTimeout"`
	KeyPrefix    string        `toml:"keyPrefix"`
	TTL          time.Duration `toml:"ttl"`
	MaxRetries   int           `toml:"maxRetries"`
}

// TorConfig represents Tor-specific configuration
type TorConfig struct {
	Enabled                   bool          `toml:"enabled"`
	MaxRequestsPerConnection  int           `toml:"maxRequestsPerConnection"`
	MaxConcurrentConnections  int           `toml:"maxConcurrentConnections"`
	ConnectionRate            int           `toml:"connectionRate"`
	ConnectionRateWindow      time.Duration `toml:"connectionRateWindow"`
	BanDuration               time.Duration `toml:"banDuration"`
	RepeatOffenderBanDuration time.Duration `toml:"repeatOffenderBanDuration"`
	ExitNodeListURL           string        `toml:"exitNodeListURL"`
	UpdateInterval            time.Duration `toml:"updateInterval"`
	CacheFilePath             string        `toml:"cacheFilePath"`
	UserAgent                 string        `toml:"userAgent"`

	// Global Tor rate limiting
	GlobalRateLimit   bool          `toml:"globalRateLimit"`
	GlobalRequestRate int           `toml:"globalRequestRate"`
	GlobalRateWindow  time.Duration `toml:"globalRateWindow"`
	GlobalBanDuration time.Duration `toml:"globalBanDuration"`
}

// WhitelistConfig represents whitelist configuration
type WhitelistConfig struct {
	IPs []string `toml:"ips"`
}

// KeyserverSyncConfig represents keyserver sync configuration
type KeyserverSyncConfig struct {
	Enabled bool `toml:"enabled"`
}

// HeaderConfig represents header configuration
type HeaderConfig struct {
	Enabled   bool   `toml:"enabled"`
	TorHeader string `toml:"torHeader"`
	BanHeader string `toml:"banHeader"`
}

// Default configuration values
func DefaultConfig() Config {
	return Config{
		Enabled:                  true,
		MaxConcurrentConnections: 80,
		ConnectionRate:           40,
		HTTPRequestRate:          100,
		HTTPErrorRate:            20,
		CrawlerBlockDuration:     24 * time.Hour,
		TrustProxyHeaders:        false,
		Backend: BackendConfig{
			Type: "memory",
			Redis: RedisConfig{
				Addr:         "localhost:6379",
				Password:     "",
				DB:           0,
				PoolSize:     10,
				DialTimeout:  5 * time.Second,
				ReadTimeout:  3 * time.Second,
				WriteTimeout: 3 * time.Second,
				KeyPrefix:    "hockeypuck:ratelimit:",
				TTL:          24 * time.Hour,
				MaxRetries:   3,
			},
		},
		Tor: TorConfig{
			Enabled:                   true,
			MaxRequestsPerConnection:  2,
			MaxConcurrentConnections:  1,
			ConnectionRate:            1,
			ConnectionRateWindow:      10 * time.Second,
			BanDuration:               24 * time.Hour,
			RepeatOffenderBanDuration: 24 * 24 * time.Hour, // 24 days
			ExitNodeListURL:           "https://www.dan.me.uk/torlist/?exit",
			UpdateInterval:            1 * time.Hour,
			CacheFilePath:             "tor_exit_nodes.cache",
			GlobalRateLimit:           true,
			GlobalRequestRate:         1,
			GlobalRateWindow:          10 * time.Second,
			GlobalBanDuration:         1 * time.Hour,
		},
		Whitelist: WhitelistConfig{
			IPs: []string{
				"127.0.0.1",
				"::1",
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
		},
		KeyserverSync: KeyserverSyncConfig{
			Enabled: true,
		},
		Headers: HeaderConfig{
			Enabled:   true,
			TorHeader: "X-Tor-Exit",
			BanHeader: "X-RateLimit-Ban",
		},
	}
}

// RateLimiter represents the main rate limiting system
type RateLimiter struct {
	config    Config
	backend   Backend
	whitelist map[string]bool
	ipNets    []*net.IPNet
	tomb      tomb.Tomb
	metrics   *RateLimitMetrics

	// Tor exit node management
	torExits   map[string]bool
	torMutex   sync.RWMutex
	torUpdater *TorExitUpdater

	// Request tracking for connection limits
	activeConnections map[string]int
	connectionsMutex  sync.RWMutex
}

// RateLimitMetrics represents Prometheus metrics for rate limiting
type RateLimitMetrics struct {
	ViolationsTotal *prometheus.CounterVec
	BannedIPs       *prometheus.GaugeVec
	TrackedIPs      prometheus.Gauge
	TorExitCount    prometheus.Gauge
	BackendDuration *prometheus.HistogramVec
}

// New creates a new rate limiter
func New(config Config) (*RateLimiter, error) {
	rl := &RateLimiter{
		config:            config,
		activeConnections: make(map[string]int),
		torExits:          make(map[string]bool),
	}

	// Initialize backend
	backend, err := createBackend(config.Backend)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend: %w", err)
	}
	rl.backend = backend

	// Initialize whitelist
	if err := rl.initWhitelist(); err != nil {
		return nil, fmt.Errorf("failed to initialize whitelist: %w", err)
	}

	// Initialize metrics
	rl.initMetrics()

	// Initialize Tor exit updater if enabled
	if config.Tor.Enabled {
		rl.torUpdater = NewTorExitUpdater(config.Tor, rl.backend)
	}

	return rl, nil
}

// createBackend creates the appropriate backend based on configuration
func createBackend(config BackendConfig) (Backend, error) {
	switch config.Type {
	case "memory":
		return NewMemoryBackend(), nil
	case "redis":
		return NewRedisBackend(config.Redis)
	default:
		return nil, fmt.Errorf("unknown backend type: %s", config.Type)
	}
}

// initWhitelist initializes the IP whitelist
func (rl *RateLimiter) initWhitelist() error {
	rl.whitelist = make(map[string]bool)
	rl.ipNets = make([]*net.IPNet, 0)

	for _, ipStr := range rl.config.Whitelist.IPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			// Single IP address
			rl.whitelist[ip.String()] = true
		} else if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
			// CIDR range
			rl.ipNets = append(rl.ipNets, ipNet)
		} else {
			return fmt.Errorf("invalid IP or CIDR: %s", ipStr)
		}
	}

	return nil
}

// initMetrics initializes Prometheus metrics
func (rl *RateLimiter) initMetrics() {
	rl.metrics = &RateLimitMetrics{
		ViolationsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_rate_limit_violations_total",
			Help: "Total number of rate limit violations",
		}, []string{"reason", "is_tor"}),

		BannedIPs: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_rate_limit_banned_ips",
			Help: "Number of currently banned IPs",
		}, []string{"is_tor"}),

		TrackedIPs: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_rate_limit_tracked_ips",
			Help: "Number of IPs being tracked",
		}),

		TorExitCount: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_rate_limit_tor_exits",
			Help: "Number of known Tor exit nodes",
		}),

		BackendDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_rate_limit_backend_duration_seconds",
			Help:    "Duration of backend operations",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		}, []string{"operation"}),
	}
}

// Start starts the rate limiter background tasks
func (rl *RateLimiter) Start() {
	if !rl.config.Enabled {
		return
	}

	// Start Tor exit list updater
	if rl.config.Tor.Enabled && rl.torUpdater != nil {
		rl.tomb.Go(rl.torUpdater.Run)
	}

	// Start cleanup task
	rl.tomb.Go(rl.cleanupTask)

	// Start metrics update task
	rl.tomb.Go(rl.metricsUpdateTask)
}

// Stop stops the rate limiter background tasks
func (rl *RateLimiter) Stop() {
	rl.tomb.Kill(nil)
	rl.tomb.Wait()

	if rl.backend != nil {
		rl.backend.Close()
	}
}

// IsWhitelisted checks if an IP is whitelisted
func (rl *RateLimiter) IsWhitelisted(ip string) bool {
	// Check exact IP match
	if rl.whitelist[ip] {
		return true
	}

	// Check CIDR ranges
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, ipNet := range rl.ipNets {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// CheckConnectionLimit checks if a connection should be allowed
func (rl *RateLimiter) CheckConnectionLimit(ip string) (bool, string) {
	if !rl.config.Enabled || rl.IsWhitelisted(ip) {
		return true, ""
	}

	// Check if IP is banned
	if banned, _, reason, err := rl.backend.IsBanned(ip); err == nil && banned {
		return false, reason
	}

	// Check concurrent connections
	rl.connectionsMutex.RLock()
	current := rl.activeConnections[ip]
	rl.connectionsMutex.RUnlock()

	maxConnections := rl.config.MaxConcurrentConnections
	if rl.isTorExit(ip) && rl.config.Tor.Enabled {
		maxConnections = rl.config.Tor.MaxConcurrentConnections
	}

	if current >= maxConnections {
		reason := fmt.Sprintf("Too many concurrent connections (%d >= %d)", current, maxConnections)
		rl.banIP(ip, rl.config.CrawlerBlockDuration, reason, "connection")
		return false, reason
	}

	// Check connection rate
	if count, err := rl.backend.GetConnectionCount(ip); err == nil {
		maxRate := rl.config.ConnectionRate
		if rl.isTorExit(ip) && rl.config.Tor.Enabled {
			maxRate = rl.config.Tor.ConnectionRate
		}

		if count >= maxRate {
			reason := fmt.Sprintf("Connection rate exceeded (%d >= %d per 3s)", count, maxRate)
			rl.banIP(ip, rl.config.CrawlerBlockDuration, reason, "connection")
			return false, reason
		}
	}

	return true, ""
}

// OnConnection tracks a new connection
func (rl *RateLimiter) OnConnection(ip string) {
	if !rl.config.Enabled || rl.IsWhitelisted(ip) {
		return
	}

	// Increment connection count
	rl.connectionsMutex.Lock()
	rl.activeConnections[ip]++
	rl.connectionsMutex.Unlock()

	// Track in backend
	rl.backend.IncrementConnectionCount(ip, 3*time.Second)
}

// OnConnectionClose tracks a closed connection
func (rl *RateLimiter) OnConnectionClose(ip string) {
	if !rl.config.Enabled || rl.IsWhitelisted(ip) {
		return
	}

	// Decrement connection count
	rl.connectionsMutex.Lock()
	if rl.activeConnections[ip] > 0 {
		rl.activeConnections[ip]--
		if rl.activeConnections[ip] == 0 {
			delete(rl.activeConnections, ip)
		}
	}
	rl.connectionsMutex.Unlock()

	// Track in backend
	rl.backend.DecrementConnectionCount(ip)
}

// CheckRequestLimit checks if a request should be allowed
func (rl *RateLimiter) CheckRequestLimit(ip string, r *http.Request) (bool, string) {
	if !rl.config.Enabled || rl.IsWhitelisted(ip) {
		return true, ""
	}

	// Check if IP is banned
	if banned, _, reason, err := rl.backend.IsBanned(ip); err == nil && banned {
		return false, reason
	}

	// Check global Tor rate limit first
	if rl.isTorExit(ip) && rl.config.Tor.Enabled && rl.config.Tor.GlobalRateLimit {
		if count, err := rl.backend.GetGlobalTorRequestCount(rl.config.Tor.GlobalRateWindow); err == nil {
			if count >= rl.config.Tor.GlobalRequestRate {
				reason := fmt.Sprintf("Global Tor rate limit exceeded (%d >= %d per %v)", count, rl.config.Tor.GlobalRequestRate, rl.config.Tor.GlobalRateWindow)
				rl.banIP(ip, rl.config.Tor.GlobalBanDuration, reason, "tor")
				return false, reason
			}
		}
		// Increment global Tor counter
		rl.backend.IncrementGlobalTorRequestCount(rl.config.Tor.GlobalRateWindow)
	}

	// Check request rate
	if count, err := rl.backend.GetRequestCount(ip, 10*time.Second); err == nil {
		if count >= rl.config.HTTPRequestRate {
			reason := fmt.Sprintf("Request rate exceeded (%d >= %d per 10s)", count, rl.config.HTTPRequestRate)
			rl.banIP(ip, rl.config.CrawlerBlockDuration, reason, "request")
			return false, reason
		}
	}

	// Increment request count
	rl.backend.IncrementRequestCount(ip, 10*time.Second)

	return true, ""
}

// OnHTTPError tracks an HTTP error
func (rl *RateLimiter) OnHTTPError(ip string, statusCode int) {
	if !rl.config.Enabled || rl.IsWhitelisted(ip) {
		return
	}

	// Only track 4xx and 5xx errors
	if statusCode < 400 {
		return
	}

	rl.backend.IncrementErrorCount(ip, 5*time.Minute)

	// Check error rate
	if count, err := rl.backend.GetErrorCount(ip, 5*time.Minute); err == nil {
		if count >= rl.config.HTTPErrorRate {
			reason := fmt.Sprintf("Error rate exceeded (%d >= %d per 5m)", count, rl.config.HTTPErrorRate)
			rl.banIP(ip, rl.config.CrawlerBlockDuration, reason, "crawler")
		}
	}
}

// isTorExit checks if an IP is a Tor exit node
func (rl *RateLimiter) isTorExit(ip string) bool {
	if !rl.config.Tor.Enabled {
		return false
	}

	if isTor, err := rl.backend.IsTorExit(ip); err == nil {
		return isTor
	}

	// Fallback to in-memory cache
	rl.torMutex.RLock()
	defer rl.torMutex.RUnlock()
	return rl.torExits[ip]
}

// banIP bans an IP address
func (rl *RateLimiter) banIP(ip string, duration time.Duration, reason, violationType string) {
	// Determine if it's a Tor exit
	isTor := rl.isTorExit(ip)

	// Use escalating ban duration for Tor repeat offenders
	if isTor && rl.config.Tor.Enabled {
		// Check if this is a repeat offender
		// For simplicity, we'll use the standard Tor ban duration
		// In a full implementation, you'd track offense counts
		duration = rl.config.Tor.BanDuration
	}

	// Ban the IP
	rl.backend.BanIP(ip, duration, reason)

	// Update metrics
	isTorStr := "false"
	if isTor {
		isTorStr = "true"
	}
	rl.metrics.ViolationsTotal.WithLabelValues(violationType, isTorStr).Inc()
}

// GetStats returns current rate limiting statistics
func (rl *RateLimiter) GetStats() (BackendStats, error) {
	return rl.backend.GetStats()
}

// SetResponseHeaders sets rate limiting headers on HTTP responses
func (rl *RateLimiter) SetResponseHeaders(w http.ResponseWriter, ip string, banned bool, banReason string, banDuration time.Duration) {
	if !rl.config.Headers.Enabled {
		return
	}

	// Set Tor exit header
	if rl.isTorExit(ip) {
		w.Header().Set(rl.config.Headers.TorHeader, "true")
	}

	// Set ban headers
	if banned {
		w.Header().Set(rl.config.Headers.BanHeader, formatDuration(banDuration))
		w.Header().Set("X-RateLimit-Ban-Reason", banReason)
		w.Header().Set("X-RateLimit-Ban-Type", "general")
	}
}

// formatDuration formats a duration for headers
func formatDuration(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmt.Sprintf("%.0fd", d.Hours()/24)
	} else if d >= time.Hour {
		return fmt.Sprintf("%.0fh", d.Hours())
	} else {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
}

// Background task for cleanup
func (rl *RateLimiter) cleanupTask() error {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			rl.backend.Cleanup(ctx)
			cancel()
		case <-rl.tomb.Dying():
			return nil
		}
	}
}

// Background task for metrics updates
func (rl *RateLimiter) metricsUpdateTask() error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if stats, err := rl.backend.GetStats(); err == nil {
				rl.metrics.TrackedIPs.Set(float64(stats.TrackedIPs))
				rl.metrics.BannedIPs.WithLabelValues("false").Set(float64(stats.BannedIPs - stats.TorBanned))
				rl.metrics.BannedIPs.WithLabelValues("true").Set(float64(stats.TorBanned))
				rl.metrics.TorExitCount.Set(float64(stats.TorExitCount))
			}
		case <-rl.tomb.Dying():
			return nil
		}
	}
}

// Middleware creates an HTTP middleware for rate limiting
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Extract client IP
			clientIP := extractClientIP(r, rl.config.TrustProxyHeaders)
			if clientIP == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check request limit
			allowed, reason := rl.CheckRequestLimit(clientIP, r)
			if !allowed {
				rl.SetResponseHeaders(w, clientIP, true, reason, rl.config.CrawlerBlockDuration)
				http.Error(w, "Rate limit exceeded: Too many requests", http.StatusTooManyRequests)
				return
			}

			// Create a response recorder to capture the status code
			recorder := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

			// Process the request
			next.ServeHTTP(recorder, r)

			// Track errors
			if recorder.statusCode >= 400 {
				rl.OnHTTPError(clientIP, recorder.statusCode)
			}
		})
	}
}

// extractClientIP extracts the client IP from the request
func extractClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		// Try X-Forwarded-For header
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return xff
		}
		// Try X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	// Fall back to remote address
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// responseRecorder captures the response status code
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}
