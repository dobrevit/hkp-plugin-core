// Package antiabuse provides basic behavioral anti-abuse functionality
package antiabuse

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
)

// Plugin constants
const (
	PluginName    = "antiabuse-basic"
	PluginVersion = "1.0.0"
)

// AntiAbusePlugin implements basic behavioral anti-abuse functionality
type AntiAbusePlugin struct {
	host          plugin.PluginHost
	requestCounts map[string][]time.Time
	mu            sync.Mutex
	threshold     int
	window        time.Duration
	shutdownCh    chan struct{}
	whitelist     map[string]bool
	ipNets        []*net.IPNet
}

// Initialize implements the Plugin interface
func (p *AntiAbusePlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
	p.host = host
	p.requestCounts = make(map[string][]time.Time)
	p.threshold = 10            // default threshold
	p.window = 10 * time.Second // default window
	p.shutdownCh = make(chan struct{})
	p.whitelist = make(map[string]bool)
	p.ipNets = make([]*net.IPNet, 0)

	if cfg, ok := config["requestThreshold"].(int); ok {
		p.threshold = cfg
	}
	if cfg, ok := config["windowSeconds"].(int); ok {
		p.window = time.Duration(cfg) * time.Second
	}

	// Initialize whitelist with default safe IPs
	defaultWhitelist := []string{
		"127.0.0.1",
		"::1",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	// Check if custom whitelist is provided
	if whitelistCfg, ok := config["whitelist"].([]interface{}); ok {
		defaultWhitelist = make([]string, 0, len(whitelistCfg))
		for _, ip := range whitelistCfg {
			if ipStr, ok := ip.(string); ok {
				defaultWhitelist = append(defaultWhitelist, ipStr)
			}
		}
	}

	// Parse whitelist entries
	for _, ipStr := range defaultWhitelist {
		if ip := net.ParseIP(ipStr); ip != nil {
			// Single IP address
			p.whitelist[ip.String()] = true
		} else if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
			// CIDR range
			p.ipNets = append(p.ipNets, ipNet)
		} else {
			host.Logger().Warn("Invalid whitelist entry", "ip", ipStr)
		}
	}

	host.Logger().Info("Anti-abuse plugin initialized",
		"threshold", p.threshold,
		"window", p.window,
		"whitelist_ips", len(p.whitelist),
		"whitelist_nets", len(p.ipNets))

	// Register middleware
	middleware, err := p.CreateMiddleware()
	if err != nil {
		return fmt.Errorf("failed to create middleware: %w", err)
	}

	if err := host.RegisterMiddleware("/", middleware); err != nil {
		return fmt.Errorf("failed to register middleware: %w", err)
	}

	return nil
}

// Name returns the plugin name
func (p *AntiAbusePlugin) Name() string {
	return PluginName
}

// Version returns the plugin version
func (p *AntiAbusePlugin) Version() string {
	return PluginVersion
}

// Description returns the plugin description
func (p *AntiAbusePlugin) Description() string {
	return "Basic behavioral anti-abuse functionality with request rate limiting"
}

// Dependencies returns required dependencies
func (p *AntiAbusePlugin) Dependencies() []plugin.PluginDependency {
	return []plugin.PluginDependency{}
}

// Priority returns the plugin priority (higher numbers run later)
func (p *AntiAbusePlugin) Priority() int {
	return 100 // Run early in the middleware chain
}

// Shutdown gracefully stops the plugin
func (p *AntiAbusePlugin) Shutdown(ctx context.Context) error {
	close(p.shutdownCh)
	return nil
}

// CreateMiddleware creates the anti-abuse middleware
func (p *AntiAbusePlugin) CreateMiddleware() (func(http.Handler) http.Handler, error) {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := p.extractClientIP(r)
			now := time.Now()

			// Check if IP is whitelisted
			if p.isWhitelisted(clientIP) {
				// Add headers for debugging but don't enforce limits
				w.Header().Set("X-AntiAbuse-Plugin", fmt.Sprintf("%s/%s", p.Name(), p.Version()))
				w.Header().Set("X-AntiAbuse-Whitelisted", "true")
				w.Header().Set("X-AntiAbuse-ClientIP", clientIP)
				next.ServeHTTP(w, r)
				return
			}

			p.mu.Lock()
			reqs := append(p.requestCounts[clientIP], now)
			// Purge old requests outside the window
			cutoff := now.Add(-p.window)
			n := 0
			for _, t := range reqs {
				if t.After(cutoff) {
					reqs[n] = t
					n++
				}
			}
			reqs = reqs[:n]
			p.requestCounts[clientIP] = reqs
			p.mu.Unlock()

			// Always add debugging headers for SIEM and monitoring
			w.Header().Set("X-AntiAbuse-Plugin", fmt.Sprintf("%s/%s", p.Name(), p.Version()))
			w.Header().Set("X-AntiAbuse-Requests", fmt.Sprintf("%d/%d", len(reqs), p.threshold))
			w.Header().Set("X-AntiAbuse-Window", p.window.String())
			w.Header().Set("X-AntiAbuse-ClientIP", clientIP)

			if len(reqs) > p.threshold {
				w.Header().Set("X-AntiAbuse-Blocked", "true")
				w.Header().Set("X-RateLimit-Ban", "10s")
				w.Header().Set("X-AntiAbuse-Reason", "rate_exceeded")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte("Rate limit exceeded: Too many requests"))
				return
			}

			// Not blocked
			w.Header().Set("X-AntiAbuse-Blocked", "false")
			next.ServeHTTP(w, r)
		})
	}, nil
}

// extractClientIP extracts the client IP from the request
func (p *AntiAbusePlugin) extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

// isWhitelisted checks if an IP is whitelisted
func (p *AntiAbusePlugin) isWhitelisted(ip string) bool {
	// Check exact IP match
	if p.whitelist[ip] {
		return true
	}

	// Check CIDR ranges
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, ipNet := range p.ipNets {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// GetPlugin returns a new instance of the plugin for dynamic loading
func GetPlugin() plugin.Plugin {
	return &AntiAbusePlugin{}
}
