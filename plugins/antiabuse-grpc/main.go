// Antiabuse plugin using gRPC architecture
package main

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/server"
	"github.com/sirupsen/logrus"
)

// AntiAbusePlugin implements basic anti-abuse functionality
type AntiAbusePlugin struct {
	server.BasePlugin

	// Configuration
	maxRequestsPerMinute int
	maxRequestsPerHour   int
	blockDurationMinutes int
	suspiciousKeywords   []string
	suspiciousUserAgents []string

	// Rate limiting state
	ipRequests map[string]*RequestCounter
	blockedIPs map[string]time.Time
	mutex      sync.RWMutex

	logger *logrus.Logger
}

// RequestCounter tracks requests from an IP
type RequestCounter struct {
	RequestsPerMinute int
	RequestsPerHour   int
	LastMinute        time.Time
	LastHour          time.Time
}

// NewAntiAbusePlugin creates a new antiabuse plugin
func NewAntiAbusePlugin() *AntiAbusePlugin {
	return &AntiAbusePlugin{
		BasePlugin: server.BasePlugin{
			Name:         "antiabuse",
			Version:      "1.0.0",
			Description:  "Basic anti-abuse plugin for HKP servers",
			Capabilities: []string{"http_middleware", "rate_limiting", "abuse_detection"},
		},
		ipRequests: make(map[string]*RequestCounter),
		blockedIPs: make(map[string]time.Time),
		logger:     logrus.New(),
	}
}

// Initialize configures the plugin
func (p *AntiAbusePlugin) Initialize(config map[string]interface{}) error {
	// Call base initialization
	if err := p.BasePlugin.Initialize(config); err != nil {
		return err
	}

	// Configure logger
	p.logger.SetLevel(logrus.InfoLevel)
	p.logger.SetFormatter(&logrus.JSONFormatter{})

	// Parse configuration
	helper := server.NewConfigHelper(config)

	p.maxRequestsPerMinute = helper.GetInt("max_requests_per_minute", 60)
	p.maxRequestsPerHour = helper.GetInt("max_requests_per_hour", 1000)
	p.blockDurationMinutes = helper.GetInt("block_duration_minutes", 30)
	p.suspiciousKeywords = helper.GetStringSlice("suspicious_keywords")
	p.suspiciousUserAgents = helper.GetStringSlice("suspicious_user_agents")

	// Set defaults if not provided
	if len(p.suspiciousKeywords) == 0 {
		p.suspiciousKeywords = []string{"spam", "test", "fake", "bot"}
	}
	if len(p.suspiciousUserAgents) == 0 {
		p.suspiciousUserAgents = []string{"bot", "crawler", "scanner", "spider"}
	}

	p.logger.WithFields(logrus.Fields{
		"max_requests_per_minute": p.maxRequestsPerMinute,
		"max_requests_per_hour":   p.maxRequestsPerHour,
		"block_duration_minutes":  p.blockDurationMinutes,
	}).Info("AntiAbuse plugin initialized")

	return nil
}

// HandleHTTPRequest processes HTTP requests for abuse detection
func (p *AntiAbusePlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
	clientIP := p.extractClientIP(req)

	p.logger.WithFields(logrus.Fields{
		"method":     req.Method,
		"path":       req.Path,
		"client_ip":  clientIP,
		"user_agent": req.Headers["User-Agent"],
	}).Debug("Processing HTTP request")

	// Check if IP is blocked
	if p.isBlocked(clientIP) {
		p.logger.WithField("client_ip", clientIP).Warn("Blocked IP attempted access")
		return &proto.HTTPResponse{
			StatusCode: 429,
			Headers: map[string]string{
				"Content-Type":   "text/plain",
				"Retry-After":    "1800", // 30 minutes
				"X-Block-Reason": "Rate limit exceeded",
			},
			Body:          []byte("Too Many Requests - IP temporarily blocked"),
			ContinueChain: false,
		}, nil
	}

	// Check rate limits
	if p.exceedsRateLimit(clientIP) {
		p.blockIP(clientIP)
		p.logger.WithField("client_ip", clientIP).Warn("IP blocked for rate limit violation")
		return &proto.HTTPResponse{
			StatusCode: 429,
			Headers: map[string]string{
				"Content-Type":   "text/plain",
				"Retry-After":    "1800",
				"X-Block-Reason": "Rate limit exceeded",
			},
			Body:          []byte("Too Many Requests - Rate limit exceeded"),
			ContinueChain: false,
		}, nil
	}

	// Check for suspicious patterns
	if p.isSuspiciousRequest(req) {
		p.logger.WithFields(logrus.Fields{
			"client_ip":  clientIP,
			"user_agent": req.Headers["User-Agent"],
			"path":       req.Path,
		}).Warn("Suspicious request detected")

		// Increase rate limit penalty for suspicious requests
		p.incrementRequests(clientIP, 5) // Count as 5 requests

		return &proto.HTTPResponse{
			StatusCode: 403,
			Headers: map[string]string{
				"Content-Type":   "text/plain",
				"X-Block-Reason": "Suspicious activity detected",
			},
			Body:          []byte("Forbidden - Suspicious activity detected"),
			ContinueChain: false,
		}, nil
	}

	// Normal request - increment counter
	p.incrementRequests(clientIP, 1)

	// Allow request to continue
	return &proto.HTTPResponse{
		StatusCode:    200,
		Headers:       make(map[string]string),
		Body:          []byte{},
		ContinueChain: true,
	}, nil
}

// HandleKeyChange processes key change events
func (p *AntiAbusePlugin) HandleKeyChange(ctx context.Context, event *proto.KeyChangeEvent) error {
	p.logger.WithFields(logrus.Fields{
		"change_type": event.ChangeType.String(),
		"fingerprint": event.Fingerprint,
		"key_size":    len(event.KeyData),
	}).Debug("Processing key change event")

	// Check for suspicious key patterns
	if p.isSuspiciousKey(event) {
		p.logger.WithField("fingerprint", event.Fingerprint).Warn("Suspicious key detected")
		// In a real implementation, this might trigger additional validation
	}

	return nil
}

// Shutdown cleans up resources
func (p *AntiAbusePlugin) Shutdown() error {
	p.logger.Info("AntiAbuse plugin shutting down")
	return nil
}

// Helper methods

func (p *AntiAbusePlugin) extractClientIP(req *proto.HTTPRequest) string {
	// Check X-Forwarded-For header first
	if xff := req.Headers["X-Forwarded-For"]; xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if realIP := req.Headers["X-Real-IP"]; realIP != "" {
		return realIP
	}

	// Fall back to remote address
	if req.RemoteAddr != "" {
		// Remove port if present
		if idx := strings.LastIndex(req.RemoteAddr, ":"); idx != -1 {
			return req.RemoteAddr[:idx]
		}
	}

	return req.RemoteAddr
}

func (p *AntiAbusePlugin) isBlocked(ip string) bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	blockedUntil, exists := p.blockedIPs[ip]
	if !exists {
		return false
	}

	// Check if block has expired
	if time.Now().After(blockedUntil) {
		// Clean up expired block
		delete(p.blockedIPs, ip)
		return false
	}

	return true
}

func (p *AntiAbusePlugin) blockIP(ip string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	blockUntil := time.Now().Add(time.Duration(p.blockDurationMinutes) * time.Minute)
	p.blockedIPs[ip] = blockUntil
}

func (p *AntiAbusePlugin) exceedsRateLimit(ip string) bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	counter, exists := p.ipRequests[ip]
	if !exists {
		return false
	}

	now := time.Now()

	// Check minute limit
	if now.Sub(counter.LastMinute) < time.Minute {
		if counter.RequestsPerMinute >= p.maxRequestsPerMinute {
			return true
		}
	}

	// Check hour limit
	if now.Sub(counter.LastHour) < time.Hour {
		if counter.RequestsPerHour >= p.maxRequestsPerHour {
			return true
		}
	}

	return false
}

func (p *AntiAbusePlugin) incrementRequests(ip string, count int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	now := time.Now()
	counter, exists := p.ipRequests[ip]

	if !exists {
		counter = &RequestCounter{
			LastMinute: now,
			LastHour:   now,
		}
		p.ipRequests[ip] = counter
	}

	// Reset counters if time windows have passed
	if now.Sub(counter.LastMinute) >= time.Minute {
		counter.RequestsPerMinute = 0
		counter.LastMinute = now
	}

	if now.Sub(counter.LastHour) >= time.Hour {
		counter.RequestsPerHour = 0
		counter.LastHour = now
	}

	// Increment counters
	counter.RequestsPerMinute += count
	counter.RequestsPerHour += count
}

func (p *AntiAbusePlugin) isSuspiciousRequest(req *proto.HTTPRequest) bool {
	userAgent := strings.ToLower(req.Headers["User-Agent"])
	path := strings.ToLower(req.Path)

	// Check user agent for suspicious patterns
	for _, suspicious := range p.suspiciousUserAgents {
		if strings.Contains(userAgent, strings.ToLower(suspicious)) {
			return true
		}
	}

	// Check path for suspicious keywords
	for _, keyword := range p.suspiciousKeywords {
		if strings.Contains(path, strings.ToLower(keyword)) {
			return true
		}
	}

	// Check query parameters for suspicious patterns
	for _, value := range req.QueryParams {
		lowerValue := strings.ToLower(value)
		for _, keyword := range p.suspiciousKeywords {
			if strings.Contains(lowerValue, strings.ToLower(keyword)) {
				return true
			}
		}
	}

	return false
}

func (p *AntiAbusePlugin) isSuspiciousKey(event *proto.KeyChangeEvent) bool {
	// Simple heuristics for suspicious keys
	// In practice, this would be much more sophisticated

	// Check for very small keys (likely test keys)
	if len(event.KeyData) < 100 {
		return true
	}

	// Check for very large keys (potential DoS)
	if len(event.KeyData) > 1024*1024 { // 1MB
		return true
	}

	return false
}

func main() {
	// Create plugin instance
	plugin := NewAntiAbusePlugin()

	// Create gRPC server
	opts := &server.Options{
		Logger:           plugin.logger,
		EnableReflection: true,
	}

	grpcServer := server.NewPluginServer(plugin, opts)

	// Run the server (blocks until shutdown)
	if err := grpcServer.Run(); err != nil {
		plugin.logger.WithError(err).Fatal("Plugin server failed")
	}
}
