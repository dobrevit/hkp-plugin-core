// Zero Trust Network Access Plugin - gRPC Implementation
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// Plugin constants
const (
	PluginName    = "zero-trust-security"
	PluginVersion = "1.0.0"
	Priority      = 40
)

// ZeroTrustPlugin implements gRPC-based Zero Trust Network Access
type ZeroTrustPlugin struct {
	proto.UnimplementedHKPPluginServer
	config            *ZeroTrustConfig
	authenticator     *ContinuousAuthenticator
	deviceProfiler    *DeviceProfiler
	riskAssessor      *RiskAssessor
	policyEngine      *AdaptivePolicyEngine
	sessionManager    *SessionManager
	auditLogger       *AuditLogger
	mu                sync.RWMutex
}

// ZeroTrustConfig holds configuration
type ZeroTrustConfig struct {
	Enabled                   bool                      `json:"enabled"`
	PolicyMode                string                    `json:"policy_mode"` // enforce, monitor, disabled
	RequireAuthentication     bool                      `json:"require_authentication"`
	SessionTimeout            string                    `json:"session_timeout"`
	ReevaluationInterval      string                    `json:"reevaluation_interval"`
	MaxRiskScore              float64                   `json:"max_risk_score"`
	DeviceFingerprintingLevel string                    `json:"device_fingerprinting_level"`
	RiskAssessment            RiskAssessmentConfig      `json:"risk_assessment"`
	NetworkSegmentation       NetworkSegmentationConfig `json:"network_segmentation"`
	AdaptivePolicies          AdaptivePolicyConfig      `json:"adaptive_policies"`
	AuditLevel                string                    `json:"audit_level"`
	AuditLogPath              string                    `json:"audit_log_path"`
	PublicPaths               []string                  `json:"public_paths"`
}

// RiskAssessmentConfig configures risk assessment
type RiskAssessmentConfig struct {
	Enabled              bool    `json:"enabled"`
	LocationRiskWeight   float64 `json:"location_risk_weight"`
	BehaviorRiskWeight   float64 `json:"behavior_risk_weight"`
	DeviceRiskWeight     float64 `json:"device_risk_weight"`
	TimeRiskWeight       float64 `json:"time_risk_weight"`
	VelocityThreshold    float64 `json:"velocity_threshold"`
	AnomalyThreshold     float64 `json:"anomaly_threshold"`
}

// NetworkSegmentationConfig defines micro-segmentation rules
type NetworkSegmentationConfig struct {
	Enabled         bool                     `json:"enabled"`
	DefaultSegment  string                   `json:"default_segment"`
	SegmentPolicies map[string]SegmentPolicy `json:"segment_policies"`
}

// SegmentPolicy defines access rules for a network segment
type SegmentPolicy struct {
	Name            string   `json:"name"`
	AllowedServices []string `json:"allowed_services"`
	AllowedMethods  []string `json:"allowed_methods"`
	AllowedPaths    []string `json:"allowed_paths"`
	RiskThreshold   float64  `json:"risk_threshold"`
}

// AdaptivePolicyConfig configures adaptive policies
type AdaptivePolicyConfig struct {
	Enabled              bool   `json:"enabled"`
	PolicyUpdateInterval string `json:"policy_update_interval"`
	LearningPeriod       string `json:"learning_period"`
	AutoAdjustThresholds bool   `json:"auto_adjust_thresholds"`
}

// Session represents an authenticated session
type Session struct {
	ID                string
	UserID            string
	DeviceID          string
	CreatedAt         time.Time
	LastActivity      time.Time
	RiskScore         float64
	TrustLevel        string
	Authenticated     bool
	DeviceFingerprint map[string]string
	Location          *Location
	VerificationCount int
}

// Location represents a geographic location
type Location struct {
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	ISP       string  `json:"isp"`
}

// NewZeroTrustPlugin creates a new zero trust plugin
func NewZeroTrustPlugin() *ZeroTrustPlugin {
	config := &ZeroTrustConfig{
		Enabled:                   true,
		PolicyMode:                "enforce",
		RequireAuthentication:     true,
		SessionTimeout:            "30m",
		ReevaluationInterval:      "5m",
		MaxRiskScore:              0.7,
		DeviceFingerprintingLevel: "standard",
		AuditLevel:                "detailed",
		AuditLogPath:              "./logs",
		PublicPaths: []string{
			"/pks/lookup",
			"/pks/stats",
			"/health",
			"/metrics",
		},
		RiskAssessment: RiskAssessmentConfig{
			Enabled:              true,
			LocationRiskWeight:   0.3,
			BehaviorRiskWeight:   0.4,
			DeviceRiskWeight:     0.2,
			TimeRiskWeight:       0.1,
			VelocityThreshold:    1000.0, // km/h
			AnomalyThreshold:     0.8,
		},
		NetworkSegmentation: NetworkSegmentationConfig{
			Enabled:        true,
			DefaultSegment: "public",
			SegmentPolicies: map[string]SegmentPolicy{
				"public": {
					Name:            "Public Access",
					AllowedServices: []string{"hkp", "health"},
					AllowedMethods:  []string{"GET"},
					AllowedPaths:    []string{"/pks/lookup", "/health"},
					RiskThreshold:   0.3,
				},
				"authenticated": {
					Name:            "Authenticated Access",
					AllowedServices: []string{"hkp", "admin"},
					AllowedMethods:  []string{"GET", "POST"},
					AllowedPaths:    []string{"/pks/add", "/pks/lookup"},
					RiskThreshold:   0.6,
				},
			},
		},
		AdaptivePolicies: AdaptivePolicyConfig{
			Enabled:              true,
			PolicyUpdateInterval: "30m",
			LearningPeriod:       "7d",
			AutoAdjustThresholds: true,
		},
	}

	return &ZeroTrustPlugin{
		config:         config,
		authenticator:  NewContinuousAuthenticator(config),
		deviceProfiler: NewDeviceProfiler(config.DeviceFingerprintingLevel),
		riskAssessor:   NewRiskAssessor(config.RiskAssessment),
		policyEngine:   NewAdaptivePolicyEngine(config.AdaptivePolicies),
		sessionManager: NewSessionManager(config),
		auditLogger:    NewAuditLogger(config.AuditLevel, config.AuditLogPath),
	}
}

// Initialize implements the gRPC HKPPlugin interface
func (p *ZeroTrustPlugin) Initialize(ctx context.Context, req *proto.InitRequest) (*proto.InitResponse, error) {
	// Parse configuration
	if req.ConfigJson != "" {
		if err := json.Unmarshal([]byte(req.ConfigJson), p.config); err != nil {
			return &proto.InitResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to parse config: %v", err),
			}, nil
		}
	}

	// Initialize components with new config
	p.authenticator = NewContinuousAuthenticator(p.config)
	p.deviceProfiler = NewDeviceProfiler(p.config.DeviceFingerprintingLevel)
	p.riskAssessor = NewRiskAssessor(p.config.RiskAssessment)
	p.policyEngine = NewAdaptivePolicyEngine(p.config.AdaptivePolicies)
	p.sessionManager = NewSessionManager(p.config)
	p.auditLogger = NewAuditLogger(p.config.AuditLevel, p.config.AuditLogPath)

	// Initialize audit logger
	if err := p.auditLogger.Initialize(); err != nil {
		return &proto.InitResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to initialize audit logger: %v", err),
		}, nil
	}

	// Start background tasks
	go p.runContinuousVerification(ctx)
	go p.runSessionCleanup(ctx)
	if p.config.AdaptivePolicies.Enabled {
		go p.runPolicyUpdates(ctx)
	}

	log.Printf("Zero Trust plugin initialized - enabled: %t, policy_mode: %s, max_risk: %.2f",
		p.config.Enabled, p.config.PolicyMode, p.config.MaxRiskScore)

	return &proto.InitResponse{
		Success: true,
		Info: &proto.PluginInfo{
			Name:         PluginName,
			Version:      PluginVersion,
			Description:  "Zero-Trust Network Access with continuous authentication and micro-segmentation",
			Capabilities: []string{"authentication", "zero_trust", "micro_segmentation", "risk_assessment"},
		},
	}, nil
}

// HandleHTTPRequest implements HTTP request processing with zero trust
func (p *ZeroTrustPlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
	// Skip if not enabled
	if !p.config.Enabled {
		return &proto.HTTPResponse{
			StatusCode:    200,
			ContinueChain: true,
		}, nil
	}

	// Extract client information
	clientIP := p.extractClientIP(req)
	
	// Check if path is public
	if p.isPublicPath(req.Path) {
		return &proto.HTTPResponse{
			StatusCode: 200,
			Headers: map[string]string{
				"X-ZeroTrust-Plugin": fmt.Sprintf("%s/%s", PluginName, PluginVersion),
				"X-ZeroTrust-Level":  "public",
			},
			ContinueChain: true,
		}, nil
	}

	// Extract session information
	sessionID := p.extractSessionID(req)
	session := p.sessionManager.GetSession(sessionID)

	// Check authentication requirement
	if p.config.RequireAuthentication && (session == nil || !session.Authenticated) {
		return p.requireAuthentication()
	}

	// Perform risk assessment
	riskScore := p.riskAssessor.AssessRisk(clientIP, req, session)
	
	// Update session risk
	if session != nil {
		session.RiskScore = riskScore
		session.LastActivity = time.Now()
		p.sessionManager.UpdateSession(session)
	}

	// Check risk threshold
	if riskScore > p.config.MaxRiskScore {
		p.auditLogger.LogHighRiskAccess(clientIP, riskScore, req.Path)
		
		if p.config.PolicyMode == "enforce" {
			return p.blockHighRiskRequest(riskScore)
		}
	}

	// Apply network segmentation
	if p.config.NetworkSegmentation.Enabled {
		if allowed, reason := p.checkSegmentPolicy(session, req); !allowed {
			p.auditLogger.LogSegmentationBlock(clientIP, req.Path, reason)
			
			if p.config.PolicyMode == "enforce" {
				return p.blockSegmentationViolation(reason)
			}
		}
	}

	// Log successful access
	p.auditLogger.LogAccess(clientIP, req.Path, riskScore, session)

	// Add zero trust headers
	headers := map[string]string{
		"X-ZeroTrust-Plugin":    fmt.Sprintf("%s/%s", PluginName, PluginVersion),
		"X-ZeroTrust-Level":     "authenticated",
		"X-ZeroTrust-RiskScore": fmt.Sprintf("%.3f", riskScore),
		"X-ZeroTrust-Mode":      p.config.PolicyMode,
	}

	if session != nil {
		headers["X-ZeroTrust-Session"] = session.ID
		headers["X-ZeroTrust-Trust"] = session.TrustLevel
	}

	return &proto.HTTPResponse{
		StatusCode:    200,
		Headers:       headers,
		ContinueChain: true,
	}, nil
}

// CheckRateLimit implements zero trust rate limiting
func (p *ZeroTrustPlugin) CheckRateLimit(ctx context.Context, req *proto.RateLimitCheck) (*proto.RateLimitResponse, error) {
	if !p.config.Enabled {
		return &proto.RateLimitResponse{Allowed: true}, nil
	}

	clientIP := req.Identifier

	// Perform quick risk assessment
	riskScore := p.riskAssessor.QuickAssess(clientIP)

	// Allow based on risk score
	if riskScore > p.config.MaxRiskScore {
		return &proto.RateLimitResponse{
			Allowed: false,
			Reason:  fmt.Sprintf("Zero trust risk score too high: %.3f", riskScore),
		}, nil
	}

	return &proto.RateLimitResponse{Allowed: true}, nil
}

// Helper methods

func (p *ZeroTrustPlugin) extractClientIP(req *proto.HTTPRequest) string {
	// Check X-Forwarded-For
	if xForwardedFor, exists := req.Headers["X-Forwarded-For"]; exists {
		return xForwardedFor
	}

	// Check X-Real-IP
	if xRealIP, exists := req.Headers["X-Real-IP"]; exists {
		return xRealIP
	}

	return req.RemoteAddr
}

func (p *ZeroTrustPlugin) extractSessionID(req *proto.HTTPRequest) string {
	// Try Authorization header first
	if auth, exists := req.Headers["Authorization"]; exists {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}

	// Try session cookie
	if cookie, exists := req.Headers["Cookie"]; exists {
		// Simple cookie parsing for session ID
		parts := strings.Split(cookie, ";")
		for _, part := range parts {
			if strings.Contains(part, "session_id=") {
				return strings.TrimSpace(strings.Split(part, "=")[1])
			}
		}
	}

	return ""
}

func (p *ZeroTrustPlugin) isPublicPath(path string) bool {
	for _, publicPath := range p.config.PublicPaths {
		if strings.HasPrefix(path, publicPath) {
			return true
		}
	}
	return false
}

func (p *ZeroTrustPlugin) requireAuthentication() (*proto.HTTPResponse, error) {
	return &proto.HTTPResponse{
		StatusCode: 401,
		Body:       []byte("Authentication required"),
		Headers: map[string]string{
			"X-ZeroTrust-Plugin": fmt.Sprintf("%s/%s", PluginName, PluginVersion),
			"X-ZeroTrust-Error":  "authentication_required",
			"WWW-Authenticate":   "Bearer realm=\"Zero Trust\"",
		},
		ContinueChain: false,
	}, nil
}

func (p *ZeroTrustPlugin) blockHighRiskRequest(riskScore float64) (*proto.HTTPResponse, error) {
	return &proto.HTTPResponse{
		StatusCode: 403,
		Body:       []byte("Access denied: High risk score detected"),
		Headers: map[string]string{
			"X-ZeroTrust-Plugin":    fmt.Sprintf("%s/%s", PluginName, PluginVersion),
			"X-ZeroTrust-Error":     "high_risk",
			"X-ZeroTrust-RiskScore": fmt.Sprintf("%.3f", riskScore),
		},
		ContinueChain: false,
	}, nil
}

func (p *ZeroTrustPlugin) blockSegmentationViolation(reason string) (*proto.HTTPResponse, error) {
	return &proto.HTTPResponse{
		StatusCode: 403,
		Body:       []byte("Access denied: Network segmentation policy violation"),
		Headers: map[string]string{
			"X-ZeroTrust-Plugin": fmt.Sprintf("%s/%s", PluginName, PluginVersion),
			"X-ZeroTrust-Error":  "segmentation_violation",
			"X-ZeroTrust-Reason": reason,
		},
		ContinueChain: false,
	}, nil
}

func (p *ZeroTrustPlugin) checkSegmentPolicy(session *Session, req *proto.HTTPRequest) (bool, string) {
	segment := "public"
	if session != nil && session.Authenticated {
		segment = "authenticated"
	}

	policy, exists := p.config.NetworkSegmentation.SegmentPolicies[segment]
	if !exists {
		return false, "no_policy_found"
	}

	// Check if path is allowed
	pathAllowed := false
	for _, allowedPath := range policy.AllowedPaths {
		if strings.HasPrefix(req.Path, allowedPath) {
			pathAllowed = true
			break
		}
	}

	if !pathAllowed {
		return false, "path_not_allowed"
	}

	// Check if method is allowed
	methodAllowed := false
	for _, allowedMethod := range policy.AllowedMethods {
		if req.Method == allowedMethod {
			methodAllowed = true
			break
		}
	}

	if !methodAllowed {
		return false, "method_not_allowed"
	}

	// Check risk threshold
	if session != nil && session.RiskScore > policy.RiskThreshold {
		return false, "risk_threshold_exceeded"
	}

	return true, ""
}

// Background tasks

func (p *ZeroTrustPlugin) runContinuousVerification(ctx context.Context) {
	interval, _ := time.ParseDuration(p.config.ReevaluationInterval)
	if interval == 0 {
		interval = 5 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.performContinuousVerification()
		case <-ctx.Done():
			return
		}
	}
}

func (p *ZeroTrustPlugin) performContinuousVerification() {
	sessions := p.sessionManager.GetActiveSessions()
	
	for _, session := range sessions {
		// Re-assess risk for active sessions
		riskScore := p.riskAssessor.ReassessSession(session)
		session.RiskScore = riskScore

		// Revoke sessions with high risk
		if riskScore > p.config.MaxRiskScore {
			p.sessionManager.RevokeSession(session.ID)
			p.auditLogger.LogSessionRevoked(session.ID, riskScore)
		}
	}
}

func (p *ZeroTrustPlugin) runSessionCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.sessionManager.CleanupExpiredSessions()
		case <-ctx.Done():
			return
		}
	}
}

func (p *ZeroTrustPlugin) runPolicyUpdates(ctx context.Context) {
	interval, _ := time.ParseDuration(p.config.AdaptivePolicies.PolicyUpdateInterval)
	if interval == 0 {
		interval = 30 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.policyEngine.UpdatePolicies()
		case <-ctx.Done():
			return
		}
	}
}

// Required gRPC methods

func (p *ZeroTrustPlugin) GetInfo(ctx context.Context, req *proto.Empty) (*proto.PluginInfo, error) {
	return &proto.PluginInfo{
		Name:         PluginName,
		Version:      PluginVersion,
		Description:  "Zero-Trust Network Access with continuous authentication and micro-segmentation",
		Capabilities: []string{"authentication", "zero_trust", "micro_segmentation", "risk_assessment"},
		Metadata: map[string]string{
			"priority":               fmt.Sprintf("%d", Priority),
			"policy_mode":            p.config.PolicyMode,
			"max_risk_score":         fmt.Sprintf("%.2f", p.config.MaxRiskScore),
			"require_authentication": fmt.Sprintf("%t", p.config.RequireAuthentication),
			"segmentation_enabled":   fmt.Sprintf("%t", p.config.NetworkSegmentation.Enabled),
		},
	}, nil
}

func (p *ZeroTrustPlugin) HandleKeyChange(ctx context.Context, req *proto.KeyChangeEvent) (*proto.Event, error) {
	// Zero trust plugin monitors key changes for audit purposes
	clientIP := "unknown"
	
	// Determine operation type from the event
	operation := "unknown"
	if req.Fingerprint != "" {
		operation = "key_change"
	}
	
	// Log key change for audit
	p.auditLogger.LogKeyChange(req.Fingerprint, clientIP, operation)

	eventData := map[string]string{
		"fingerprint": req.Fingerprint,
		"operation":   operation,
		"audited":     "true",
	}

	dataBytes, _ := json.Marshal(eventData)

	return &proto.Event{
		Type:      "zerotrust.key.audited",
		Source:    PluginName,
		Timestamp: time.Now().Unix(),
		Data:      dataBytes,
	}, nil
}

func (p *ZeroTrustPlugin) SubscribeEvents(req *proto.EventFilter, stream proto.HKPPlugin_SubscribeEventsServer) error {
	<-stream.Context().Done()
	return nil
}

func (p *ZeroTrustPlugin) PublishEvent(ctx context.Context, req *proto.Event) (*proto.Empty, error) {
	// Process security events
	if req.Type == "security.threat.detected" || req.Type == "ratelimit.violation" {
		var data map[string]interface{}
		if err := json.Unmarshal(req.Data, &data); err == nil {
			if clientIP, ok := data["client_ip"].(string); ok {
				// Increase risk assessment for this IP
				p.riskAssessor.RecordSecurityEvent(clientIP, req.Type)
				
				// Potentially revoke sessions
				sessions := p.sessionManager.GetSessionsByIP(clientIP)
				for _, session := range sessions {
					session.RiskScore += 0.2 // Increase risk
					if session.RiskScore > p.config.MaxRiskScore {
						p.sessionManager.RevokeSession(session.ID)
					}
				}
			}
		}
	}
	return &proto.Empty{}, nil
}

func (p *ZeroTrustPlugin) QueryStorage(ctx context.Context, req *proto.StorageQuery) (*proto.StorageResponse, error) {
	return &proto.StorageResponse{
		Success: false,
		Error:   "Storage queries not supported by zero trust plugin",
	}, nil
}

func (p *ZeroTrustPlugin) ReportThreat(ctx context.Context, req *proto.ThreatInfo) (*proto.Empty, error) {
	// Use threat reports to update risk assessments
	if clientIP, exists := req.Indicators["client_ip"]; exists {
		p.riskAssessor.RecordThreatReport(clientIP, req.Type, req.Description)
		
		// Revoke sessions for this IP if threat is severe
		if req.Type == "malware" || req.Type == "botnet" {
			sessions := p.sessionManager.GetSessionsByIP(clientIP)
			for _, session := range sessions {
				p.sessionManager.RevokeSession(session.ID)
				p.auditLogger.LogSessionRevoked(session.ID, 1.0) // Max risk
			}
		}
	}
	return &proto.Empty{}, nil
}

func (p *ZeroTrustPlugin) HealthCheck(ctx context.Context, req *proto.Empty) (*proto.HealthStatus, error) {
	status := proto.HealthStatus_HEALTHY
	message := "Zero trust plugin is healthy"

	// Check session manager
	activeSessionCount := p.sessionManager.GetActiveSessionCount()
	
	// Check components
	if !p.auditLogger.IsHealthy() {
		status = proto.HealthStatus_DEGRADED
		message = "Audit logger is not healthy"
	}

	return &proto.HealthStatus{
		Status:    status,
		Message:   message,
		Timestamp: time.Now().Unix(),
		Details: map[string]string{
			"enabled":                fmt.Sprintf("%t", p.config.Enabled),
			"policy_mode":            p.config.PolicyMode,
			"active_sessions":        fmt.Sprintf("%d", activeSessionCount),
			"max_risk_score":         fmt.Sprintf("%.2f", p.config.MaxRiskScore),
			"segmentation_enabled":   fmt.Sprintf("%t", p.config.NetworkSegmentation.Enabled),
			"adaptive_policies":      fmt.Sprintf("%t", p.config.AdaptivePolicies.Enabled),
			"audit_level":            p.config.AuditLevel,
		},
	}, nil
}

func (p *ZeroTrustPlugin) Shutdown(ctx context.Context, req *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	log.Printf("Zero trust plugin shutting down...")

	// Save session state
	if err := p.sessionManager.SaveState(); err != nil {
		log.Printf("Failed to save session state: %v", err)
	}

	// Final audit log
	p.auditLogger.LogShutdown()

	return &proto.ShutdownResponse{Success: true}, nil
}

func main() {
	// Get gRPC address from environment
	address := os.Getenv("PLUGIN_GRPC_ADDRESS")
	if address == "" {
		address = "localhost:50007"
	}

	// Create listener
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create and register plugin
	plugin := NewZeroTrustPlugin()
	proto.RegisterHKPPluginServer(grpcServer, plugin)

	// Register health service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	log.Printf("Zero Trust gRPC plugin starting on %s", address)

	// Start serving
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}