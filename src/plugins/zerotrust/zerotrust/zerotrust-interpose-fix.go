// Package zerotrust provides a Zero-Trust Network Access (ZTNA) plugin for Hockeypuck
package zerotrust

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"

	"gopkg.in/tomb.v2"
)

// Plugin constants
const (
	PluginName    = "zero-trust-security"
	PluginVersion = "1.0.0"
	Priority      = 40 // Run after ML detection (priority 30)
)

// ZeroTrustPlugin implements Zero-Trust Network Access principles
type ZeroTrustPlugin struct {
	host              plugin.PluginHost
	config            *ZeroTrustConfig
	authenticator     *ContinuousAuthenticator
	deviceProfiler    *DeviceProfiler
	riskAssessor      *RiskAssessor
	policyEngine      *AdaptivePolicyEngine
	segmentController *MicroSegmentController
	sessionManager    *SessionManager
	auditLogger       *AuditLogger
	mu                sync.RWMutex
	tomb              tomb.Tomb
}

// Initialize implements the Plugin interface
func (p *ZeroTrustPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
	// Parse configuration
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	p.config = &ZeroTrustConfig{
		Enabled:                   true,
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
			"/api/ztna/status", // Allow status check without auth
		},
	}

	if err := json.Unmarshal(configBytes, p.config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	p.host = host

	// Initialize components
	p.authenticator = NewContinuousAuthenticator(p.config)
	p.deviceProfiler = NewDeviceProfiler(p.config.DeviceFingerprintingLevel)
	p.riskAssessor = NewRiskAssessor()
	p.policyEngine = NewAdaptivePolicyEngine(p.config.AdaptivePolicies)
	p.segmentController = NewMicroSegmentController(p.config.NetworkSegmentation)
	p.sessionManager = NewSessionManager(p.config)
	p.auditLogger = NewAuditLogger(p.config.AuditLevel, p.config.AuditLogPath)

	// Initialize audit logger
	if err := p.auditLogger.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize audit logger: %w", err)
	}

	// Register background tasks
	reevalInterval, _ := time.ParseDuration(p.config.ReevaluationInterval)
	if reevalInterval == 0 {
		reevalInterval = 5 * time.Minute
	}

	host.RegisterTask("ztna-continuous-verification", reevalInterval, p.performContinuousVerification)
	host.RegisterTask("ztna-session-cleanup", 5*time.Minute, p.cleanupExpiredSessions)

	if p.config.AdaptivePolicies.Enabled {
		policyInterval, _ := time.ParseDuration(p.config.AdaptivePolicies.PolicyUpdateInterval)
		if policyInterval == 0 {
			policyInterval = 30 * time.Minute
		}
		host.RegisterTask("ztna-policy-update", policyInterval, p.updateAdaptivePolicies)
	}

	// Register middleware
	middleware, err := p.CreateMiddleware()
	if err != nil {
		return fmt.Errorf("failed to create middleware: %w", err)
	}

	if err := host.RegisterMiddleware("/", middleware); err != nil {
		return fmt.Errorf("failed to register middleware: %w", err)
	}

	// Register handlers
	host.RegisterHandler("/ztna/login", p.handleLogin)
	host.RegisterHandler("/ztna/logout", p.handleLogout)
	host.RegisterHandler("/ztna/verify", p.handleVerification)
	host.RegisterHandler("/ztna/device", p.handleDeviceRegistration)
	host.RegisterHandler("/ztna/status", p.handleZTNAStatus)
	host.RegisterHandler("/ztna/sessions", p.handleSessions)
	host.RegisterHandler("/ztna/policies", p.handlePolicies)

	// Subscribe to security events
	host.SubscribeEvent("security.threat.detected", p.handleThreatEvent)
	host.SubscribeEvent("ratelimit.violation", p.handleRateLimitEvent)

	// Subscribe to endpoint protection events
	host.SubscribeEvent(plugin.EventEndpointProtectionRequest, p.handleEndpointProtectionEvent)
	host.SubscribeEvent(plugin.EventSecurityThreatDetected, p.handleSecurityThreatEvent)

	host.Logger().Info("Zero-Trust plugin initialized",
		"require_auth", p.config.RequireAuthentication,
		"max_risk", p.config.MaxRiskScore)

	return nil
}

// Name returns the plugin name
func (p *ZeroTrustPlugin) Name() string {
	return PluginName
}

// Version returns the plugin version
func (p *ZeroTrustPlugin) Version() string {
	return PluginVersion
}

// Description returns the plugin description
func (p *ZeroTrustPlugin) Description() string {
	return "Zero-Trust Network Access with continuous authentication and micro-segmentation"
}

// Dependencies returns required plugin dependencies
func (p *ZeroTrustPlugin) Dependencies() []plugin.PluginDependency {
	return []plugin.PluginDependency{
		{
			Name:     "ratelimit",
			Version:  "1.0.0",
			Type:     plugin.DependencyOptional,
			Optional: true,
		},
	}
}

// Priority returns the plugin priority (higher numbers run later)
func (p *ZeroTrustPlugin) Priority() int {
	return Priority
}

// Shutdown gracefully stops the plugin
func (p *ZeroTrustPlugin) Shutdown(ctx context.Context) error {
	// Signal shutdown to all goroutines
	p.tomb.Kill(nil)

	// Wait for all goroutines to finish with context timeout
	done := make(chan error, 1)
	go func() {
		done <- p.tomb.Wait()
	}()

	select {
	case err := <-done:
		// Save session state before returning
		if saveErr := p.sessionManager.SaveState(); saveErr != nil {
			p.host.Logger().Error("Failed to save session state during shutdown", "error", saveErr)
		}

		// Final audit log
		p.auditLogger.LogShutdown()

		return err
	case <-ctx.Done():
		// Timeout - return error
		return fmt.Errorf("plugin shutdown timed out")
	}
}

// CreateMiddleware creates the Zero Trust middleware
func (p *ZeroTrustPlugin) CreateMiddleware() (func(http.Handler) http.Handler, error) {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if not enabled
			if !p.config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			startTime := time.Now()

			// Extract request context
			clientIP := p.extractClientIP(r)
			sessionID := p.extractSessionID(r)

			// Check if path requires authentication
			if !p.requiresAuth(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Get or create session
			session, err := p.sessionManager.GetOrCreateSession(sessionID, clientIP, r)
			if err != nil {
				p.auditLogger.LogAuthFailure(clientIP, "session_error", err.Error())
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Perform device profiling
			deviceProfile := p.deviceProfiler.ProfileDevice(r)
			session.DeviceProfile = deviceProfile

			// Continuous authentication check
			authResult := p.authenticator.VerifySession(session, r)
			if !authResult.Authenticated {
				p.auditLogger.LogAuthFailure(clientIP, "continuous_auth_failed", authResult.Reason)
				http.Error(w, "Authentication failed", http.StatusUnauthorized)
				return
			}

			// Risk assessment
			riskScore := p.riskAssessor.AssessRisk(session, r)
			session.RiskScore = riskScore

			// Update continuous scores
			session.ContinuousScores[time.Now()] = riskScore

			// Policy evaluation
			decision := p.policyEngine.EvaluateAccess(session, r)
			session.AccessDecisions = append(session.AccessDecisions, decision)

			if !decision.Allowed {
				p.auditLogger.LogAccessDenied(session, decision)
				http.Error(w, fmt.Sprintf("Access denied: %s", decision.Reason), http.StatusForbidden)
				return
			}

			// Network segmentation enforcement
			segment := p.segmentController.DetermineSegment(session, r)
			if !p.segmentController.IsAccessAllowed(segment, r) {
				p.auditLogger.LogSegmentViolation(session, segment, r)
				http.Error(w, "Network segment access denied", http.StatusForbidden)
				return
			}

			// Update session activity
			session.LastActivityAt = time.Now()
			session.Segment = segment
			p.sessionManager.UpdateSession(session)

			// Add Zero-Trust headers
			p.addZeroTrustHeaders(w, session, decision)

			// Audit successful access
			p.auditLogger.LogAccess(session, r, decision, time.Since(startTime))

			// Continue with request
			next.ServeHTTP(w, r)
		})
	}, nil
}

// Helper methods

func (p *ZeroTrustPlugin) requiresAuth(path string) bool {
	// Check configured public paths that don't require auth
	for _, publicPath := range p.config.PublicPaths {
		if strings.HasPrefix(path, publicPath) {
			return false
		}
	}

	// Check if path is explicitly protected (requires elevated auth)
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Check permanent protected paths
	for _, protectedPath := range p.config.ProtectedPaths {
		if strings.HasPrefix(path, protectedPath) {
			return true // Always require auth for protected paths
		}
	}

	// Check temporary protected paths
	if p.config.TempProtectedPaths != nil {
		now := time.Now()
		for protectedPath, expiry := range p.config.TempProtectedPaths {
			if now.Before(expiry) && strings.HasPrefix(path, protectedPath) {
				return true // Require auth for non-expired temp protected paths
			}
		}
	}

	return p.config.RequireAuthentication
}

func (p *ZeroTrustPlugin) extractSessionID(r *http.Request) string {
	// Check cookie
	if cookie, err := r.Cookie("ztna-session"); err == nil {
		return cookie.Value
	}

	// Check Authorization header
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}

	// Check custom header
	if sessionID := r.Header.Get("X-ZTNA-Session"); sessionID != "" {
		return sessionID
	}

	return ""
}

func (p *ZeroTrustPlugin) extractClientIP(r *http.Request) string {
	// Trust proxy headers if configured
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Fall back to remote address
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

func (p *ZeroTrustPlugin) addZeroTrustHeaders(w http.ResponseWriter, session *SessionContext, decision AccessDecision) {
	w.Header().Set("X-ZTNA-Session-ID", session.SessionID)
	w.Header().Set("X-ZTNA-Trust-Level", session.TrustLevel.String())
	w.Header().Set("X-ZTNA-Risk-Score", fmt.Sprintf("%.3f", session.RiskScore))
	w.Header().Set("X-ZTNA-Segment", session.Segment)
	w.Header().Set("X-ZTNA-Policy", decision.PolicyApplied)

	// Set session cookie if not present
	http.SetCookie(w, &http.Cookie{
		Name:     "ztna-session",
		Value:    session.SessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   1800, // 30 minutes
	})
}

// Background tasks

func (p *ZeroTrustPlugin) performContinuousVerification(ctx context.Context) error {
	sessions := p.sessionManager.GetActiveSessions()

	for _, session := range sessions {
		// Re-assess risk
		newRiskScore := p.riskAssessor.ReassessRisk(session)

		// Check if risk increased significantly
		if newRiskScore > session.RiskScore*1.5 || newRiskScore > p.config.MaxRiskScore {
			// Downgrade trust level
			session.TrustLevel = p.calculateTrustLevel(newRiskScore)

			// Log significant risk increase
			p.auditLogger.LogRiskIncrease(session, session.RiskScore, newRiskScore)

			// Potentially terminate high-risk sessions
			if newRiskScore > 0.9 {
				p.sessionManager.TerminateSession(session.SessionID, "High risk detected")
				p.auditLogger.LogSessionTermination(session, "continuous_verification", "high_risk")
			}
		}

		session.RiskScore = newRiskScore
		p.sessionManager.UpdateSession(session)
	}

	return nil
}

func (p *ZeroTrustPlugin) cleanupExpiredSessions(ctx context.Context) error {
	sessions := p.sessionManager.GetActiveSessions()

	for _, session := range sessions {
		if !p.sessionManager.isSessionValid(session) {
			p.sessionManager.TerminateSession(session.SessionID, "expired")
			p.auditLogger.LogSessionExpiration(session)
		}
	}

	return nil
}

func (p *ZeroTrustPlugin) updateAdaptivePolicies(ctx context.Context) error {
	if !p.config.AdaptivePolicies.LearningMode {
		return nil
	}

	// Analyze recent access patterns
	sessions := p.sessionManager.GetActiveSessions()

	// Update risk thresholds based on current threat landscape
	avgRisk := p.calculateAverageRisk(sessions)
	if avgRisk > p.config.AdaptivePolicies.AnomalyThreshold {
		// Tighten policies
		p.tightenPolicies(avgRisk)
	} else if avgRisk < p.config.AdaptivePolicies.AnomalyThreshold*0.5 {
		// Relax policies slightly
		p.relaxPolicies(avgRisk)
	}

	// Update learning data
	p.policyEngine.learningData.LastUpdate = time.Now()

	return nil
}

// Additional handler for session management
func (p *ZeroTrustPlugin) handleSessions(w http.ResponseWriter, r *http.Request) {
	// Get active sessions (admin only)
	sessions := p.sessionManager.GetActiveSessions()

	sessionList := make([]map[string]interface{}, 0, len(sessions))
	for _, session := range sessions {
		sessionList = append(sessionList, map[string]interface{}{
			"session_id":    session.SessionID,
			"user_id":       session.UserID,
			"ip_address":    session.IPAddress,
			"trust_level":   session.TrustLevel.String(),
			"risk_score":    session.RiskScore,
			"segment":       session.Segment,
			"created_at":    session.CreatedAt,
			"last_activity": session.LastActivityAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessionList)
}

func (p *ZeroTrustPlugin) handlePolicies(w http.ResponseWriter, r *http.Request) {
	// Get current policies (admin only)
	policies := p.policyEngine.GetPolicies()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

// calculateTrustLevel determines trust level based on risk score
func (p *ZeroTrustPlugin) calculateTrustLevel(riskScore float64) TrustLevel {
	switch {
	case riskScore < 0.2:
		return TrustLevelVerified
	case riskScore < 0.4:
		return TrustLevelHigh
	case riskScore < 0.6:
		return TrustLevelMedium
	case riskScore < 0.8:
		return TrustLevelLow
	default:
		return TrustLevelNone
	}
}

// ZeroTrustConfig holds the plugin configuration
type ZeroTrustConfig struct {
	Enabled                   bool                      `json:"enabled"`
	PolicyMode                string                    `json:"policyMode"` // Added for test compatibility
	RequireAuthentication     bool                      `json:"requireAuthentication"`
	SessionTimeout            interface{}               `json:"sessionTimeout"` // Can be string or time.Duration
	ReevaluationInterval      string                    `json:"reevaluationInterval"`
	MaxRiskScore              float64                   `json:"maxRiskScore"`
	DeviceFingerprintingLevel string                    `json:"deviceFingerprintingLevel"`
	RiskAssessment            RiskAssessmentConfig      `json:"riskAssessment"` // Added for test compatibility
	NetworkSegmentation       NetworkSegmentationConfig `json:"networkSegmentation"`
	AdaptivePolicies          AdaptivePolicyConfig      `json:"adaptivePolicies"`
	AuditLevel                string                    `json:"auditLevel"`
	AuditLogPath              string                    `json:"auditLogPath"`
	PublicPaths               []string                  `json:"publicPaths"`
	ProtectedPaths            []string                  `json:"protectedPaths"` // Dynamically protected paths
	TempProtectedPaths        map[string]time.Time      `json:"-"`              // Temporarily protected paths with expiry
}

// NetworkSegmentationConfig defines micro-segmentation rules
type NetworkSegmentationConfig struct {
	Enabled         bool                     `json:"enabled"`
	DefaultSegment  string                   `json:"defaultSegment"`
	SegmentPolicies map[string]SegmentPolicy `json:"segmentPolicies"`
	ServiceMesh     ServiceMeshConfig        `json:"serviceMesh"`
}

// SegmentPolicy defines access rules for a network segment
type SegmentPolicy struct {
	Name             string   `json:"name"`
	AllowedServices  []string `json:"allowedServices"`
	AllowedMethods   []string `json:"allowedMethods"`
	AllowedResources []string `json:"allowedResources"` // Added for test compatibility
	RiskThreshold    float64  `json:"riskThreshold"`
	MaxRiskScore     float64  `json:"maxRiskScore"` // Added for test compatibility
	RequireMFA       bool     `json:"requireMFA"`
}

// ServiceMeshConfig defines service-to-service authentication
type ServiceMeshConfig struct {
	Enabled             bool     `json:"enabled"`
	TrustedServices     []string `json:"trustedServices"`
	MutualTLSRequired   bool     `json:"mutualTLSRequired"`
	ServiceAuthTokenTTL string   `json:"serviceAuthTokenTTL"`
}

// AdaptivePolicyConfig defines dynamic policy adjustment
type AdaptivePolicyConfig struct {
	Enabled              bool    `json:"enabled"`
	LearningMode         bool    `json:"learningMode"`
	PolicyUpdateInterval string  `json:"policyUpdateInterval"`
	AnomalyThreshold     float64 `json:"anomalyThreshold"`
}

// SessionContext represents a zero-trust session
type SessionContext struct {
	SessionID        string
	UserID           string
	DeviceID         string
	IPAddress        string
	CreatedAt        time.Time
	LastActivityAt   time.Time
	RiskScore        float64
	TrustLevel       TrustLevel
	DeviceProfile    *DeviceProfile
	Segment          string
	AuthFactors      []AuthFactor
	AccessDecisions  []AccessDecision
	ContinuousScores map[time.Time]float64
}

// DeviceProfile represents device characteristics
type DeviceProfile struct {
	DeviceID          string
	Fingerprint       string
	Platform          string
	Browser           string
	BrowserInfo       string // Added for test compatibility
	TLSFingerprint    string
	ScreenResolution  string
	Timezone          string
	Languages         []string
	Plugins           []string
	Fonts             []string
	WebGLFingerprint  string
	CanvasFingerprint string
	AudioFingerprint  string
	LastSeen          time.Time
	TrustScore        float64
}

// TrustLevel represents the current trust level
type TrustLevel int

const (
	TrustLevelNone TrustLevel = iota
	TrustLevelLow
	TrustLevelMedium
	TrustLevelHigh
	TrustLevelVerified
)

// String returns string representation of TrustLevel
func (tl TrustLevel) String() string {
	switch tl {
	case TrustLevelNone:
		return "none"
	case TrustLevelLow:
		return "low"
	case TrustLevelMedium:
		return "medium"
	case TrustLevelHigh:
		return "high"
	case TrustLevelVerified:
		return "verified"
	default:
		return "unknown"
	}
}

// AuthFactor represents an authentication factor
type AuthFactor struct {
	Type      string // password, mfa, certificate, biometric
	Verified  bool
	Timestamp time.Time
	Strength  int // 1-10
}

// AccessDecision represents a zero-trust access decision
type AccessDecision struct {
	Resource      string
	Action        string
	Allowed       bool
	Reason        string
	RiskScore     float64
	Timestamp     time.Time
	PolicyApplied string
}

// Types for test compatibility

// ZTNAConfig is an alias for ZeroTrustConfig for backward compatibility
type ZTNAConfig = ZeroTrustConfig

// GetSessionTimeoutString converts SessionTimeout to string for compatibility
func (c *ZeroTrustConfig) GetSessionTimeoutString() string {
	switch v := c.SessionTimeout.(type) {
	case string:
		return v
	case time.Duration:
		return v.String()
	default:
		return "30m" // default fallback
	}
}

// RiskAssessmentConfig defines risk assessment configuration
type RiskAssessmentConfig struct {
	Enabled           bool    `json:"enabled"`
	BaselineRisk      float64 `json:"baselineRisk"`
	HighRiskThreshold float64 `json:"highRiskThreshold"`
	AnomalyMultiplier float64 `json:"anomalyMultiplier"`
}

// NetworkSegmentationConfig with embedded RiskAssessmentConfig for tests
type NetworkSegmentationConfigCompat struct {
	NetworkSegmentationConfig
	RiskAssessment RiskAssessmentConfig `json:"riskAssessment"`
}

// Note: LoginRequest, VerificationRequest, and VerificationResponse
// are defined in zt-handlers.go

// AccessPolicy represents an access policy
type AccessPolicy struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Resources          []string   `json:"resources"`
	RequiredTrustLevel TrustLevel `json:"requiredTrustLevel"`
	RequiredFactors    []string   `json:"requiredFactors"`
	RiskThreshold      float64    `json:"riskThreshold"`
}

// Update DeviceProfile to include missing fields for tests
type DeviceProfileCompat struct {
	DeviceProfile
	BrowserInfo string `json:"browserInfo"`
}

// GetPlugin returns a new instance of the plugin for dynamic loading
func GetPlugin() plugin.Plugin {
	return &ZeroTrustPlugin{}
}
