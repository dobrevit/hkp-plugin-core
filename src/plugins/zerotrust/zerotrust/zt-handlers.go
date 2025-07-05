package zerotrust

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
)

// HTTP Handler implementations

// handleLogin handles authentication requests
func (p *ZeroTrustPlugin) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse login request
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Extract client IP
	clientIP := p.extractClientIP(r)

	// Validate credentials (simplified - in production would use proper auth backend)
	if !p.validateCredentials(loginReq) {
		p.auditLogger.LogAuthFailure(clientIP, "invalid_credentials", loginReq.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create session
	session, err := p.sessionManager.GetOrCreateSession("", clientIP, r)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set user ID
	session.UserID = loginReq.Username

	// Add password auth factor
	session.AuthFactors = append(session.AuthFactors, AuthFactor{
		Type:      "password",
		Verified:  true,
		Timestamp: time.Now(),
		Strength:  5,
	})

	// Device profiling
	session.DeviceProfile = p.deviceProfiler.ProfileDevice(r)

	// Initial risk assessment
	session.RiskScore = p.riskAssessor.AssessRisk(session, r)
	session.TrustLevel = p.calculateTrustLevel(session.RiskScore)

	// Check if MFA required
	if p.requiresMFA(session, r) {
		// Return MFA challenge
		resp := LoginResponse{
			Status:    "mfa_required",
			SessionID: session.SessionID,
			Challenge: p.generateMFAChallenge(session),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Update session
	p.sessionManager.UpdateSession(session)

	// Return success response
	resp := LoginResponse{
		Status:     "success",
		SessionID:  session.SessionID,
		TrustLevel: session.TrustLevel.String(),
		ValidUntil: time.Now().Add(30 * time.Minute),
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "ztna-session",
		Value:    session.SessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   1800,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	// Audit log
	p.auditLogger.LogAccess(session, r, AccessDecision{
		Resource:      "/auth/login",
		Action:        "login",
		Allowed:       true,
		PolicyApplied: "authentication",
	}, time.Since(time.Now()))
}

// handleLogout handles logout requests
func (p *ZeroTrustPlugin) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := p.extractSessionID(r)
	if sessionID == "" {
		http.Error(w, "No session", http.StatusBadRequest)
		return
	}

	// Terminate session
	if err := p.sessionManager.TerminateSession(sessionID, "user_logout"); err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "ztna-session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"logged_out"}`))
}

// handleVerification handles MFA and step-up authentication
func (p *ZeroTrustPlugin) handleVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session
	sessionID := p.extractSessionID(r)
	session, err := p.sessionManager.GetOrCreateSession(sessionID, p.extractClientIP(r), r)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Parse verification request
	var verifyReq VerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&verifyReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify the challenge
	if !p.verifyChallenge(session, verifyReq) {
		p.auditLogger.LogAuthFailure(session.IPAddress, "verification_failed", verifyReq.Type)
		http.Error(w, "Verification failed", http.StatusUnauthorized)
		return
	}

	// Add verified factor
	session.AuthFactors = append(session.AuthFactors, AuthFactor{
		Type:      verifyReq.Type,
		Verified:  true,
		Timestamp: time.Now(),
		Strength:  p.getFactorStrength(verifyReq.Type),
	})

	// Re-assess risk and trust
	session.RiskScore = p.riskAssessor.AssessRisk(session, r)
	session.TrustLevel = p.calculateTrustLevel(session.RiskScore)

	// Update session
	p.sessionManager.UpdateSession(session)

	// Return response
	resp := VerificationResponse{
		Status:     "verified",
		TrustLevel: session.TrustLevel.String(),
		RiskScore:  session.RiskScore,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleDeviceRegistration handles device registration
func (p *ZeroTrustPlugin) handleDeviceRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session
	sessionID := p.extractSessionID(r)
	session, err := p.sessionManager.GetOrCreateSession(sessionID, p.extractClientIP(r), r)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Require authentication
	if len(session.AuthFactors) == 0 {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Parse device info
	var deviceReq DeviceRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&deviceReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Create enhanced device profile
	profile := p.deviceProfiler.ProfileDevice(r)

	// Add additional device information
	profile.Platform = deviceReq.Platform
	profile.ScreenResolution = deviceReq.ScreenResolution
	profile.Timezone = deviceReq.Timezone
	profile.Plugins = deviceReq.Plugins
	profile.Fonts = deviceReq.Fonts
	profile.WebGLFingerprint = deviceReq.WebGLFingerprint
	profile.CanvasFingerprint = deviceReq.CanvasFingerprint
	profile.AudioFingerprint = deviceReq.AudioFingerprint

	// Increase trust score for registered device
	profile.TrustScore = math.Min(profile.TrustScore+0.2, 0.95)

	// Update session
	session.DeviceProfile = profile
	p.sessionManager.UpdateSession(session)

	// Return response
	resp := DeviceRegistrationResponse{
		Status:   "registered",
		DeviceID: profile.DeviceID,
		Trust:    profile.TrustScore,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleZTNAStatus provides Zero-Trust status information
func (p *ZeroTrustPlugin) handleZTNAStatus(w http.ResponseWriter, r *http.Request) {
	// Get session if available
	sessionID := p.extractSessionID(r)

	status := ZTNAStatus{
		Enabled:   p.config.Enabled,
		Timestamp: time.Now(),
	}

	if sessionID != "" {
		session, err := p.sessionManager.GetOrCreateSession(sessionID, p.extractClientIP(r), r)
		if err == nil {
			status.Session = &SessionStatus{
				SessionID:    session.SessionID,
				UserID:       session.UserID,
				TrustLevel:   session.TrustLevel.String(),
				RiskScore:    session.RiskScore,
				Segment:      session.Segment,
				AuthFactors:  len(session.AuthFactors),
				CreatedAt:    session.CreatedAt,
				LastActivity: session.LastActivityAt,
			}
		}
	}

	// Add system statistics
	activeSessions := p.sessionManager.GetActiveSessions()
	status.Statistics = ZTNAStatistics{
		ActiveSessions: len(activeSessions),
		PolicyCount:    len(p.policyEngine.policies),
		SegmentCount:   len(p.segmentController.segments),
		AverageRisk:    p.calculateAverageRisk(activeSessions),
		HighRiskCount:  p.countHighRiskSessions(activeSessions),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// Event handlers

// handleThreatEvent handles threat detection events
func (p *ZeroTrustPlugin) handleThreatEvent(event plugin.PluginEvent) error {
	data := event.Data

	// Extract threat information
	clientIP, _ := data["client_ip"].(string)
	threatType, _ := data["threat_type"].(string)
	severity, _ := data["severity"].(string)

	// Find sessions for this IP
	sessions := p.sessionManager.GetActiveSessions()
	for _, session := range sessions {
		if session.IPAddress == clientIP {
			// Record incident
			p.riskAssessor.RecordIncident(session.SessionID, threatType, severity, "Threat detected by external system")

			// Re-assess risk
			oldRisk := session.RiskScore
			session.RiskScore = p.riskAssessor.ReassessRisk(session)

			// Log if risk increased significantly
			if session.RiskScore > oldRisk*1.2 {
				p.auditLogger.LogRiskIncrease(session, oldRisk, session.RiskScore)
			}

			// Terminate high-risk sessions
			if session.RiskScore > 0.95 {
				p.sessionManager.TerminateSession(session.SessionID, fmt.Sprintf("Threat detected: %s", threatType))
				p.auditLogger.LogSessionTermination(session, "threat_detected", threatType)
			}
		}
	}

	return nil
}

// handleRateLimitEvent handles rate limit violation events
func (p *ZeroTrustPlugin) handleRateLimitEvent(event plugin.PluginEvent) error {
	data := event.Data

	clientIP, _ := data["client_ip"].(string)
	reason, _ := data["reason"].(string)

	// Find sessions for this IP
	sessions := p.sessionManager.GetActiveSessions()
	for _, session := range sessions {
		if session.IPAddress == clientIP {
			// Record as security incident
			p.riskAssessor.RecordIncident(session.SessionID, "rate_limit_violation", "medium", reason)

			// Increase risk score
			session.RiskScore = math.Min(1.0, session.RiskScore*1.3)
			p.sessionManager.UpdateSession(session)

			// Downgrade trust level
			if session.TrustLevel > TrustLevelLow {
				session.TrustLevel = TrustLevelLow
				p.sessionManager.UpdateSession(session)
			}
		}
	}

	return nil
}

// handleEndpointProtectionEvent handles dynamic endpoint protection requests
func (p *ZeroTrustPlugin) handleEndpointProtectionEvent(event plugin.PluginEvent) error {
	data := event.Data

	// Parse the protection request
	var protectionReq plugin.EndpointProtectionRequest
	requestData, ok := data["request"].(map[string]interface{})
	if !ok {
		// Try to parse directly from data
		requestBytes, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal request data: %w", err)
		}
		if err := json.Unmarshal(requestBytes, &protectionReq); err != nil {
			return fmt.Errorf("failed to parse protection request: %w", err)
		}
	} else {
		requestBytes, err := json.Marshal(requestData)
		if err != nil {
			return fmt.Errorf("failed to marshal request data: %w", err)
		}
		if err := json.Unmarshal(requestBytes, &protectionReq); err != nil {
			return fmt.Errorf("failed to parse protection request: %w", err)
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Initialize temp protection map if nil
	if p.config.TempProtectedPaths == nil {
		p.config.TempProtectedPaths = make(map[string]time.Time)
	}

	switch protectionReq.Action {
	case "protect":
		// Add paths to protected list
		for _, path := range protectionReq.Paths {
			if protectionReq.Temporary {
				// Parse duration
				duration, err := time.ParseDuration(protectionReq.Duration)
				if err != nil {
					duration = 1 * time.Hour // Default to 1 hour
				}
				p.config.TempProtectedPaths[path] = time.Now().Add(duration)
				p.host.Logger().Info("Added temporary endpoint protection",
					"path", path,
					"duration", duration.String(),
					"requester", protectionReq.RequesterID,
					"reason", protectionReq.Reason)
			} else {
				// Add to permanent protected paths if not already present
				found := false
				for _, existingPath := range p.config.ProtectedPaths {
					if existingPath == path {
						found = true
						break
					}
				}
				if !found {
					p.config.ProtectedPaths = append(p.config.ProtectedPaths, path)
					p.host.Logger().Info("Added permanent endpoint protection",
						"path", path,
						"requester", protectionReq.RequesterID,
						"reason", protectionReq.Reason)
				}
			}
		}

	case "whitelist":
		// Add paths to public (whitelisted) paths
		for _, path := range protectionReq.Paths {
			if protectionReq.Temporary {
				// For temporary whitelist, we could implement a similar mechanism
				// but for now, just add to permanent list with logging
				p.host.Logger().Info("Temporary whitelist requested but adding permanently",
					"path", path,
					"duration", protectionReq.Duration,
					"requester", protectionReq.RequesterID)
			}

			// Add to public paths if not already present
			found := false
			for _, existingPath := range p.config.PublicPaths {
				if existingPath == path {
					found = true
					break
				}
			}
			if !found {
				p.config.PublicPaths = append(p.config.PublicPaths, path)
				p.host.Logger().Info("Added endpoint to whitelist",
					"path", path,
					"requester", protectionReq.RequesterID,
					"reason", protectionReq.Reason)
			}
		}

	default:
		p.host.Logger().Warn("Unknown endpoint protection action",
			"action", protectionReq.Action,
			"requester", protectionReq.RequesterID)
	}

	// Publish confirmation event
	responseEvent := plugin.PluginEvent{
		Type:      plugin.EventEndpointProtectionUpdate,
		Source:    p.Name(),
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"action":       protectionReq.Action,
			"paths":        protectionReq.Paths,
			"status":       "applied",
			"requester_id": protectionReq.RequesterID,
			"timestamp":    time.Now(),
		},
	}

	if err := p.host.PublishEvent(responseEvent); err != nil {
		p.host.Logger().Error("Failed to publish endpoint protection update event", "error", err)
	}

	return nil
}

// handleSecurityThreatEvent handles security threat notifications
func (p *ZeroTrustPlugin) handleSecurityThreatEvent(event plugin.PluginEvent) error {
	data := event.Data

	// Parse threat information
	var threatInfo plugin.SecurityThreatInfo
	threatData, ok := data["threat"].(map[string]interface{})
	if !ok {
		// Try to parse directly from data
		threatBytes, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal threat data: %w", err)
		}
		if err := json.Unmarshal(threatBytes, &threatInfo); err != nil {
			return fmt.Errorf("failed to parse threat info: %w", err)
		}
	} else {
		threatBytes, err := json.Marshal(threatData)
		if err != nil {
			return fmt.Errorf("failed to marshal threat data: %w", err)
		}
		if err := json.Unmarshal(threatBytes, &threatInfo); err != nil {
			return fmt.Errorf("failed to parse threat info: %w", err)
		}
	}

	// Log the threat
	p.host.Logger().Warn("Security threat detected",
		"threat_type", threatInfo.ThreatType,
		"severity", threatInfo.Severity,
		"client_ip", threatInfo.ClientIP,
		"endpoint", threatInfo.Endpoint,
		"confidence", threatInfo.Confidence,
		"description", threatInfo.Description)

	// Find affected sessions
	sessions := p.sessionManager.GetActiveSessions()
	for _, session := range sessions {
		if session.IPAddress == threatInfo.ClientIP {
			// Record security incident
			p.riskAssessor.RecordIncident(session.SessionID, threatInfo.ThreatType,
				threatInfo.Severity, threatInfo.Description)

			// Adjust risk score based on threat severity and confidence
			riskMultiplier := 1.0
			switch threatInfo.Severity {
			case "critical":
				riskMultiplier = 2.0
			case "high":
				riskMultiplier = 1.5
			case "medium":
				riskMultiplier = 1.2
			case "low":
				riskMultiplier = 1.1
			}

			// Apply confidence factor
			riskMultiplier = 1.0 + (riskMultiplier-1.0)*threatInfo.Confidence

			oldRisk := session.RiskScore
			session.RiskScore = math.Min(1.0, session.RiskScore*riskMultiplier)

			// Log risk increase
			if session.RiskScore > oldRisk {
				p.auditLogger.LogRiskIncrease(session, oldRisk, session.RiskScore)
			}

			// Take action based on recommended action and current risk
			switch threatInfo.RecommendedAction {
			case "block":
				if session.RiskScore > 0.8 || threatInfo.Severity == "critical" {
					p.sessionManager.TerminateSession(session.SessionID,
						fmt.Sprintf("Security threat: %s", threatInfo.ThreatType))
					p.auditLogger.LogSessionTermination(session, "security_threat", threatInfo.ThreatType)
				}
			case "rate_limit":
				// Downgrade trust level to trigger stricter rate limiting
				if session.TrustLevel > TrustLevelLow {
					session.TrustLevel = TrustLevelLow
				}
			case "monitor":
				// Just log and continue monitoring
				p.host.Logger().Info("Enhanced monitoring activated for session",
					"session_id", session.SessionID,
					"threat_type", threatInfo.ThreatType)
			}

			p.sessionManager.UpdateSession(session)
		}
	}

	return nil
}

// cleanupExpiredTempProtections removes expired temporary protections
func (p *ZeroTrustPlugin) cleanupExpiredTempProtections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.config.TempProtectedPaths == nil {
		return
	}

	now := time.Now()
	for path, expiry := range p.config.TempProtectedPaths {
		if now.After(expiry) {
			delete(p.config.TempProtectedPaths, path)
			p.host.Logger().Info("Removed expired temporary endpoint protection", "path", path)
		}
	}
}

// runPolicyUpdates handles periodic policy updates
func (p *ZeroTrustPlugin) runPolicyUpdates(ctx context.Context) {
	if !p.config.AdaptivePolicies.Enabled {
		return
	}

	interval, _ := time.ParseDuration(p.config.AdaptivePolicies.PolicyUpdateInterval)
	if interval == 0 {
		interval = 30 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.updateAdaptivePolicies(ctx)
		case <-p.tomb.Dying():
			return
		case <-ctx.Done():
			return
		}
	}
}

// // updateAdaptivePolicies updates policies based on learning data
// func (p *ZeroTrustPlugin) updateAdaptivePolicies() {
// 	if !p.config.AdaptivePolicies.LearningMode {
// 		return
// 	}

// 	// Analyze recent access patterns
// 	sessions := p.sessionManager.GetActiveSessions()

// 	// Update risk thresholds based on current threat landscape
// 	avgRisk := p.calculateAverageRisk(sessions)
// 	if avgRisk > p.config.AdaptivePolicies.AnomalyThreshold {
// 		// Tighten policies
// 		p.tightenPolicies(avgRisk)
// 	} else if avgRisk < p.config.AdaptivePolicies.AnomalyThreshold*0.5 {
// 		// Relax policies slightly
// 		p.relaxPolicies(avgRisk)
// 	}

// 	// Update learning data
// 	p.policyEngine.learningData.LastUpdate = time.Now()
// }

// Helper functions

func (p *ZeroTrustPlugin) validateCredentials(req LoginRequest) bool {
	// In production, would validate against LDAP/AD/OAuth provider
	// For demo, simple validation
	expectedPassword := "demo-password-" + req.Username
	return subtle.ConstantTimeCompare([]byte(req.Password), []byte(expectedPassword)) == 1
}

func (p *ZeroTrustPlugin) requiresMFA(session *SessionContext, r *http.Request) bool {
	// Check if accessing sensitive resources
	if strings.Contains(r.URL.Path, "/admin") {
		return true
	}

	// Check risk score
	if session.RiskScore > 0.6 {
		return true
	}

	// Check segment policy
	segment := p.segmentController.DetermineSegment(session, r)
	if policy, exists := p.config.NetworkSegmentation.SegmentPolicies[segment]; exists {
		return policy.RequireMFA
	}

	return false
}

func (p *ZeroTrustPlugin) generateMFAChallenge(session *SessionContext) MFAChallenge {
	// Generate TOTP challenge (simplified)
	return MFAChallenge{
		Type:      "totp",
		Challenge: fmt.Sprintf("Enter TOTP code for user %s", session.UserID),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

func (p *ZeroTrustPlugin) verifyChallenge(session *SessionContext, req VerificationRequest) bool {
	switch req.Type {
	case "totp":
		// In production, would verify TOTP token
		// For demo, accept specific format
		expectedCode := fmt.Sprintf("123456-%s", session.UserID[:3])
		return req.Code == expectedCode
	case "email":
		// In production, would verify email token
		return strings.HasPrefix(req.Code, "EMAIL-")
	case "sms":
		// In production, would verify SMS token
		return strings.HasPrefix(req.Code, "SMS-")
	default:
		return false
	}
}

func (p *ZeroTrustPlugin) getFactorStrength(factorType string) int {
	strengths := map[string]int{
		"password":    5,
		"totp":        8,
		"email":       6,
		"sms":         6,
		"certificate": 10,
		"biometric":   9,
		"hardware":    10,
	}

	if strength, exists := strengths[factorType]; exists {
		return strength
	}
	return 5
}

func (p *ZeroTrustPlugin) calculateAverageRisk(sessions []*SessionContext) float64 {
	if len(sessions) == 0 {
		return 0
	}

	var totalRisk float64
	for _, session := range sessions {
		totalRisk += session.RiskScore
	}

	return totalRisk / float64(len(sessions))
}

func (p *ZeroTrustPlugin) countHighRiskSessions(sessions []*SessionContext) int {
	count := 0
	for _, session := range sessions {
		if session.RiskScore > 0.7 {
			count++
		}
	}
	return count
}

func (p *ZeroTrustPlugin) tightenPolicies(avgRisk float64) {
	p.policyEngine.mu.Lock()
	defer p.policyEngine.mu.Unlock()

	// Lower risk thresholds
	for id, policy := range p.policyEngine.policies {
		if policy.RiskThreshold > 0 {
			policy.RiskThreshold = math.Max(0.3, policy.RiskThreshold*0.9)
			policy.UpdatedAt = time.Now()
			p.policyEngine.policies[id] = policy
		}
	}
}

func (p *ZeroTrustPlugin) relaxPolicies(avgRisk float64) {
	p.policyEngine.mu.Lock()
	defer p.policyEngine.mu.Unlock()

	// Slightly increase risk thresholds
	for id, policy := range p.policyEngine.policies {
		if policy.RiskThreshold > 0 && policy.RiskThreshold < 0.9 {
			policy.RiskThreshold = math.Min(0.9, policy.RiskThreshold*1.05)
			policy.UpdatedAt = time.Now()
			p.policyEngine.policies[id] = policy
		}
	}
}

// Request/Response types

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	DeviceID string `json:"device_id,omitempty"`
}

type LoginResponse struct {
	Status     string       `json:"status"`
	SessionID  string       `json:"session_id,omitempty"`
	TrustLevel string       `json:"trust_level,omitempty"`
	Challenge  MFAChallenge `json:"challenge,omitempty"`
	ValidUntil time.Time    `json:"valid_until,omitempty"`
}

type MFAChallenge struct {
	Type      string    `json:"type"`
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

type VerificationRequest struct {
	Type string `json:"type"`
	Code string `json:"code"`
}

type VerificationResponse struct {
	Status     string  `json:"status"`
	TrustLevel string  `json:"trust_level"`
	RiskScore  float64 `json:"risk_score"`
}

type DeviceRegistrationRequest struct {
	Platform          string   `json:"platform"`
	ScreenResolution  string   `json:"screen_resolution"`
	Timezone          string   `json:"timezone"`
	Plugins           []string `json:"plugins"`
	Fonts             []string `json:"fonts"`
	WebGLFingerprint  string   `json:"webgl_fingerprint"`
	CanvasFingerprint string   `json:"canvas_fingerprint"`
	AudioFingerprint  string   `json:"audio_fingerprint"`
}

type DeviceRegistrationResponse struct {
	Status   string  `json:"status"`
	DeviceID string  `json:"device_id"`
	Trust    float64 `json:"trust"`
}

type ZTNAStatus struct {
	Enabled    bool           `json:"enabled"`
	Timestamp  time.Time      `json:"timestamp"`
	Session    *SessionStatus `json:"session,omitempty"`
	Statistics ZTNAStatistics `json:"statistics"`
}

type SessionStatus struct {
	SessionID    string    `json:"session_id"`
	UserID       string    `json:"user_id"`
	TrustLevel   string    `json:"trust_level"`
	RiskScore    float64   `json:"risk_score"`
	Segment      string    `json:"segment"`
	AuthFactors  int       `json:"auth_factors"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
}

type ZTNAStatistics struct {
	ActiveSessions int     `json:"active_sessions"`
	PolicyCount    int     `json:"policy_count"`
	SegmentCount   int     `json:"segment_count"`
	AverageRisk    float64 `json:"average_risk"`
	HighRiskCount  int     `json:"high_risk_sessions"`
}
