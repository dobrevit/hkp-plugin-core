package zerotrust

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SessionManager manages zero-trust sessions
type SessionManager struct {
	config          *ZeroTrustConfig
	sessions        map[string]*SessionContext
	sessionIndex    map[string][]string // userID -> sessionIDs
	mu              sync.RWMutex
	persistencePath string
}

// NewSessionManager creates a new session manager
func NewSessionManager(config *ZeroTrustConfig) *SessionManager {
	return &SessionManager{
		config:          config,
		sessions:        make(map[string]*SessionContext),
		sessionIndex:    make(map[string][]string),
		persistencePath: "/var/lib/hockeypuck/ztna-sessions.json",
	}
}

// GetOrCreateSession retrieves an existing session or creates a new one
func (sm *SessionManager) GetOrCreateSession(sessionID string, clientIP string, r *http.Request) (*SessionContext, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Try to get existing session
	if sessionID != "" {
		if session, exists := sm.sessions[sessionID]; exists {
			// Verify session is still valid
			if sm.isSessionValid(session) {
				// Update last activity
				session.LastActivityAt = time.Now()
				return session, nil
			}
			// Session expired, remove it
			sm.removeSession(sessionID)
		}
	}

	// Create new session
	newSessionID, err := sm.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	session := &SessionContext{
		SessionID:        newSessionID,
		IPAddress:        clientIP,
		CreatedAt:        time.Now(),
		LastActivityAt:   time.Now(),
		TrustLevel:       TrustLevelNone,
		RiskScore:        0.5, // Default medium risk
		AuthFactors:      make([]AuthFactor, 0),
		AccessDecisions:  make([]AccessDecision, 0),
		ContinuousScores: make(map[time.Time]float64),
		Segment:          sm.config.NetworkSegmentation.DefaultSegment,
	}

	// Extract user ID if available
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		session.UserID = userID
	}

	sm.sessions[newSessionID] = session

	// Update session index
	if session.UserID != "" {
		sm.sessionIndex[session.UserID] = append(sm.sessionIndex[session.UserID], newSessionID)
	}

	return session, nil
}

// UpdateSession updates session information
func (sm *SessionManager) UpdateSession(session *SessionContext) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if existing, exists := sm.sessions[session.SessionID]; exists {
		// Update mutable fields
		existing.LastActivityAt = time.Now()
		existing.RiskScore = session.RiskScore
		existing.TrustLevel = session.TrustLevel
		existing.DeviceProfile = session.DeviceProfile
		existing.Segment = session.Segment
		existing.AuthFactors = session.AuthFactors
		existing.AccessDecisions = session.AccessDecisions
		existing.ContinuousScores = session.ContinuousScores
	}
}

// GetActiveSessions returns all active sessions
func (sm *SessionManager) GetActiveSessions() []*SessionContext {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	active := make([]*SessionContext, 0)
	for _, session := range sm.sessions {
		if sm.isSessionValid(session) {
			// Return a copy to prevent concurrent modification
			sessionCopy := *session
			active = append(active, &sessionCopy)
		}
	}

	return active
}

// TerminateSession terminates a session
func (sm *SessionManager) TerminateSession(sessionID string, reason string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Log termination
	fmt.Printf("Session %s terminated: %s\n", sessionID, reason)

	// Remove from index
	sm.removeSession(sessionID)

	return nil
}

// SaveState persists session state to disk
func (sm *SessionManager) SaveState() error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Create session data for persistence
	data := make(map[string]interface{})
	data["sessions"] = sm.sessions
	data["index"] = sm.sessionIndex
	data["timestamp"] = time.Now()

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sessions: %w", err)
	}

	// Write to file
	if err := os.WriteFile(sm.persistencePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	return nil
}

// LoadState loads session state from disk
func (sm *SessionManager) LoadState() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check if file exists
	if _, err := os.Stat(sm.persistencePath); os.IsNotExist(err) {
		return nil // No state to load
	}

	// Read file
	jsonData, err := os.ReadFile(sm.persistencePath)
	if err != nil {
		return fmt.Errorf("failed to read session file: %w", err)
	}

	// Unmarshal data
	var data map[string]interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return fmt.Errorf("failed to unmarshal sessions: %w", err)
	}

	// Restore sessions (simplified - would need proper type conversion)
	// In production, would properly deserialize session objects

	return nil
}

// Helper functions

func (sm *SessionManager) generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (sm *SessionManager) isSessionValid(session *SessionContext) bool {
	// Check session timeout
	timeout, _ := time.ParseDuration(sm.config.GetSessionTimeoutString())
	if time.Since(session.CreatedAt) > timeout {
		return false
	}

	// Check inactivity timeout
	inactivityTimeout := 15 * time.Minute
	return time.Since(session.LastActivityAt) <= inactivityTimeout
}

func (sm *SessionManager) removeSession(sessionID string) {
	session, exists := sm.sessions[sessionID]
	if !exists {
		return
	}

	// Remove from sessions map
	delete(sm.sessions, sessionID)

	// Remove from index
	if session.UserID != "" {
		sessions := sm.sessionIndex[session.UserID]
		for i, sid := range sessions {
			if sid == sessionID {
				sm.sessionIndex[session.UserID] = append(sessions[:i], sessions[i+1:]...)
				break
			}
		}

		// Clean up empty index entries
		if len(sm.sessionIndex[session.UserID]) == 0 {
			delete(sm.sessionIndex, session.UserID)
		}
	}
}

// runSessionCleanup periodically cleans up expired sessions
func (p *ZeroTrustPlugin) runSessionCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanupExpiredSessions(ctx)
		case <-p.tomb.Dying():
			return
		case <-ctx.Done():
			return
		}
	}
}

// func (p *ZeroTrustPlugin) cleanupExpiredSessions() {
// 	sessions := p.sessionManager.GetActiveSessions()

// 	for _, session := range sessions {
// 		if !p.sessionManager.isSessionValid(session) {
// 			p.sessionManager.TerminateSession(session.SessionID, "expired")
// 			p.auditLogger.LogSessionExpiration(session)
// 		}
// 	}
// }

// AuditLogger handles security audit logging
type AuditLogger struct {
	level      string
	logPath    string
	logFile    *os.File
	mu         sync.Mutex
	buffer     []AuditEntry
	bufferSize int
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	SessionID string                 `json:"session_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	ClientIP  string                 `json:"client_ip,omitempty"`
	Resource  string                 `json:"resource,omitempty"`
	Action    string                 `json:"action,omitempty"`
	Result    string                 `json:"result"`
	RiskScore float64                `json:"risk_score,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(level, path string) *AuditLogger {
	return &AuditLogger{
		level:      level,
		logPath:    filepath.Join(path, "ztna-audit.log"),
		buffer:     make([]AuditEntry, 0, 100),
		bufferSize: 100,
	}
}

// Initialize opens the log file
func (al *AuditLogger) Initialize() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	// Create log directory if needed
	logDir := filepath.Dir(al.logPath)
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file
	file, err := os.OpenFile(al.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}

	al.logFile = file
	return nil
}

// LogAccess logs successful access
func (al *AuditLogger) LogAccess(session *SessionContext, r *http.Request, decision AccessDecision, duration time.Duration) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		EventType: "access_granted",
		SessionID: session.SessionID,
		UserID:    session.UserID,
		ClientIP:  session.IPAddress,
		Resource:  r.URL.Path,
		Action:    r.Method,
		Result:    "success",
		RiskScore: session.RiskScore,
		Details: map[string]interface{}{
			"duration_ms":    duration.Milliseconds(),
			"trust_level":    session.TrustLevel.String(),
			"segment":        session.Segment,
			"policy_applied": decision.PolicyApplied,
		},
	}

	al.writeEntry(entry)
}

// LogAccessDenied logs denied access
func (al *AuditLogger) LogAccessDenied(session *SessionContext, decision AccessDecision) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		EventType: "access_denied",
		SessionID: session.SessionID,
		UserID:    session.UserID,
		ClientIP:  session.IPAddress,
		Resource:  decision.Resource,
		Action:    decision.Action,
		Result:    "denied",
		RiskScore: session.RiskScore,
		Details: map[string]interface{}{
			"reason":         decision.Reason,
			"policy_applied": decision.PolicyApplied,
			"trust_level":    session.TrustLevel.String(),
		},
	}

	al.writeEntry(entry)
}

// LogAuthFailure logs authentication failures
func (al *AuditLogger) LogAuthFailure(clientIP string, reason string, details string) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		EventType: "auth_failure",
		ClientIP:  clientIP,
		Result:    "failure",
		Details: map[string]interface{}{
			"reason":  reason,
			"details": details,
		},
	}

	al.writeEntry(entry)
}

// LogSegmentViolation logs network segment violations
func (al *AuditLogger) LogSegmentViolation(session *SessionContext, segment string, r *http.Request) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		EventType: "segment_violation",
		SessionID: session.SessionID,
		UserID:    session.UserID,
		ClientIP:  session.IPAddress,
		Resource:  r.URL.Path,
		Action:    r.Method,
		Result:    "blocked",
		Details: map[string]interface{}{
			"attempted_segment": segment,
			"session_segment":   session.Segment,
			"trust_level":       session.TrustLevel.String(),
		},
	}

	al.writeEntry(entry)
}

// LogRiskIncrease logs significant risk score increases
func (al *AuditLogger) LogRiskIncrease(session *SessionContext, oldRisk, newRisk float64) {
	if al.level != "detailed" {
		return
	}

	entry := AuditEntry{
		Timestamp: time.Now(),
		EventType: "risk_increase",
		SessionID: session.SessionID,
		UserID:    session.UserID,
		ClientIP:  session.IPAddress,
		Result:    "warning",
		RiskScore: newRisk,
		Details: map[string]interface{}{
			"old_risk":    oldRisk,
			"new_risk":    newRisk,
			"increase":    newRisk - oldRisk,
			"trust_level": session.TrustLevel.String(),
		},
	}

	al.writeEntry(entry)
}

// LogSessionTermination logs session terminations
func (al *AuditLogger) LogSessionTermination(session *SessionContext, reason string, details string) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		EventType: "session_terminated",
		SessionID: session.SessionID,
		UserID:    session.UserID,
		ClientIP:  session.IPAddress,
		Result:    "terminated",
		Details: map[string]interface{}{
			"reason":           reason,
			"details":          details,
			"session_duration": time.Since(session.CreatedAt).String(),
			"final_risk":       session.RiskScore,
		},
	}

	al.writeEntry(entry)
}

// LogSessionExpiration logs expired sessions
func (al *AuditLogger) LogSessionExpiration(session *SessionContext) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		EventType: "session_expired",
		SessionID: session.SessionID,
		UserID:    session.UserID,
		ClientIP:  session.IPAddress,
		Result:    "expired",
		Details: map[string]interface{}{
			"session_duration": time.Since(session.CreatedAt).String(),
			"last_activity":    session.LastActivityAt,
		},
	}

	al.writeEntry(entry)
}

// LogShutdown logs plugin shutdown
func (al *AuditLogger) LogShutdown() {
	entry := AuditEntry{
		Timestamp: time.Now(),
		EventType: "plugin_shutdown",
		Result:    "success",
		Details: map[string]interface{}{
			"plugin": "zero-trust-security",
		},
	}

	al.writeEntry(entry)
	al.flush()

	if al.logFile != nil {
		al.logFile.Close()
	}
}

// writeEntry writes an audit entry
func (al *AuditLogger) writeEntry(entry AuditEntry) {
	al.mu.Lock()
	defer al.mu.Unlock()

	// Add to buffer
	al.buffer = append(al.buffer, entry)

	// Flush if buffer is full
	if len(al.buffer) >= al.bufferSize {
		al.flush()
	}
}

// flush writes buffered entries to disk
func (al *AuditLogger) flush() {
	if al.logFile == nil || len(al.buffer) == 0 {
		return
	}

	// Write each entry as JSON line
	for _, entry := range al.buffer {
		jsonData, err := json.Marshal(entry)
		if err != nil {
			continue
		}

		al.logFile.Write(jsonData)
		al.logFile.Write([]byte("\n"))
	}

	// Sync to disk
	al.logFile.Sync()

	// Clear buffer
	al.buffer = al.buffer[:0]
}

// DeviceProfiler handles device fingerprinting
type DeviceProfiler struct {
	level    string
	profiles map[string]*DeviceProfile
	mu       sync.RWMutex
}

// NewDeviceProfiler creates a new device profiler
func NewDeviceProfiler(level string) *DeviceProfiler {
	return &DeviceProfiler{
		level:    level,
		profiles: make(map[string]*DeviceProfile),
	}
}

// ProfileDevice creates a device profile from request
func (dp *DeviceProfiler) ProfileDevice(r *http.Request) *DeviceProfile {
	profile := &DeviceProfile{
		LastSeen: time.Now(),
	}

	// Extract basic information
	profile.Browser = dp.extractBrowser(r.Header.Get("User-Agent"))
	profile.Platform = dp.extractPlatform(r.Header.Get("User-Agent"))

	// Generate device fingerprint
	profile.Fingerprint = dp.generateFingerprint(r)
	profile.DeviceID = profile.Fingerprint[:16] // Use first 16 chars as ID

	// TLS fingerprinting
	if r.TLS != nil {
		profile.TLSFingerprint = dp.generateTLSFingerprint(r.TLS)
	}

	// Extract client hints if available
	profile.Languages = dp.extractLanguages(r.Header.Get("Accept-Language"))

	// Calculate initial trust score
	profile.TrustScore = dp.calculateInitialTrust(profile)

	// Store profile
	dp.mu.Lock()
	dp.profiles[profile.DeviceID] = profile
	dp.mu.Unlock()

	return profile
}

// Helper functions for device profiling

func (dp *DeviceProfiler) generateFingerprint(r *http.Request) string {
	h := sha256.New()

	// Core headers
	h.Write([]byte(r.Header.Get("User-Agent")))
	h.Write([]byte(r.Header.Get("Accept")))
	h.Write([]byte(r.Header.Get("Accept-Language")))
	h.Write([]byte(r.Header.Get("Accept-Encoding")))

	// Additional fingerprinting headers
	h.Write([]byte(r.Header.Get("DNT")))
	h.Write([]byte(r.Header.Get("Upgrade-Insecure-Requests")))

	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

func (dp *DeviceProfiler) extractBrowser(userAgent string) string {
	// Simplified browser detection
	if strings.Contains(userAgent, "Chrome") {
		return "Chrome"
	} else if strings.Contains(userAgent, "Firefox") {
		return "Firefox"
	} else if strings.Contains(userAgent, "Safari") {
		return "Safari"
	}
	return "Unknown"
}

func (dp *DeviceProfiler) extractPlatform(userAgent string) string {
	// Simplified platform detection
	if strings.Contains(userAgent, "Windows") {
		return "Windows"
	} else if strings.Contains(userAgent, "Mac OS") {
		return "macOS"
	} else if strings.Contains(userAgent, "Linux") {
		return "Linux"
	} else if strings.Contains(userAgent, "Android") {
		return "Android"
	} else if strings.Contains(userAgent, "iOS") {
		return "iOS"
	}
	return "Unknown"
}

func (dp *DeviceProfiler) extractLanguages(acceptLanguage string) []string {
	languages := make([]string, 0)
	parts := strings.Split(acceptLanguage, ",")

	for _, part := range parts {
		lang := strings.TrimSpace(strings.Split(part, ";")[0])
		if lang != "" {
			languages = append(languages, lang)
		}
	}

	return languages
}

func (dp *DeviceProfiler) generateTLSFingerprint(tls *tls.ConnectionState) string {
	if tls == nil {
		return ""
	}

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d", tls.Version)))
	h.Write([]byte(fmt.Sprintf("%d", tls.CipherSuite)))
	h.Write([]byte(tls.NegotiatedProtocol))

	// Add supported curves and signature schemes
	// (simplified - would need access to ClientHello in production)

	return base64.URLEncoding.EncodeToString(h.Sum(nil))[:16]
}

func (dp *DeviceProfiler) calculateInitialTrust(profile *DeviceProfile) float64 {
	trust := 0.5 // Base trust

	// Known browsers get higher trust
	if profile.Browser != "Unknown" {
		trust += 0.1
	}

	// Known platforms get higher trust
	if profile.Platform != "Unknown" {
		trust += 0.1
	}

	// Modern TLS gets higher trust
	if profile.TLSFingerprint != "" {
		trust += 0.1
	}

	// Multiple languages indicate real browser
	if len(profile.Languages) > 1 {
		trust += 0.1
	}

	return math.Min(trust, 0.9) // Cap initial trust
}
