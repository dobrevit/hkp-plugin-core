// Zero Trust components for comprehensive security
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
)

// ContinuousAuthenticator handles ongoing authentication verification
type ContinuousAuthenticator struct {
	config            *ZeroTrustConfig
	behaviorBaselines map[string]*BehaviorBaseline
	authProviders     []AuthProvider
	mu                sync.RWMutex
}

// BehaviorBaseline represents normal behavior patterns for a user/device
type BehaviorBaseline struct {
	UserID             string
	DeviceID           string
	TypicalLocations   []Location
	TypicalAccessTimes []TimeRange
	TypicalResources   []string
	LastUpdated        time.Time
}

// TimeRange represents a time period
type TimeRange struct {
	StartHour int
	EndHour   int
	Days      []int // 0-6, Sunday=0
}

// AuthProvider represents an authentication provider
type AuthProvider struct {
	Name     string
	Type     string // oauth, saml, ldap, api_key
	Endpoint string
	Config   map[string]string
}

func NewContinuousAuthenticator(config *ZeroTrustConfig) *ContinuousAuthenticator {
	return &ContinuousAuthenticator{
		config:            config,
		behaviorBaselines: make(map[string]*BehaviorBaseline),
		authProviders: []AuthProvider{
			{
				Name:     "API Key",
				Type:     "api_key",
				Endpoint: "/auth/api",
				Config:   map[string]string{"header": "X-API-Key"},
			},
		},
	}
}

func (ca *ContinuousAuthenticator) ValidateSession(sessionID string) bool {
	// Simplified session validation
	return sessionID != "" && len(sessionID) > 10
}

func (ca *ContinuousAuthenticator) CreateSession(userID, deviceID string) *Session {
	sessionID := generateSessionID()
	
	session := &Session{
		ID:                sessionID,
		UserID:            userID,
		DeviceID:          deviceID,
		CreatedAt:         time.Now(),
		LastActivity:      time.Now(),
		RiskScore:         0.0,
		TrustLevel:        "low",
		Authenticated:     true,
		DeviceFingerprint: make(map[string]string),
		VerificationCount: 1,
	}

	return session
}

// DeviceProfiler creates device fingerprints and profiles
type DeviceProfiler struct {
	fingerprintingLevel string
	deviceProfiles      map[string]*DeviceProfile
	mu                  sync.RWMutex
}

type DeviceProfile struct {
	DeviceID         string
	UserAgent        string
	ScreenResolution string
	TimeZone         string
	Languages        []string
	Plugins          []string
	FirstSeen        time.Time
	LastSeen         time.Time
	TrustScore       float64
}

func NewDeviceProfiler(level string) *DeviceProfiler {
	return &DeviceProfiler{
		fingerprintingLevel: level,
		deviceProfiles:      make(map[string]*DeviceProfile),
	}
}

func (dp *DeviceProfiler) CreateFingerprint(req *proto.HTTPRequest) map[string]string {
	fingerprint := make(map[string]string)

	// Extract device characteristics from headers
	if userAgent, exists := req.Headers["User-Agent"]; exists {
		fingerprint["user_agent"] = userAgent
	}

	if acceptLang, exists := req.Headers["Accept-Language"]; exists {
		fingerprint["languages"] = acceptLang
	}

	if xForwardedFor, exists := req.Headers["X-Forwarded-For"]; exists {
		fingerprint["proxy_chain"] = xForwardedFor
	}

	// Generate device ID based on characteristics
	deviceID := dp.generateDeviceID(fingerprint)
	fingerprint["device_id"] = deviceID

	return fingerprint
}

func (dp *DeviceProfiler) generateDeviceID(fingerprint map[string]string) string {
	// Create deterministic device ID based on characteristics
	var components []string
	for key, value := range fingerprint {
		components = append(components, key+":"+value)
	}
	
	// For simplicity, use first 16 chars of combined string hash
	combined := strings.Join(components, "|")
	if len(combined) > 16 {
		return combined[:16]
	}
	return combined
}

func (dp *DeviceProfiler) UpdateProfile(deviceID string, req *proto.HTTPRequest) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	profile, exists := dp.deviceProfiles[deviceID]
	if !exists {
		profile = &DeviceProfile{
			DeviceID:  deviceID,
			FirstSeen: time.Now(),
			TrustScore: 0.5, // Start with neutral trust
		}
		dp.deviceProfiles[deviceID] = profile
	}

	// Update profile with new information
	if userAgent, exists := req.Headers["User-Agent"]; exists {
		profile.UserAgent = userAgent
	}
	
	profile.LastSeen = time.Now()
	
	// Increase trust score over time
	if time.Since(profile.FirstSeen) > 24*time.Hour {
		profile.TrustScore = math.Min(1.0, profile.TrustScore+0.1)
	}
}

// RiskAssessor evaluates risk levels for requests and sessions
type RiskAssessor struct {
	config         RiskAssessmentConfig
	riskHistory    map[string][]RiskEvent
	locationCache  map[string]*Location
	securityEvents map[string][]SecurityEvent
	mu             sync.RWMutex
}

type RiskEvent struct {
	Timestamp time.Time
	RiskScore float64
	Factors   []string
}

type SecurityEvent struct {
	Timestamp   time.Time
	EventType   string
	Description string
	Severity    string
}

func NewRiskAssessor(config RiskAssessmentConfig) *RiskAssessor {
	return &RiskAssessor{
		config:         config,
		riskHistory:    make(map[string][]RiskEvent),
		locationCache:  make(map[string]*Location),
		securityEvents: make(map[string][]SecurityEvent),
	}
}

func (ra *RiskAssessor) AssessRisk(clientIP string, req *proto.HTTPRequest, session *Session) float64 {
	var riskScore float64

	// Location risk
	locationRisk := ra.assessLocationRisk(clientIP)
	riskScore += locationRisk * ra.config.LocationRiskWeight

	// Behavioral risk
	behaviorRisk := ra.assessBehaviorRisk(session, req)
	riskScore += behaviorRisk * ra.config.BehaviorRiskWeight

	// Device risk
	deviceRisk := ra.assessDeviceRisk(session)
	riskScore += deviceRisk * ra.config.DeviceRiskWeight

	// Time-based risk
	timeRisk := ra.assessTimeRisk()
	riskScore += timeRisk * ra.config.TimeRiskWeight

	// Record risk event
	ra.recordRiskEvent(clientIP, riskScore, []string{"location", "behavior", "device", "time"})

	return math.Max(0.0, math.Min(1.0, riskScore))
}

func (ra *RiskAssessor) QuickAssess(clientIP string) float64 {
	// Quick risk assessment for rate limiting
	locationRisk := ra.assessLocationRisk(clientIP)
	
	// Check security event history
	securityRisk := 0.0
	ra.mu.RLock()
	if events, exists := ra.securityEvents[clientIP]; exists {
		recentEvents := 0
		cutoff := time.Now().Add(-1 * time.Hour)
		for _, event := range events {
			if event.Timestamp.After(cutoff) {
				recentEvents++
			}
		}
		securityRisk = math.Min(1.0, float64(recentEvents)*0.2)
	}
	ra.mu.RUnlock()

	return math.Max(0.0, math.Min(1.0, locationRisk*0.7+securityRisk*0.3))
}

func (ra *RiskAssessor) ReassessSession(session *Session) float64 {
	// Re-evaluate session risk
	baseRisk := session.RiskScore

	// Increase risk over time if no activity
	timeSinceActivity := time.Since(session.LastActivity)
	if timeSinceActivity > 30*time.Minute {
		baseRisk += 0.1
	}

	// Check for security events related to this session
	if session.Location != nil {
		locationRisk := ra.assessLocationRisk(session.Location.IP)
		baseRisk = math.Max(baseRisk, locationRisk)
	}

	return math.Max(0.0, math.Min(1.0, baseRisk))
}

func (ra *RiskAssessor) assessLocationRisk(clientIP string) float64 {
	// Check if IP is private (low risk)
	if isPrivateIP(clientIP) {
		return 0.1
	}

	// Simplified location risk assessment
	// In production, would use GeoIP database and reputation services
	
	// Check for known high-risk countries or networks
	highRiskIPs := []string{
		"192.0.2.", // RFC 5737 test range
		"198.51.100.",
		"203.0.113.",
	}

	for _, riskIP := range highRiskIPs {
		if strings.HasPrefix(clientIP, riskIP) {
			return 0.8
		}
	}

	return 0.3 // Default moderate risk for unknown IPs
}

func (ra *RiskAssessor) assessBehaviorRisk(session *Session, req *proto.HTTPRequest) float64 {
	if session == nil {
		return 0.5 // Unknown session = moderate risk
	}

	behaviorRisk := 0.0

	// Check access patterns
	if strings.Contains(req.Path, "admin") && session.TrustLevel == "low" {
		behaviorRisk += 0.3
	}

	// Check for rapid successive requests (potential automation)
	if session.VerificationCount > 10 {
		behaviorRisk += 0.2
	}

	return math.Max(0.0, math.Min(1.0, behaviorRisk))
}

func (ra *RiskAssessor) assessDeviceRisk(session *Session) float64 {
	if session == nil || len(session.DeviceFingerprint) == 0 {
		return 0.4 // Unknown device = moderate risk
	}

	deviceRisk := 0.0

	// Check for suspicious device characteristics
	if userAgent, exists := session.DeviceFingerprint["user_agent"]; exists {
		// Check for bot-like user agents
		botIndicators := []string{"bot", "crawler", "spider", "scraper"}
		for _, indicator := range botIndicators {
			if strings.Contains(strings.ToLower(userAgent), indicator) {
				deviceRisk += 0.5
				break
			}
		}
	}

	return math.Max(0.0, math.Min(1.0, deviceRisk))
}

func (ra *RiskAssessor) assessTimeRisk() float64 {
	now := time.Now()
	hour := now.Hour()

	// Higher risk during unusual hours (late night/early morning)
	if hour < 6 || hour > 22 {
		return 0.3
	}

	// Business hours = lower risk
	if hour >= 9 && hour <= 17 {
		return 0.1
	}

	return 0.2 // Moderate risk for evening hours
}

func (ra *RiskAssessor) recordRiskEvent(clientIP string, riskScore float64, factors []string) {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	event := RiskEvent{
		Timestamp: time.Now(),
		RiskScore: riskScore,
		Factors:   factors,
	}

	events := ra.riskHistory[clientIP]
	events = append(events, event)

	// Keep only recent events (last 24 hours)
	cutoff := time.Now().Add(-24 * time.Hour)
	filtered := make([]RiskEvent, 0)
	for _, e := range events {
		if e.Timestamp.After(cutoff) {
			filtered = append(filtered, e)
		}
	}

	ra.riskHistory[clientIP] = filtered
}

func (ra *RiskAssessor) RecordSecurityEvent(clientIP, eventType string) {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	event := SecurityEvent{
		Timestamp:   time.Now(),
		EventType:   eventType,
		Description: fmt.Sprintf("Security event: %s", eventType),
		Severity:    "medium",
	}

	events := ra.securityEvents[clientIP]
	events = append(events, event)

	// Keep only recent events
	cutoff := time.Now().Add(-24 * time.Hour)
	filtered := make([]SecurityEvent, 0)
	for _, e := range events {
		if e.Timestamp.After(cutoff) {
			filtered = append(filtered, e)
		}
	}

	ra.securityEvents[clientIP] = filtered
}

func (ra *RiskAssessor) RecordThreatReport(clientIP, threatType, description string) {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	severity := "high"
	if threatType == "malware" || threatType == "botnet" {
		severity = "critical"
	}

	event := SecurityEvent{
		Timestamp:   time.Now(),
		EventType:   threatType,
		Description: description,
		Severity:    severity,
	}

	events := ra.securityEvents[clientIP]
	ra.securityEvents[clientIP] = append(events, event)
}

// AdaptivePolicyEngine manages dynamic policy adjustments
type AdaptivePolicyEngine struct {
	config         AdaptivePolicyConfig
	policies       map[string]*Policy
	policyHistory  []PolicyChange
	learningData   map[string][]PolicyEvent
	mu             sync.RWMutex
}

type Policy struct {
	Name        string
	Type        string
	Rules       []PolicyRule
	Threshold   float64
	LastUpdated time.Time
	Enabled     bool
}

type PolicyRule struct {
	Condition string
	Action    string
	Value     interface{}
}

type PolicyChange struct {
	Timestamp   time.Time
	PolicyName  string
	ChangeType  string
	OldValue    interface{}
	NewValue    interface{}
	Reason      string
}

type PolicyEvent struct {
	Timestamp time.Time
	EventType string
	Context   map[string]interface{}
	Outcome   string
}

func NewAdaptivePolicyEngine(config AdaptivePolicyConfig) *AdaptivePolicyEngine {
	engine := &AdaptivePolicyEngine{
		config:        config,
		policies:      make(map[string]*Policy),
		learningData:  make(map[string][]PolicyEvent),
	}

	// Initialize default policies
	engine.initializeDefaultPolicies()
	
	return engine
}

func (ape *AdaptivePolicyEngine) initializeDefaultPolicies() {
	// Default risk threshold policy
	riskPolicy := &Policy{
		Name: "risk_threshold",
		Type: "risk_assessment",
		Rules: []PolicyRule{
			{
				Condition: "risk_score > threshold",
				Action:    "block",
				Value:     0.7,
			},
		},
		Threshold:   0.7,
		LastUpdated: time.Now(),
		Enabled:     true,
	}

	ape.policies["risk_threshold"] = riskPolicy
}

func (ape *AdaptivePolicyEngine) UpdatePolicies() {
	if !ape.config.Enabled {
		return
	}

	ape.mu.Lock()
	defer ape.mu.Unlock()

	// Analyze learning data and adjust policies
	for policyName, policy := range ape.policies {
		if ape.config.AutoAdjustThresholds {
			newThreshold := ape.calculateOptimalThreshold(policyName)
			if newThreshold != policy.Threshold {
				ape.recordPolicyChange(policyName, "threshold_adjustment", policy.Threshold, newThreshold, "adaptive_learning")
				policy.Threshold = newThreshold
				policy.LastUpdated = time.Now()
			}
		}
	}
}

func (ape *AdaptivePolicyEngine) calculateOptimalThreshold(policyName string) float64 {
	// Simplified threshold calculation
	// In production, would use machine learning algorithms
	
	events := ape.learningData[policyName]
	if len(events) < 10 {
		return 0.7 // Default threshold
	}

	// Calculate success/failure rates at different thresholds
	successRate := 0.0
	for _, event := range events {
		if event.Outcome == "success" {
			successRate++
		}
	}
	successRate /= float64(len(events))

	// Adjust threshold based on success rate
	if successRate > 0.9 {
		return 0.8 // Increase threshold if too many false positives
	} else if successRate < 0.7 {
		return 0.6 // Decrease threshold if too many false negatives
	}

	return 0.7 // Maintain current threshold
}

func (ape *AdaptivePolicyEngine) recordPolicyChange(policyName, changeType string, oldValue, newValue interface{}, reason string) {
	change := PolicyChange{
		Timestamp:  time.Now(),
		PolicyName: policyName,
		ChangeType: changeType,
		OldValue:   oldValue,
		NewValue:   newValue,
		Reason:     reason,
	}

	ape.policyHistory = append(ape.policyHistory, change)

	// Keep only recent history
	if len(ape.policyHistory) > 1000 {
		ape.policyHistory = ape.policyHistory[100:]
	}
}

// SessionManager manages user sessions
type SessionManager struct {
	config   *ZeroTrustConfig
	sessions map[string]*Session
	ipMap    map[string][]*Session // IP to sessions mapping
	mu       sync.RWMutex
}

func NewSessionManager(config *ZeroTrustConfig) *SessionManager {
	return &SessionManager{
		config:   config,
		sessions: make(map[string]*Session),
		ipMap:    make(map[string][]*Session),
	}
}

func (sm *SessionManager) GetSession(sessionID string) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil
	}

	// Check if session is expired
	timeout, _ := time.ParseDuration(sm.config.SessionTimeout)
	if time.Since(session.LastActivity) > timeout {
		return nil
	}

	return session
}

func (sm *SessionManager) UpdateSession(session *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session.LastActivity = time.Now()
	sm.sessions[session.ID] = session

	// Update IP mapping
	if session.Location != nil {
		sessions := sm.ipMap[session.Location.IP]
		found := false
		for i, s := range sessions {
			if s.ID == session.ID {
				sessions[i] = session
				found = true
				break
			}
		}
		if !found {
			sm.ipMap[session.Location.IP] = append(sessions, session)
		}
	}
}

func (sm *SessionManager) RevokeSession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return
	}

	// Remove from sessions map
	delete(sm.sessions, sessionID)

	// Remove from IP map
	if session.Location != nil {
		sessions := sm.ipMap[session.Location.IP]
		for i, s := range sessions {
			if s.ID == sessionID {
				sm.ipMap[session.Location.IP] = append(sessions[:i], sessions[i+1:]...)
				break
			}
		}
	}
}

func (sm *SessionManager) GetActiveSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var active []*Session
	timeout, _ := time.ParseDuration(sm.config.SessionTimeout)

	for _, session := range sm.sessions {
		if time.Since(session.LastActivity) <= timeout {
			active = append(active, session)
		}
	}

	return active
}

func (sm *SessionManager) GetSessionsByIP(clientIP string) []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.ipMap[clientIP]
}

func (sm *SessionManager) GetActiveSessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0
	timeout, _ := time.ParseDuration(sm.config.SessionTimeout)

	for _, session := range sm.sessions {
		if time.Since(session.LastActivity) <= timeout {
			count++
		}
	}

	return count
}

func (sm *SessionManager) CleanupExpiredSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	timeout, _ := time.ParseDuration(sm.config.SessionTimeout)
	cutoff := time.Now().Add(-timeout)

	for sessionID, session := range sm.sessions {
		if session.LastActivity.Before(cutoff) {
			delete(sm.sessions, sessionID)
			
			// Clean up IP map
			if session.Location != nil {
				sessions := sm.ipMap[session.Location.IP]
				for i, s := range sessions {
					if s.ID == sessionID {
						sm.ipMap[session.Location.IP] = append(sessions[:i], sessions[i+1:]...)
						break
					}
				}
			}
		}
	}
}

func (sm *SessionManager) SaveState() error {
	// In production, would persist sessions to storage
	return nil
}

// AuditLogger handles audit logging
type AuditLogger struct {
	level    string
	logPath  string
	logFile  *os.File
	mu       sync.RWMutex
}

func NewAuditLogger(level, logPath string) *AuditLogger {
	return &AuditLogger{
		level:   level,
		logPath: logPath,
	}
}

func (al *AuditLogger) Initialize() error {
	// In production, would open log file
	return nil
}

func (al *AuditLogger) LogAccess(clientIP, path string, riskScore float64, session *Session) {
	// Simplified logging
	if al.level == "detailed" || al.level == "verbose" {
		userID := "anonymous"
		if session != nil {
			userID = session.UserID
		}
		
		fmt.Printf("AUDIT: Access granted - IP: %s, User: %s, Path: %s, Risk: %.3f\n", 
			clientIP, userID, path, riskScore)
	}
}

func (al *AuditLogger) LogHighRiskAccess(clientIP string, riskScore float64, path string) {
	fmt.Printf("AUDIT: High risk access - IP: %s, Path: %s, Risk: %.3f\n", 
		clientIP, path, riskScore)
}

func (al *AuditLogger) LogSegmentationBlock(clientIP, path, reason string) {
	fmt.Printf("AUDIT: Segmentation block - IP: %s, Path: %s, Reason: %s\n", 
		clientIP, path, reason)
}

func (al *AuditLogger) LogSessionRevoked(sessionID string, riskScore float64) {
	fmt.Printf("AUDIT: Session revoked - ID: %s, Risk: %.3f\n", sessionID, riskScore)
}

func (al *AuditLogger) LogKeyChange(fingerprint, clientIP, operation string) {
	fmt.Printf("AUDIT: Key change - Fingerprint: %s, IP: %s, Operation: %s\n", 
		fingerprint, clientIP, operation)
}

func (al *AuditLogger) LogShutdown() {
	fmt.Printf("AUDIT: Zero Trust plugin shutdown at %s\n", time.Now().Format(time.RFC3339))
}

func (al *AuditLogger) IsHealthy() bool {
	// Simple health check
	return true
}

// Utility functions

func generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func isPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}

	for _, cidr := range privateRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		ipAddr := net.ParseIP(ip)
		if ipAddr != nil && ipnet.Contains(ipAddr) {
			return true
		}
	}

	return false
}