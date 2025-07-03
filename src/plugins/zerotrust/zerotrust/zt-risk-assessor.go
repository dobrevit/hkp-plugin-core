package zerotrust

import (
	"math"
	"net/http"
	"strings"
	"time"
)

// RiskAssessor evaluates security risk for sessions and requests
type RiskAssessor struct {
	riskFactors     []RiskFactor
	historicalData  map[string]*RiskHistory
	threatIntel     *ThreatIntelligence
	anomalyDetector *AnomalyDetector
}

// RiskFactor represents a factor that contributes to risk score
type RiskFactor struct {
	Name     string
	Weight   float64
	Evaluate func(*SessionContext, *http.Request) float64
}

// RiskHistory tracks historical risk data for analysis
type RiskHistory struct {
	SessionID     string
	RiskScores    []TimedScore
	Incidents     []SecurityIncident
	LastEvaluated time.Time
}

// TimedScore represents a risk score at a point in time
type TimedScore struct {
	Score     float64
	Timestamp time.Time
	Factors   map[string]float64
}

// SecurityIncident represents a security event
type SecurityIncident struct {
	Type        string
	Severity    string
	Description string
	Timestamp   time.Time
}

// ThreatIntelligence provides threat data
type ThreatIntelligence struct {
	MaliciousIPs   map[string]ThreatInfo
	KnownAttackers map[string]AttackerProfile
	VulnerableUAs  []string
	ThreatPatterns []ThreatPattern
}

// ThreatInfo contains information about a threat
type ThreatInfo struct {
	ThreatLevel string
	Category    string
	LastSeen    time.Time
	Confidence  float64
}

// AttackerProfile represents known attacker characteristics
type AttackerProfile struct {
	Techniques []string
	Targets    []string
	RiskLevel  float64
}

// ThreatPattern represents attack patterns to detect
type ThreatPattern struct {
	Name       string
	Pattern    string
	Severity   float64
	Indicators []string
}

// AnomalyDetector detects anomalous behavior
type AnomalyDetector struct {
	normalProfiles map[string]*NormalProfile
	threshold      float64
}

// NormalProfile represents normal behavior profile
type NormalProfile struct {
	RequestRate      float64
	PathDistribution map[string]float64
	MethodUsage      map[string]float64
	ErrorRate        float64
	ResponseTimes    []time.Duration
}

// NewRiskAssessor creates a new risk assessor
func NewRiskAssessor() *RiskAssessor {
	ra := &RiskAssessor{
		historicalData:  make(map[string]*RiskHistory),
		threatIntel:     initializeThreatIntel(),
		anomalyDetector: newAnomalyDetector(),
	}

	// Initialize risk factors
	ra.initializeRiskFactors()

	return ra
}

// initializeThreatIntel sets up threat intelligence data
func initializeThreatIntel() *ThreatIntelligence {
	return &ThreatIntelligence{
		MaliciousIPs:   make(map[string]ThreatInfo),
		KnownAttackers: make(map[string]AttackerProfile),
		VulnerableUAs: []string{
			"Mozilla/4.0",   // Old browsers
			"Python-urllib", // Scripted access
			"curl", "wget",  // Command line tools
		},
		ThreatPatterns: []ThreatPattern{
			{
				Name:       "SQL Injection",
				Pattern:    "(?i)(union|select|insert|update|delete|drop).*(?i)(from|where)",
				Severity:   0.9,
				Indicators: []string{"'", "\"", "--", "/*", "*/"},
			},
			{
				Name:       "Path Traversal",
				Pattern:    `\.\.\/|\.\.\\`,
				Severity:   0.8,
				Indicators: []string{"../", "..\\", "%2e%2e"},
			},
			{
				Name:       "Command Injection",
				Pattern:    `[;&|]|\$\(|` + "`",
				Severity:   0.9,
				Indicators: []string{";", "|", "$", "`"},
			},
		},
	}
}

// newAnomalyDetector creates an anomaly detector
func newAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		normalProfiles: make(map[string]*NormalProfile),
		threshold:      2.0, // Standard deviations
	}
}

// initializeRiskFactors sets up risk evaluation factors
func (ra *RiskAssessor) initializeRiskFactors() {
	ra.riskFactors = []RiskFactor{
		{
			Name:   "location_risk",
			Weight: 0.15,
			Evaluate: func(s *SessionContext, r *http.Request) float64 {
				return ra.evaluateLocationRisk(s, r)
			},
		},
		{
			Name:   "time_risk",
			Weight: 0.10,
			Evaluate: func(s *SessionContext, r *http.Request) float64 {
				return ra.evaluateTimeRisk(s, r)
			},
		},
		{
			Name:   "device_risk",
			Weight: 0.15,
			Evaluate: func(s *SessionContext, r *http.Request) float64 {
				return ra.evaluateDeviceRisk(s, r)
			},
		},
		{
			Name:   "behavior_risk",
			Weight: 0.20,
			Evaluate: func(s *SessionContext, r *http.Request) float64 {
				return ra.evaluateBehaviorRisk(s, r)
			},
		},
		{
			Name:   "threat_intel_risk",
			Weight: 0.15,
			Evaluate: func(s *SessionContext, r *http.Request) float64 {
				return ra.evaluateThreatIntelRisk(s, r)
			},
		},
		{
			Name:   "auth_strength_risk",
			Weight: 0.10,
			Evaluate: func(s *SessionContext, r *http.Request) float64 {
				return ra.evaluateAuthStrengthRisk(s, r)
			},
		},
		{
			Name:   "anomaly_risk",
			Weight: 0.15,
			Evaluate: func(s *SessionContext, r *http.Request) float64 {
				return ra.evaluateAnomalyRisk(s, r)
			},
		},
	}
}

// AssessRisk calculates the overall risk score for a session
func (ra *RiskAssessor) AssessRisk(session *SessionContext, r *http.Request) float64 {
	factorScores := make(map[string]float64)
	weightedSum := 0.0
	totalWeight := 0.0

	// Evaluate each risk factor
	for _, factor := range ra.riskFactors {
		score := factor.Evaluate(session, r)
		factorScores[factor.Name] = score
		weightedSum += score * factor.Weight
		totalWeight += factor.Weight
	}

	// Calculate base risk score
	baseRisk := weightedSum / totalWeight

	// Apply modifiers based on context
	finalRisk := ra.applyRiskModifiers(baseRisk, session, r)

	// Update historical data
	ra.updateRiskHistory(session.SessionID, finalRisk, factorScores)

	// Ensure risk score is in valid range [0, 1]
	return math.Max(0, math.Min(1, finalRisk))
}

// ReassessRisk performs continuous risk reassessment
func (ra *RiskAssessor) ReassessRisk(session *SessionContext) float64 {
	// Get historical risk data
	history, exists := ra.historicalData[session.SessionID]
	if !exists {
		return session.RiskScore // No change if no history
	}

	// Check for risk escalation patterns
	if ra.detectRiskEscalation(history) {
		return math.Min(1.0, session.RiskScore*1.5)
	}

	// Check for risk de-escalation
	if ra.detectRiskDeescalation(history) {
		return math.Max(0.1, session.RiskScore*0.8)
	}

	// Apply time-based decay
	timeSinceLastIncident := ra.getTimeSinceLastIncident(history)
	if timeSinceLastIncident > 30*time.Minute {
		return math.Max(0.1, session.RiskScore*0.95)
	}

	return session.RiskScore
}

// Risk evaluation functions

func (ra *RiskAssessor) evaluateLocationRisk(s *SessionContext, r *http.Request) float64 {
	risk := 0.0

	// Check if IP is in threat intelligence
	if threat, exists := ra.threatIntel.MaliciousIPs[s.IPAddress]; exists {
		risk += threat.Confidence
	}

	// Check for geographic anomalies
	if ra.isGeographicAnomaly(s, r) {
		risk += 0.3
	}

	// Check for VPN/Proxy usage
	if ra.detectVPNProxy(r) {
		risk += 0.2
	}

	return math.Min(1.0, risk)
}

func (ra *RiskAssessor) evaluateTimeRisk(s *SessionContext, r *http.Request) float64 {
	now := time.Now()
	risk := 0.0

	// Off-hours access (customize based on organization)
	hour := now.Hour()
	if hour < 6 || hour > 22 {
		risk += 0.3
	}

	// Weekend access
	if now.Weekday() == time.Saturday || now.Weekday() == time.Sunday {
		risk += 0.2
	}

	// Rapid session creation
	if time.Since(s.CreatedAt) < 1*time.Minute && len(s.AccessDecisions) > 10 {
		risk += 0.4
	}

	return math.Min(1.0, risk)
}

func (ra *RiskAssessor) evaluateDeviceRisk(s *SessionContext, r *http.Request) float64 {
	if s.DeviceProfile == nil {
		return 0.5 // Unknown device
	}

	risk := 0.0

	// Check for vulnerable user agents
	ua := r.Header.Get("User-Agent")
	for _, vulnUA := range ra.threatIntel.VulnerableUAs {
		if strings.Contains(ua, vulnUA) {
			risk += 0.3
			break
		}
	}

	// New device
	if time.Since(s.DeviceProfile.LastSeen) < 1*time.Hour {
		risk += 0.2
	}

	// Low device trust score
	if s.DeviceProfile.TrustScore < 0.5 {
		risk += 0.3
	}

	return math.Min(1.0, risk)
}

func (ra *RiskAssessor) evaluateBehaviorRisk(s *SessionContext, r *http.Request) float64 {
	risk := 0.0

	// Check access patterns
	recentDecisions := ra.getRecentDecisions(s, 5*time.Minute)
	deniedCount := 0
	for _, decision := range recentDecisions {
		if !decision.Allowed {
			deniedCount++
		}
	}

	if deniedCount > 3 {
		risk += 0.4
	}

	// Check for suspicious patterns
	if ra.detectSuspiciousPatterns(s, r) {
		risk += 0.3
	}

	// Check request velocity
	requestRate := float64(len(recentDecisions)) / 5.0 // per minute
	if requestRate > 20 {
		risk += 0.3
	}

	return math.Min(1.0, risk)
}

func (ra *RiskAssessor) evaluateThreatIntelRisk(s *SessionContext, r *http.Request) float64 {
	risk := 0.0

	// Check URL for threat patterns
	url := r.URL.String()
	body := ra.getRequestBody(r)

	for _, pattern := range ra.threatIntel.ThreatPatterns {
		if strings.Contains(url, pattern.Pattern) || strings.Contains(body, pattern.Pattern) {
			risk += pattern.Severity
		}

		// Check indicators
		for _, indicator := range pattern.Indicators {
			if strings.Contains(url, indicator) || strings.Contains(body, indicator) {
				risk += 0.1
			}
		}
	}

	return math.Min(1.0, risk)
}

func (ra *RiskAssessor) evaluateAuthStrengthRisk(s *SessionContext, r *http.Request) float64 {
	if len(s.AuthFactors) == 0 {
		return 1.0 // No authentication
	}

	// Calculate total auth strength
	totalStrength := 0
	for _, factor := range s.AuthFactors {
		if factor.Verified {
			totalStrength += factor.Strength
		}
	}

	// Higher risk for weaker authentication
	if totalStrength < 5 {
		return 0.8
	} else if totalStrength < 10 {
		return 0.5
	} else if totalStrength < 15 {
		return 0.3
	}

	return 0.1
}

func (ra *RiskAssessor) evaluateAnomalyRisk(s *SessionContext, r *http.Request) float64 {
	profile, exists := ra.anomalyDetector.normalProfiles[s.UserID]
	if !exists {
		// No profile yet, moderate risk
		return 0.3
	}

	// Calculate anomaly score
	anomalyScore := ra.anomalyDetector.calculateAnomalyScore(profile, s, r)

	// Convert to risk (higher anomaly = higher risk)
	return math.Min(1.0, anomalyScore/ra.anomalyDetector.threshold)
}

// Helper functions

func (ra *RiskAssessor) applyRiskModifiers(baseRisk float64, session *SessionContext, r *http.Request) float64 {
	risk := baseRisk

	// Increase risk for sensitive operations
	if strings.Contains(r.URL.Path, "/admin") || strings.Contains(r.URL.Path, "/api/v1/keys") {
		risk *= 1.2
	}

	// Increase risk for state-changing operations
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
		risk *= 1.1
	}

	// Decrease risk for established sessions
	sessionAge := time.Since(session.CreatedAt)
	if sessionAge > 1*time.Hour && session.TrustLevel >= TrustLevelHigh {
		risk *= 0.9
	}

	return risk
}

func (ra *RiskAssessor) updateRiskHistory(sessionID string, score float64, factors map[string]float64) {
	history, exists := ra.historicalData[sessionID]
	if !exists {
		history = &RiskHistory{
			SessionID: sessionID,
		}
		ra.historicalData[sessionID] = history
	}

	history.RiskScores = append(history.RiskScores, TimedScore{
		Score:     score,
		Timestamp: time.Now(),
		Factors:   factors,
	})

	// Keep only recent scores
	if len(history.RiskScores) > 100 {
		history.RiskScores = history.RiskScores[len(history.RiskScores)-100:]
	}

	history.LastEvaluated = time.Now()
}

func (ra *RiskAssessor) detectRiskEscalation(history *RiskHistory) bool {
	if len(history.RiskScores) < 3 {
		return false
	}

	// Check if risk is increasing
	scores := history.RiskScores[len(history.RiskScores)-3:]
	return scores[0].Score < scores[1].Score && scores[1].Score < scores[2].Score
}

func (ra *RiskAssessor) detectRiskDeescalation(history *RiskHistory) bool {
	if len(history.RiskScores) < 5 {
		return false
	}

	// Check if risk is consistently decreasing
	scores := history.RiskScores[len(history.RiskScores)-5:]
	decreasing := true
	for i := 1; i < len(scores); i++ {
		if scores[i].Score >= scores[i-1].Score {
			decreasing = false
			break
		}
	}

	return decreasing
}

func (ra *RiskAssessor) getTimeSinceLastIncident(history *RiskHistory) time.Duration {
	if len(history.Incidents) == 0 {
		return 24 * time.Hour // No incidents
	}

	lastIncident := history.Incidents[len(history.Incidents)-1]
	return time.Since(lastIncident.Timestamp)
}

func (ra *RiskAssessor) isGeographicAnomaly(s *SessionContext, r *http.Request) bool {
	// Simplified geographic anomaly detection
	// In production, would use GeoIP database
	return false
}

func (ra *RiskAssessor) detectVPNProxy(r *http.Request) bool {
	// Check for common proxy headers
	proxyHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"Via",
		"X-Proxy-ID",
	}

	count := 0
	for _, header := range proxyHeaders {
		if r.Header.Get(header) != "" {
			count++
		}
	}

	return count >= 2
}

func (ra *RiskAssessor) getRecentDecisions(s *SessionContext, duration time.Duration) []AccessDecision {
	cutoff := time.Now().Add(-duration)
	recent := make([]AccessDecision, 0)

	for _, decision := range s.AccessDecisions {
		if decision.Timestamp.After(cutoff) {
			recent = append(recent, decision)
		}
	}

	return recent
}

func (ra *RiskAssessor) detectSuspiciousPatterns(s *SessionContext, r *http.Request) bool {
	// Check for automated behavior patterns
	if len(s.AccessDecisions) < 10 {
		return false
	}

	// Check for regular timing intervals
	intervals := make([]time.Duration, 0)
	for i := 1; i < len(s.AccessDecisions); i++ {
		interval := s.AccessDecisions[i].Timestamp.Sub(s.AccessDecisions[i-1].Timestamp)
		intervals = append(intervals, interval)
	}

	// Calculate variance
	if len(intervals) > 5 {
		variance := ra.calculateVariance(intervals)
		// Low variance indicates automated behavior
		if variance < 100 { // milliseconds squared
			return true
		}
	}

	// Check for repeated access patterns
	resources := make(map[string]int)
	for _, decision := range s.AccessDecisions {
		resources[decision.Resource]++
	}

	// High repetition of same resource
	for _, count := range resources {
		if count > len(s.AccessDecisions)/2 {
			return true
		}
	}

	return false
}

func (ra *RiskAssessor) calculateVariance(intervals []time.Duration) float64 {
	if len(intervals) == 0 {
		return 0
	}

	// Calculate mean
	var sum time.Duration
	for _, interval := range intervals {
		sum += interval
	}
	mean := sum / time.Duration(len(intervals))

	// Calculate variance
	var variance float64
	for _, interval := range intervals {
		diff := interval - mean
		variance += float64(diff.Milliseconds() * diff.Milliseconds())
	}

	return variance / float64(len(intervals))
}

func (ra *RiskAssessor) getRequestBody(r *http.Request) string {
	// In a real implementation, would read and restore body
	// For now, return empty string
	return ""
}

// AnomalyDetector methods

func (ad *AnomalyDetector) calculateAnomalyScore(profile *NormalProfile, s *SessionContext, r *http.Request) float64 {
	score := 0.0

	// Request rate anomaly
	currentRate := float64(len(s.AccessDecisions)) / time.Since(s.CreatedAt).Minutes()
	if currentRate > profile.RequestRate*2 {
		score += (currentRate - profile.RequestRate) / profile.RequestRate
	}

	// Path distribution anomaly
	path := r.URL.Path
	expectedFreq, exists := profile.PathDistribution[path]
	if !exists {
		score += 1.0 // Unknown path
	} else if expectedFreq < 0.01 {
		score += 0.5 // Rare path
	}

	// Method usage anomaly
	method := r.Method
	expectedMethodFreq, exists := profile.MethodUsage[method]
	if !exists {
		score += 0.5
	} else if expectedMethodFreq < 0.05 && method != "GET" {
		score += 0.3
	}

	return score
}

// RecordIncident records a security incident
func (ra *RiskAssessor) RecordIncident(sessionID string, incidentType string, severity string, description string) {
	history, exists := ra.historicalData[sessionID]
	if !exists {
		history = &RiskHistory{
			SessionID: sessionID,
		}
		ra.historicalData[sessionID] = history
	}

	incident := SecurityIncident{
		Type:        incidentType,
		Severity:    severity,
		Description: description,
		Timestamp:   time.Now(),
	}

	history.Incidents = append(history.Incidents, incident)

	// Keep only recent incidents
	if len(history.Incidents) > 50 {
		history.Incidents = history.Incidents[len(history.Incidents)-50:]
	}
}
