package zerotrust

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
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
	TypingPattern      *TypingPattern
	MousePattern       *MousePattern
	NavigationPattern  *NavigationPattern
	LastUpdated        time.Time
}

// Location represents a geographic location
type Location struct {
	IP         string
	Country    string
	City       string
	Latitude   float64
	Longitude  float64
	ISP        string
	Confidence float64
}

// TimeRange represents a time period
type TimeRange struct {
	StartHour int
	EndHour   int
	DayOfWeek []time.Weekday
	Timezone  string
}

// TypingPattern represents keystroke dynamics
type TypingPattern struct {
	DwellTimes  []float64 // Time key is held down
	FlightTimes []float64 // Time between keystrokes
	Pressure    []float64 // Key pressure (if available)
	TypingSpeed float64   // WPM
	Rhythm      float64   // Consistency measure
}

// MousePattern represents mouse movement characteristics
type MousePattern struct {
	Velocity       float64
	Acceleration   float64
	ClickPatterns  []ClickPattern
	MovementCurves []Curve
	ScrollBehavior ScrollPattern
}

// NavigationPattern represents how a user navigates
type NavigationPattern struct {
	PageSequences    [][]string
	DwellTimes       map[string]time.Duration
	LinkClickPattern []string
	FormFillSpeed    time.Duration
}

// AuthResult represents an authentication verification result
type AuthResult struct {
	Authenticated bool
	Confidence    float64
	Reason        string
	Factors       []AuthFactor
	Timestamp     time.Time
}

// AuthProvider interface for different authentication methods
type AuthProvider interface {
	Name() string
	Verify(session *SessionContext, r *http.Request) (*AuthResult, error)
	GetStrength() int
}

// NewContinuousAuthenticator creates a new continuous authenticator
func NewContinuousAuthenticator(config *ZeroTrustConfig) *ContinuousAuthenticator {
	ca := &ContinuousAuthenticator{
		config:            config,
		behaviorBaselines: make(map[string]*BehaviorBaseline),
		authProviders:     make([]AuthProvider, 0),
	}

	// Initialize authentication providers
	ca.initAuthProviders()

	return ca
}

// initAuthProviders initializes available authentication providers
func (ca *ContinuousAuthenticator) initAuthProviders() {
	// Add default providers
	ca.authProviders = append(ca.authProviders,
		&SessionTokenProvider{},
		&BehavioralBiometricProvider{baselines: ca.behaviorBaselines},
		&DeviceFingerprintProvider{},
		&NetworkContextProvider{},
	)

	// Add optional providers based on config
	if ca.config.NetworkSegmentation.ServiceMesh.MutualTLSRequired {
		ca.authProviders = append(ca.authProviders, &CertificateAuthProvider{})
	}
}

// VerifySession performs continuous authentication verification
func (ca *ContinuousAuthenticator) VerifySession(session *SessionContext, r *http.Request) *AuthResult {
	result := &AuthResult{
		Authenticated: false,
		Timestamp:     time.Now(),
		Factors:       make([]AuthFactor, 0),
	}

	// Check session validity
	if !ca.isSessionValid(session) {
		result.Reason = "Session expired or invalid"
		return result
	}

	// Verify through each auth provider
	totalStrength := 0
	requiredStrength := ca.calculateRequiredStrength(session)
	successfulProviders := 0

	for _, provider := range ca.authProviders {
		providerResult, err := provider.Verify(session, r)
		if err != nil {
			continue
		}

		if providerResult.Authenticated {
			successfulProviders++
			totalStrength += provider.GetStrength()
			result.Factors = append(result.Factors, AuthFactor{
				Type:      provider.Name(),
				Verified:  true,
				Timestamp: time.Now(),
				Strength:  provider.GetStrength(),
			})
		}
	}

	// Determine if authentication is sufficient
	result.Authenticated = totalStrength >= requiredStrength && successfulProviders >= 2
	result.Confidence = float64(totalStrength) / float64(requiredStrength*2) // Normalize to 0-1

	if !result.Authenticated {
		result.Reason = fmt.Sprintf("Insufficient authentication strength: %d/%d", totalStrength, requiredStrength)
	}

	// Update behavioral baseline if authenticated
	if result.Authenticated {
		ca.updateBehaviorBaseline(session, r)
	}

	return result
}

// isSessionValid checks if a session is still valid
func (ca *ContinuousAuthenticator) isSessionValid(session *SessionContext) bool {
	// Check session age
	sessionTimeout, _ := time.ParseDuration(ca.config.SessionTimeout)
	if time.Since(session.CreatedAt) > sessionTimeout {
		return false
	}

	// Check inactivity timeout
	inactivityTimeout := 15 * time.Minute
	return time.Since(session.LastActivityAt) <= inactivityTimeout
}

// calculateRequiredStrength determines required auth strength based on context
func (ca *ContinuousAuthenticator) calculateRequiredStrength(session *SessionContext) int {
	baseStrength := 10

	// Increase requirements based on risk
	if session.RiskScore > 0.7 {
		baseStrength += 10
	} else if session.RiskScore > 0.5 {
		baseStrength += 5
	}

	// Increase for sensitive operations
	if session.Segment == "admin" || session.Segment == "sensitive" {
		baseStrength += 5
	}

	return baseStrength
}

// updateBehaviorBaseline updates the behavioral baseline for a user
func (ca *ContinuousAuthenticator) updateBehaviorBaseline(session *SessionContext, r *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	key := fmt.Sprintf("%s:%s", session.UserID, session.DeviceID)
	baseline, exists := ca.behaviorBaselines[key]
	if !exists {
		baseline = &BehaviorBaseline{
			UserID:   session.UserID,
			DeviceID: session.DeviceID,
		}
		ca.behaviorBaselines[key] = baseline
	}

	// Update location patterns
	// In production, would use GeoIP lookup
	location := Location{
		IP:      session.IPAddress,
		Country: "US", // Placeholder
		City:    "Unknown",
	}
	baseline.TypicalLocations = ca.updateLocationHistory(baseline.TypicalLocations, location)

	// Update access time patterns
	now := time.Now()
	timeRange := TimeRange{
		StartHour: now.Hour(),
		EndHour:   now.Hour() + 1,
		DayOfWeek: []time.Weekday{now.Weekday()},
		Timezone:  now.Location().String(),
	}
	baseline.TypicalAccessTimes = ca.updateTimePatterns(baseline.TypicalAccessTimes, timeRange)

	// Update resource access patterns
	baseline.TypicalResources = ca.updateResourcePatterns(baseline.TypicalResources, r.URL.Path)

	baseline.LastUpdated = time.Now()
}

// SessionTokenProvider verifies session tokens
type SessionTokenProvider struct{}

func (p *SessionTokenProvider) Name() string     { return "session_token" }
func (p *SessionTokenProvider) GetStrength() int { return 5 }

func (p *SessionTokenProvider) Verify(session *SessionContext, r *http.Request) (*AuthResult, error) {
	// Verify session token integrity
	expectedToken := p.generateSessionToken(session)
	providedToken := r.Header.Get("X-Session-Token")

	if providedToken == "" {
		// Check cookie
		if cookie, err := r.Cookie("session-token"); err == nil {
			providedToken = cookie.Value
		}
	}

	authenticated := subtle.ConstantTimeCompare([]byte(expectedToken), []byte(providedToken)) == 1

	return &AuthResult{
		Authenticated: authenticated,
		Confidence:    1.0,
	}, nil
}

func (p *SessionTokenProvider) generateSessionToken(session *SessionContext) string {
	h := hmac.New(sha256.New, []byte("session-secret")) // In production, use proper secret
	h.Write([]byte(session.SessionID))
	h.Write([]byte(session.UserID))
	h.Write([]byte(session.DeviceID))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// BehavioralBiometricProvider verifies behavioral patterns
type BehavioralBiometricProvider struct {
	baselines map[string]*BehaviorBaseline
}

func (p *BehavioralBiometricProvider) Name() string     { return "behavioral_biometric" }
func (p *BehavioralBiometricProvider) GetStrength() int { return 8 }

func (p *BehavioralBiometricProvider) Verify(session *SessionContext, r *http.Request) (*AuthResult, error) {
	key := fmt.Sprintf("%s:%s", session.UserID, session.DeviceID)
	baseline, exists := p.baselines[key]
	if !exists {
		// No baseline yet, allow but with low confidence
		return &AuthResult{
			Authenticated: true,
			Confidence:    0.3,
		}, nil
	}

	// Compare current behavior with baseline
	score := p.compareBehavior(session, baseline, r)

	return &AuthResult{
		Authenticated: score > 0.6,
		Confidence:    score,
	}, nil
}

func (p *BehavioralBiometricProvider) compareBehavior(session *SessionContext, baseline *BehaviorBaseline, r *http.Request) float64 {
	score := 1.0

	// Check if location is typical
	locationMatch := false
	for _, loc := range baseline.TypicalLocations {
		if loc.IP == session.IPAddress {
			locationMatch = true
			break
		}
	}
	if !locationMatch && len(baseline.TypicalLocations) > 0 {
		score *= 0.7
	}

	// Check if access time is typical
	now := time.Now()
	timeMatch := false
	for _, timeRange := range baseline.TypicalAccessTimes {
		if now.Hour() >= timeRange.StartHour && now.Hour() <= timeRange.EndHour {
			for _, day := range timeRange.DayOfWeek {
				if day == now.Weekday() {
					timeMatch = true
					break
				}
			}
		}
	}
	if !timeMatch && len(baseline.TypicalAccessTimes) > 0 {
		score *= 0.8
	}

	// Check if resource access is typical
	resourceMatch := false
	for _, resource := range baseline.TypicalResources {
		if strings.HasPrefix(r.URL.Path, resource) {
			resourceMatch = true
			break
		}
	}
	if !resourceMatch && len(baseline.TypicalResources) > 5 {
		score *= 0.9
	}

	return score
}

// DeviceFingerprintProvider verifies device fingerprints
type DeviceFingerprintProvider struct{}

func (p *DeviceFingerprintProvider) Name() string     { return "device_fingerprint" }
func (p *DeviceFingerprintProvider) GetStrength() int { return 7 }

func (p *DeviceFingerprintProvider) Verify(session *SessionContext, r *http.Request) (*AuthResult, error) {
	if session.DeviceProfile == nil {
		return &AuthResult{
			Authenticated: false,
			Confidence:    0,
		}, nil
	}

	// Calculate current fingerprint
	currentFingerprint := p.calculateFingerprint(r)

	// Compare with stored fingerprint
	match := currentFingerprint == session.DeviceProfile.Fingerprint
	confidence := 1.0

	if !match {
		// Check if partial match (some components changed)
		similarity := p.calculateSimilarity(currentFingerprint, session.DeviceProfile.Fingerprint)
		if similarity > 0.7 {
			match = true
			confidence = similarity
		}
	}

	return &AuthResult{
		Authenticated: match,
		Confidence:    confidence,
	}, nil
}

func (p *DeviceFingerprintProvider) calculateFingerprint(r *http.Request) string {
	h := sha256.New()

	// User-Agent
	h.Write([]byte(r.Header.Get("User-Agent")))

	// Accept headers
	h.Write([]byte(r.Header.Get("Accept")))
	h.Write([]byte(r.Header.Get("Accept-Language")))
	h.Write([]byte(r.Header.Get("Accept-Encoding")))

	// Additional headers that form device fingerprint
	h.Write([]byte(r.Header.Get("DNT")))
	h.Write([]byte(r.Header.Get("Connection")))

	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

func (p *DeviceFingerprintProvider) calculateSimilarity(fp1, fp2 string) float64 {
	// Simple similarity calculation
	if fp1 == fp2 {
		return 1.0
	}

	// Calculate Levenshtein distance or similar metric
	// Simplified for example
	maxLen := len(fp1)
	if len(fp2) > maxLen {
		maxLen = len(fp2)
	}

	matches := 0
	minLen := len(fp1)
	if len(fp2) < minLen {
		minLen = len(fp2)
	}

	for i := 0; i < minLen; i++ {
		if fp1[i] == fp2[i] {
			matches++
		}
	}

	return float64(matches) / float64(maxLen)
}

// NetworkContextProvider verifies network context
type NetworkContextProvider struct{}

func (p *NetworkContextProvider) Name() string     { return "network_context" }
func (p *NetworkContextProvider) GetStrength() int { return 6 }

func (p *NetworkContextProvider) Verify(session *SessionContext, r *http.Request) (*AuthResult, error) {
	// Verify network characteristics
	score := 1.0

	// Check if IP changed during session
	currentIP := extractIPFromRequest(r)
	if currentIP != session.IPAddress {
		// IP change detected
		if p.isReasonableIPChange(session.IPAddress, currentIP) {
			score *= 0.8 // Minor penalty for reasonable change
		} else {
			score *= 0.3 // Major penalty for suspicious change
		}
	}

	// Check for proxy/VPN indicators
	if p.detectProxy(r) {
		score *= 0.7
	}

	// Check for TLS fingerprint consistency
	if r.TLS != nil && session.DeviceProfile != nil {
		currentTLSFP := p.calculateTLSFingerprint(r.TLS)
		if currentTLSFP != session.DeviceProfile.TLSFingerprint {
			score *= 0.8
		}
	}

	return &AuthResult{
		Authenticated: score > 0.5,
		Confidence:    score,
	}, nil
}

func (p *NetworkContextProvider) isReasonableIPChange(oldIP, newIP string) bool {
	// Check if IPs are in same subnet or ASN
	// Simplified for example
	oldParts := strings.Split(oldIP, ".")
	newParts := strings.Split(newIP, ".")

	if len(oldParts) != 4 || len(newParts) != 4 {
		return false
	}

	// Check if same /24 subnet
	return oldParts[0] == newParts[0] &&
		oldParts[1] == newParts[1] &&
		oldParts[2] == newParts[2]
}

func (p *NetworkContextProvider) detectProxy(r *http.Request) bool {
	// Check for proxy headers
	proxyHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"Via",
		"X-Proxy-ID",
		"X-Forwarded-Host",
	}

	proxyCount := 0
	for _, header := range proxyHeaders {
		if r.Header.Get(header) != "" {
			proxyCount++
		}
	}

	return proxyCount >= 2
}

func (p *NetworkContextProvider) calculateTLSFingerprint(tls *tls.ConnectionState) string {
	if tls == nil {
		return ""
	}

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d", tls.Version)))
	h.Write([]byte(fmt.Sprintf("%d", tls.CipherSuite)))
	h.Write([]byte(tls.NegotiatedProtocol))

	return base64.URLEncoding.EncodeToString(h.Sum(nil))[:16]
}

// CertificateAuthProvider provides certificate-based authentication
type CertificateAuthProvider struct{}

func (p *CertificateAuthProvider) Name() string     { return "certificate" }
func (p *CertificateAuthProvider) GetStrength() int { return 10 }

func (p *CertificateAuthProvider) Verify(session *SessionContext, r *http.Request) (*AuthResult, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return &AuthResult{
			Authenticated: false,
			Confidence:    0,
			Reason:        "No client certificate provided",
		}, nil
	}

	cert := r.TLS.PeerCertificates[0]

	// Verify certificate validity
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return &AuthResult{
			Authenticated: false,
			Confidence:    0,
			Reason:        "Certificate expired or not yet valid",
		}, nil
	}

	// Verify certificate subject matches session
	certUser := cert.Subject.CommonName
	if certUser != session.UserID {
		return &AuthResult{
			Authenticated: false,
			Confidence:    0,
			Reason:        "Certificate subject mismatch",
		}, nil
	}

	// Additional certificate validation would go here
	// (CA verification, revocation checking, etc.)

	return &AuthResult{
		Authenticated: true,
		Confidence:    1.0,
	}, nil
}

// Helper functions for updating baselines

func (ca *ContinuousAuthenticator) updateLocationHistory(history []Location, newLoc Location) []Location {
	// Check if location already exists
	for i, loc := range history {
		if loc.IP == newLoc.IP {
			// Move to front (most recent)
			history = append([]Location{newLoc}, append(history[:i], history[i+1:]...)...)
			return history
		}
	}

	// Add new location
	history = append([]Location{newLoc}, history...)

	// Keep only recent locations
	if len(history) > 10 {
		history = history[:10]
	}

	return history
}

func (ca *ContinuousAuthenticator) updateTimePatterns(patterns []TimeRange, newRange TimeRange) []TimeRange {
	// Merge overlapping time ranges
	for i, pattern := range patterns {
		if pattern.StartHour <= newRange.EndHour && pattern.EndHour >= newRange.StartHour {
			// Overlapping, merge them
			if newRange.StartHour < pattern.StartHour {
				pattern.StartHour = newRange.StartHour
			}
			if newRange.EndHour > pattern.EndHour {
				pattern.EndHour = newRange.EndHour
			}

			// Merge days of week
			dayMap := make(map[time.Weekday]bool)
			for _, day := range pattern.DayOfWeek {
				dayMap[day] = true
			}
			for _, day := range newRange.DayOfWeek {
				dayMap[day] = true
			}

			pattern.DayOfWeek = make([]time.Weekday, 0, len(dayMap))
			for day := range dayMap {
				pattern.DayOfWeek = append(pattern.DayOfWeek, day)
			}

			patterns[i] = pattern
			return patterns
		}
	}

	// No overlap, add new range
	patterns = append(patterns, newRange)

	// Keep reasonable number of patterns
	if len(patterns) > 20 {
		patterns = patterns[:20]
	}

	return patterns
}

func (ca *ContinuousAuthenticator) updateResourcePatterns(resources []string, newResource string) []string {
	// Extract base path
	basePath := newResource
	if idx := strings.Index(newResource[1:], "/"); idx > 0 {
		basePath = newResource[:idx+1]
	}

	// Check if already tracked
	for _, resource := range resources {
		if resource == basePath {
			return resources
		}
	}

	// Add new resource
	resources = append([]string{basePath}, resources...)

	// Keep most accessed resources
	if len(resources) > 50 {
		resources = resources[:50]
	}

	return resources
}

// Helper function to extract IP from request
func extractIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

// ClickPattern represents mouse click characteristics
type ClickPattern struct {
	Duration time.Duration
	Pressure float64
	Area     float64
}

// Curve represents a movement curve
type Curve struct {
	Points     []Point
	Smoothness float64
}

// Point represents a 2D point
type Point struct {
	X, Y float64
	Time time.Time
}

// ScrollPattern represents scrolling behavior
type ScrollPattern struct {
	Speed      float64
	Smoothness float64
	Direction  string
}
