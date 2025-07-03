package zerotrust

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AdaptivePolicyEngine manages dynamic security policies
type AdaptivePolicyEngine struct {
	config        AdaptivePolicyConfig
	policies      map[string]*SecurityPolicy
	policyHistory map[string][]*PolicyDecision
	learningData  *LearningData
	mu            sync.RWMutex
}

// SecurityPolicy represents a security access policy
type SecurityPolicy struct {
	ID              string
	Name            string
	Description     string
	Priority        int
	Conditions      []PolicyCondition
	Actions         []PolicyAction
	RiskThreshold   float64
	RequiredFactors []string
	Enabled         bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// PolicyCondition represents a condition for policy evaluation
type PolicyCondition struct {
	Type     string // resource, time, location, device, risk
	Operator string // equals, contains, greater_than, less_than, regex
	Value    interface{}
}

// PolicyAction represents an action to take when policy matches
type PolicyAction struct {
	Type   string // allow, deny, challenge, step_up
	Params map[string]interface{}
}

// PolicyDecision represents a policy evaluation result
type PolicyDecision struct {
	PolicyID   string
	Matched    bool
	Action     string
	Timestamp  time.Time
	Confidence float64
}

// LearningData tracks patterns for policy adaptation
type LearningData struct {
	AccessPatterns map[string]*AccessPattern
	ThreatPatterns map[string]*ThreatPattern
	UserBehaviors  map[string]*UserBehavior
	LastUpdate     time.Time
}

// AccessPattern represents learned access patterns
type AccessPattern struct {
	Resource         string
	Methods          map[string]int
	SuccessRate      float64
	AverageRiskScore float64
	TimeDistribution map[int]int // hour -> count
}

// UserBehavior represents learned user behavior
type UserBehavior struct {
	UserID           string
	TypicalResources []string
	RiskProfile      RiskProfile
	AccessSchedule   []TimeRange
}

// RiskProfile represents risk characteristics
type RiskProfile struct {
	AverageRisk    float64
	MaxRisk        float64
	RiskVolatility float64
	IncidentCount  int
}

// NewAdaptivePolicyEngine creates a new policy engine
func NewAdaptivePolicyEngine(config AdaptivePolicyConfig) *AdaptivePolicyEngine {
	ape := &AdaptivePolicyEngine{
		config:        config,
		policies:      make(map[string]*SecurityPolicy),
		policyHistory: make(map[string][]*PolicyDecision),
		learningData: &LearningData{
			AccessPatterns: make(map[string]*AccessPattern),
			ThreatPatterns: make(map[string]*ThreatPattern),
			UserBehaviors:  make(map[string]*UserBehavior),
		},
	}

	// Initialize default policies
	ape.initializeDefaultPolicies()

	return ape
}

// initializeDefaultPolicies sets up baseline security policies
func (ape *AdaptivePolicyEngine) initializeDefaultPolicies() {
	// High-risk access policy
	ape.policies["high_risk_deny"] = &SecurityPolicy{
		ID:          "high_risk_deny",
		Name:        "Deny High Risk Access",
		Description: "Block access when risk score exceeds threshold",
		Priority:    100,
		Conditions: []PolicyCondition{
			{Type: "risk", Operator: "greater_than", Value: 0.8},
		},
		Actions: []PolicyAction{
			{Type: "deny", Params: map[string]interface{}{"reason": "High risk detected"}},
		},
		RiskThreshold: 0.8,
		Enabled:       true,
		CreatedAt:     time.Now(),
	}

	// Admin access policy
	ape.policies["admin_mfa"] = &SecurityPolicy{
		ID:          "admin_mfa",
		Name:        "Admin MFA Requirement",
		Description: "Require MFA for administrative access",
		Priority:    90,
		Conditions: []PolicyCondition{
			{Type: "resource", Operator: "contains", Value: "/admin"},
		},
		Actions: []PolicyAction{
			{Type: "step_up", Params: map[string]interface{}{"factors": []string{"mfa"}}},
		},
		RequiredFactors: []string{"password", "mfa"},
		Enabled:         true,
		CreatedAt:       time.Now(),
	}

	// Off-hours access policy
	ape.policies["off_hours_restrict"] = &SecurityPolicy{
		ID:          "off_hours_restrict",
		Name:        "Off-Hours Access Restriction",
		Description: "Restrict access during off-hours",
		Priority:    80,
		Conditions: []PolicyCondition{
			{Type: "time", Operator: "outside_range", Value: []int{6, 22}}, // 6 AM - 10 PM
		},
		Actions: []PolicyAction{
			{Type: "challenge", Params: map[string]interface{}{"type": "reason"}},
		},
		RiskThreshold: 0.5,
		Enabled:       true,
		CreatedAt:     time.Now(),
	}

	// Anomalous location policy
	ape.policies["location_anomaly"] = &SecurityPolicy{
		ID:          "location_anomaly",
		Name:        "Location Anomaly Detection",
		Description: "Challenge access from new locations",
		Priority:    70,
		Conditions: []PolicyCondition{
			{Type: "location", Operator: "new", Value: true},
		},
		Actions: []PolicyAction{
			{Type: "challenge", Params: map[string]interface{}{"type": "verification"}},
		},
		Enabled:   true,
		CreatedAt: time.Now(),
	}
}

// EvaluateAccess evaluates all policies for an access request
func (ape *AdaptivePolicyEngine) EvaluateAccess(session *SessionContext, r *http.Request) AccessDecision {
	ape.mu.RLock()
	defer ape.mu.RUnlock()

	// Sort policies by priority
	sortedPolicies := ape.getSortedPolicies()

	// Evaluate each policy
	for _, policy := range sortedPolicies {
		if !policy.Enabled {
			continue
		}

		if ape.evaluatePolicy(policy, session, r) {
			// Policy matched, apply actions
			action := ape.applyPolicyActions(policy, session, r)

			// Record decision
			decision := &PolicyDecision{
				PolicyID:   policy.ID,
				Matched:    true,
				Action:     action.Type,
				Timestamp:  time.Now(),
				Confidence: ape.calculateConfidence(policy, session),
			}

			ape.recordDecision(session.SessionID, decision)

			// Return access decision
			return AccessDecision{
				Resource:      r.URL.Path,
				Action:        r.Method,
				Allowed:       action.Type == "allow",
				Reason:        ape.formatReason(policy, action),
				RiskScore:     session.RiskScore,
				Timestamp:     time.Now(),
				PolicyApplied: policy.Name,
			}
		}
	}

	// No policy matched, apply default
	return ape.applyDefaultPolicy(session, r)
}

// evaluatePolicy checks if a policy matches the current context
func (ape *AdaptivePolicyEngine) evaluatePolicy(policy *SecurityPolicy, session *SessionContext, r *http.Request) bool {
	// Check risk threshold first
	if policy.RiskThreshold > 0 && session.RiskScore > policy.RiskThreshold {
		return true
	}

	// Check required auth factors
	if len(policy.RequiredFactors) > 0 {
		if !ape.hasRequiredFactors(session, policy.RequiredFactors) {
			return true // Policy applies because factors are missing
		}
	}

	// Evaluate all conditions
	for _, condition := range policy.Conditions {
		if !ape.evaluateCondition(condition, session, r) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a single policy condition
func (ape *AdaptivePolicyEngine) evaluateCondition(condition PolicyCondition, session *SessionContext, r *http.Request) bool {
	switch condition.Type {
	case "resource":
		return ape.evaluateResourceCondition(condition, r.URL.Path)
	case "time":
		return ape.evaluateTimeCondition(condition)
	case "location":
		return ape.evaluateLocationCondition(condition, session)
	case "device":
		return ape.evaluateDeviceCondition(condition, session)
	case "risk":
		return ape.evaluateRiskCondition(condition, session.RiskScore)
	case "method":
		return ape.evaluateMethodCondition(condition, r.Method)
	default:
		return false
	}
}

// Condition evaluation helpers

func (ape *AdaptivePolicyEngine) evaluateResourceCondition(condition PolicyCondition, resource string) bool {
	value, ok := condition.Value.(string)
	if !ok {
		return false
	}

	switch condition.Operator {
	case "equals":
		return resource == value
	case "contains":
		return strings.Contains(resource, value)
	case "regex":
		matched, _ := regexp.MatchString(value, resource)
		return matched
	case "starts_with":
		return strings.HasPrefix(resource, value)
	default:
		return false
	}
}

func (ape *AdaptivePolicyEngine) evaluateTimeCondition(condition PolicyCondition) bool {
	now := time.Now()

	switch condition.Operator {
	case "outside_range":
		hours, ok := condition.Value.([]int)
		if !ok || len(hours) != 2 {
			return false
		}
		currentHour := now.Hour()
		return currentHour < hours[0] || currentHour > hours[1]
	case "weekend":
		return now.Weekday() == time.Saturday || now.Weekday() == time.Sunday
	default:
		return false
	}
}

func (ape *AdaptivePolicyEngine) evaluateLocationCondition(condition PolicyCondition, session *SessionContext) bool {
	switch condition.Operator {
	case "new":
		// Check if location is new (simplified)
		return true // Would check against location history
	case "country":
		// Check country (would use GeoIP)
		return false
	default:
		return false
	}
}

func (ape *AdaptivePolicyEngine) evaluateDeviceCondition(condition PolicyCondition, session *SessionContext) bool {
	if session.DeviceProfile == nil {
		return condition.Operator == "unknown"
	}

	switch condition.Operator {
	case "trusted":
		return session.DeviceProfile.TrustScore > 0.7
	case "new":
		return time.Since(session.DeviceProfile.LastSeen) < 24*time.Hour
	default:
		return false
	}
}

func (ape *AdaptivePolicyEngine) evaluateRiskCondition(condition PolicyCondition, riskScore float64) bool {
	threshold, ok := condition.Value.(float64)
	if !ok {
		return false
	}

	switch condition.Operator {
	case "greater_than":
		return riskScore > threshold
	case "less_than":
		return riskScore < threshold
	case "equals":
		return riskScore == threshold
	default:
		return false
	}
}

func (ape *AdaptivePolicyEngine) evaluateMethodCondition(condition PolicyCondition, method string) bool {
	value, ok := condition.Value.(string)
	if !ok {
		return false
	}

	switch condition.Operator {
	case "equals":
		return method == value
	case "in":
		methods := strings.Split(value, ",")
		for _, m := range methods {
			if strings.TrimSpace(m) == method {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// Helper functions

func (ape *AdaptivePolicyEngine) getSortedPolicies() []*SecurityPolicy {
	policies := make([]*SecurityPolicy, 0, len(ape.policies))
	for _, policy := range ape.policies {
		policies = append(policies, policy)
	}

	// Sort by priority (higher priority first)
	for i := 0; i < len(policies)-1; i++ {
		for j := i + 1; j < len(policies); j++ {
			if policies[i].Priority < policies[j].Priority {
				policies[i], policies[j] = policies[j], policies[i]
			}
		}
	}

	return policies
}

func (ape *AdaptivePolicyEngine) hasRequiredFactors(session *SessionContext, required []string) bool {
	verified := make(map[string]bool)
	for _, factor := range session.AuthFactors {
		if factor.Verified {
			verified[factor.Type] = true
		}
	}

	for _, req := range required {
		if !verified[req] {
			return false
		}
	}

	return true
}

func (ape *AdaptivePolicyEngine) applyPolicyActions(policy *SecurityPolicy, session *SessionContext, r *http.Request) PolicyAction {
	// Return first action (simplified)
	if len(policy.Actions) > 0 {
		return policy.Actions[0]
	}

	return PolicyAction{Type: "deny", Params: map[string]interface{}{"reason": "No action defined"}}
}

func (ape *AdaptivePolicyEngine) calculateConfidence(policy *SecurityPolicy, session *SessionContext) float64 {
	// Base confidence on policy priority and risk score
	confidence := float64(policy.Priority) / 100.0

	// Adjust based on session trust level
	switch session.TrustLevel {
	case TrustLevelVerified:
		confidence *= 0.95
	case TrustLevelHigh:
		confidence *= 0.90
	case TrustLevelMedium:
		confidence *= 0.85
	case TrustLevelLow:
		confidence *= 0.80
	default:
		confidence *= 0.75
	}

	return confidence
}

func (ape *AdaptivePolicyEngine) formatReason(policy *SecurityPolicy, action PolicyAction) string {
	if reason, ok := action.Params["reason"].(string); ok {
		return reason
	}
	return fmt.Sprintf("Policy '%s' applied", policy.Name)
}

func (ape *AdaptivePolicyEngine) recordDecision(sessionID string, decision *PolicyDecision) {
	history := ape.policyHistory[sessionID]
	history = append(history, decision)

	// Keep only recent decisions
	if len(history) > 100 {
		history = history[len(history)-100:]
	}

	ape.policyHistory[sessionID] = history
}

// GetPolicies returns all current security policies
func (ape *AdaptivePolicyEngine) GetPolicies() map[string]*SecurityPolicy {
	ape.mu.RLock()
	defer ape.mu.RUnlock()

	// Create a copy to prevent external modification
	policies := make(map[string]*SecurityPolicy)
	for id, policy := range ape.policies {
		// Create a deep copy of the policy
		policyCopy := &SecurityPolicy{
			ID:              policy.ID,
			Name:            policy.Name,
			Description:     policy.Description,
			Priority:        policy.Priority,
			Conditions:      make([]PolicyCondition, len(policy.Conditions)),
			Actions:         make([]PolicyAction, len(policy.Actions)),
			RiskThreshold:   policy.RiskThreshold,
			RequiredFactors: make([]string, len(policy.RequiredFactors)),
			Enabled:         policy.Enabled,
			CreatedAt:       policy.CreatedAt,
			UpdatedAt:       policy.UpdatedAt,
		}

		// Deep copy conditions
		copy(policyCopy.Conditions, policy.Conditions)

		// Deep copy actions
		copy(policyCopy.Actions, policy.Actions)

		// Deep copy required factors
		copy(policyCopy.RequiredFactors, policy.RequiredFactors)

		policies[id] = policyCopy
	}

	return policies
}

func (ape *AdaptivePolicyEngine) applyDefaultPolicy(session *SessionContext, r *http.Request) AccessDecision {
	// Default policy based on risk score
	allowed := session.RiskScore < 0.7
	reason := "Default policy"

	if !allowed {
		reason = fmt.Sprintf("Risk score too high: %.2f", session.RiskScore)
	}

	return AccessDecision{
		Resource:      r.URL.Path,
		Action:        r.Method,
		Allowed:       allowed,
		Reason:        reason,
		RiskScore:     session.RiskScore,
		Timestamp:     time.Now(),
		PolicyApplied: "default",
	}
}

// MicroSegmentController manages network micro-segmentation
type MicroSegmentController struct {
	config   NetworkSegmentationConfig
	segments map[string]*NetworkSegment
	rules    map[string][]*SegmentRule
	mu       sync.RWMutex
}

// NetworkSegment represents a micro-segment
type NetworkSegment struct {
	Name        string
	Description string
	TrustLevel  TrustLevel
	IPRanges    []*net.IPNet
	Services    []string
	Policies    []SegmentPolicy
}

// SegmentRule defines access rules between segments
type SegmentRule struct {
	FromSegment string
	ToSegment   string
	Allowed     bool
	Conditions  []RuleCondition
	Protocol    string
	Ports       []int
}

// RuleCondition represents a condition for segment rules
type RuleCondition struct {
	Type     string
	Value    interface{}
	Operator string
}

// NewMicroSegmentController creates a new segmentation controller
func NewMicroSegmentController(config NetworkSegmentationConfig) *MicroSegmentController {
	msc := &MicroSegmentController{
		config:   config,
		segments: make(map[string]*NetworkSegment),
		rules:    make(map[string][]*SegmentRule),
	}

	// Initialize default segments
	msc.initializeDefaultSegments()

	return msc
}

// initializeDefaultSegments sets up default network segments
func (msc *MicroSegmentController) initializeDefaultSegments() {
	// Public segment
	msc.segments["public"] = &NetworkSegment{
		Name:        "public",
		Description: "Public access segment",
		TrustLevel:  TrustLevelLow,
		Services:    []string{"/pks/lookup", "/pks/stats"},
		Policies:    []SegmentPolicy{msc.config.SegmentPolicies["public"]},
	}

	// Authenticated segment
	msc.segments["authenticated"] = &NetworkSegment{
		Name:        "authenticated",
		Description: "Authenticated users segment",
		TrustLevel:  TrustLevelMedium,
		Services:    []string{"/pks/add", "/pks/delete"},
		Policies:    []SegmentPolicy{msc.config.SegmentPolicies["authenticated"]},
	}

	// Admin segment
	msc.segments["admin"] = &NetworkSegment{
		Name:        "admin",
		Description: "Administrative access segment",
		TrustLevel:  TrustLevelHigh,
		Services:    []string{"/admin", "/api/v1"},
		Policies:    []SegmentPolicy{msc.config.SegmentPolicies["admin"]},
	}

	// Service mesh segment
	if msc.config.ServiceMesh.Enabled {
		msc.segments["service-mesh"] = &NetworkSegment{
			Name:        "service-mesh",
			Description: "Internal service communication",
			TrustLevel:  TrustLevelVerified,
			Services:    []string{"/internal"},
			Policies:    []SegmentPolicy{msc.config.SegmentPolicies["service-mesh"]},
		}
	}
}

// DetermineSegment determines which segment a session belongs to
func (msc *MicroSegmentController) DetermineSegment(session *SessionContext, r *http.Request) string {
	msc.mu.RLock()
	defer msc.mu.RUnlock()

	// Check service mesh first
	if msc.isServiceMeshRequest(r) {
		return "service-mesh"
	}

	// Determine based on trust level and authentication
	if session.TrustLevel >= TrustLevelHigh && msc.hasAdminPrivileges(session) {
		return "admin"
	}

	if session.TrustLevel >= TrustLevelMedium && len(session.AuthFactors) > 0 {
		return "authenticated"
	}

	return msc.config.DefaultSegment
}

// IsAccessAllowed checks if access is allowed for the segment
func (msc *MicroSegmentController) IsAccessAllowed(segment string, r *http.Request) bool {
	msc.mu.RLock()
	defer msc.mu.RUnlock()

	seg, exists := msc.segments[segment]
	if !exists {
		return false
	}

	// Check if service is allowed in segment
	for _, service := range seg.Services {
		if strings.HasPrefix(r.URL.Path, service) {
			return true
		}
	}

	// Check segment policies
	for _, policy := range seg.Policies {
		if msc.evaluateSegmentPolicy(policy, r) {
			return true
		}
	}

	return false
}

// evaluateSegmentPolicy evaluates a segment policy
func (msc *MicroSegmentController) evaluateSegmentPolicy(policy SegmentPolicy, r *http.Request) bool {
	// Check allowed services
	for _, service := range policy.AllowedServices {
		if strings.HasPrefix(r.URL.Path, service) {
			// Check method restrictions
			if len(policy.AllowedMethods) > 0 {
				methodAllowed := false
				for _, method := range policy.AllowedMethods {
					if r.Method == method {
						methodAllowed = true
						break
					}
				}
				if !methodAllowed {
					return false
				}
			}
			return true
		}
	}

	return false
}

// Helper functions

func (msc *MicroSegmentController) isServiceMeshRequest(r *http.Request) bool {
	if !msc.config.ServiceMesh.Enabled {
		return false
	}

	// Check for service mesh headers or certificates
	if r.Header.Get("X-Service-Name") != "" {
		serviceName := r.Header.Get("X-Service-Name")
		for _, trusted := range msc.config.ServiceMesh.TrustedServices {
			if serviceName == trusted {
				return true
			}
		}
	}

	// Check mutual TLS
	if msc.config.ServiceMesh.MutualTLSRequired && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		// Verify certificate is from trusted service
		return true
	}

	return false
}

func (msc *MicroSegmentController) hasAdminPrivileges(session *SessionContext) bool {
	// Check if user has admin role (simplified)
	// In production, would check against user directory/RBAC
	return strings.HasSuffix(session.UserID, "-admin")
}
