// Package mlabuse provides a machine learning-based abuse detection plugin for Hockeypuck
package mlabuse

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
	PluginName    = "ml-abuse-detector"
	PluginVersion = "1.0.0"
	Priority      = 30 // Run after rate limiting (priority 20)
)

// BehaviorProfile represents a client's behavioral pattern
type BehaviorProfile struct {
	ClientIP          string
	RequestIntervals  []time.Duration
	PathSequences     []string
	UserAgentRotation []string
	PayloadSimilarity float64
	TLSFingerprint    string
	SessionBehavior   SessionPattern
	EntropyMetrics    EntropyMetrics
	LastUpdated       time.Time
}

// SessionPattern tracks session-level behavioral analysis
type SessionPattern struct {
	SessionDuration   time.Duration
	RequestCount      int
	UniquePathsCount  int
	ErrorRate         float64
	BytesTransferred  int64
	KeyOperationRatio float64 // ratio of key operations to total requests
}

// EntropyMetrics measures randomness in behavior
type EntropyMetrics struct {
	TimingEntropy    float64
	PathEntropy      float64
	ParameterEntropy float64
	OverallScore     float64
}

// AnomalyScore represents the ML model output
type AnomalyScore struct {
	Score          float64
	Confidence     float64
	AnomalyType    string
	Reasons        []string
	Recommendation string
}

// LLMDetectionResult represents LLM/AI-generated content detection
type LLMDetectionResult struct {
	IsAIGenerated   bool
	Perplexity      float64
	TokenPatterns   []string
	SyntheticScore  float64
	PromptInjection bool
}

// MLAbusePlugin implements machine learning-based abuse detection
type MLAbusePlugin struct {
	host      plugin.PluginHost
	config    *MLConfig
	analyzer  *BehaviorAnalyzer
	detector  *AnomalyDetector
	predictor *LLMPredictor
	metrics   *MetricsCollector
	mu        sync.RWMutex
	tomb      tomb.Tomb
}

// MLConfig holds the plugin configuration
type MLConfig struct {
	Enabled              bool    `json:"enabled"`
	ModelPath            string  `json:"modelPath"`
	AnomalyThreshold     float64 `json:"anomalyThreshold"`
	BehaviorWindowSize   int     `json:"behaviorWindowSize"`
	UpdateInterval       string  `json:"updateInterval"`
	LLMDetection         bool    `json:"llmDetection"`
	SyntheticThreshold   float64 `json:"syntheticThreshold"`
	MaxMemoryMB          int     `json:"maxMemoryMB"`
	EnableRealtimeUpdate bool    `json:"enableRealtimeUpdate"`
}

// Initialize implements the Plugin interface
func (p *MLAbusePlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
	// Parse configuration
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	p.config = &MLConfig{
		Enabled:              true,
		AnomalyThreshold:     0.85,
		BehaviorWindowSize:   100,
		UpdateInterval:       "5m",
		LLMDetection:         true,
		SyntheticThreshold:   0.75,
		MaxMemoryMB:          256,
		EnableRealtimeUpdate: true,
	}

	if err := json.Unmarshal(configBytes, p.config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	p.host = host

	// Initialize components
	p.analyzer = NewBehaviorAnalyzer(p.config.BehaviorWindowSize)
	p.detector = NewAnomalyDetector(p.config.ModelPath, p.config.AnomalyThreshold)
	p.predictor = NewLLMPredictor(p.config.SyntheticThreshold)
	p.metrics = NewMetricsCollector()

	// Load ML models
	if err := p.detector.LoadModel(); err != nil {
		return fmt.Errorf("failed to load anomaly detection model: %w", err)
	}

	// Register background tasks
	updateInterval, _ := time.ParseDuration(p.config.UpdateInterval)
	if updateInterval == 0 {
		updateInterval = 5 * time.Minute
	}

	host.RegisterTask("ml-model-update", updateInterval, p.updateModels)
	host.RegisterTask("ml-cleanup", 5*time.Minute, p.cleanup)

	// Register middleware
	middleware, err := p.CreateMiddleware()
	if err != nil {
		return fmt.Errorf("failed to create middleware: %w", err)
	}

	if err := host.RegisterMiddleware("/", middleware); err != nil {
		return fmt.Errorf("failed to register middleware: %w", err)
	}

	// Subscribe to events
	host.SubscribeEvent("ratelimit.violation", p.handleRateLimitEvent)

	host.Logger().Info("ML Abuse Detection plugin initialized",
		"threshold", p.config.AnomalyThreshold,
		"llm_detection", p.config.LLMDetection)

	return nil
}

// Name returns the plugin name
func (p *MLAbusePlugin) Name() string {
	return PluginName
}

// Version returns the plugin version
func (p *MLAbusePlugin) Version() string {
	return PluginVersion
}

// Description returns the plugin description
func (p *MLAbusePlugin) Description() string {
	return "Machine Learning-based abuse detection with LLM detection capabilities"
}

// Dependencies returns required plugin dependencies
func (p *MLAbusePlugin) Dependencies() []plugin.PluginDependency {
	return []plugin.PluginDependency{
		{Name: "ratelimit", Version: "1.0.0"},
	}
}

// Priority returns the plugin priority (higher numbers run later)
func (p *MLAbusePlugin) Priority() int {
	return Priority
}

// Shutdown gracefully stops the plugin
func (p *MLAbusePlugin) Shutdown(ctx context.Context) error {
	// Signal shutdown to all goroutines
	p.tomb.Kill(nil)

	// Wait for all goroutines to finish with context timeout
	done := make(chan error, 1)
	go func() {
		done <- p.tomb.Wait()
	}()

	select {
	case err := <-done:
		// Save model state before returning
		if p.config.EnableRealtimeUpdate {
			if saveErr := p.detector.SaveModel(); saveErr != nil {
				p.host.Logger().Error("Failed to save model state during shutdown", "error", saveErr)
			}
		}
		return err
	case <-ctx.Done():
		// Timeout - return error
		return fmt.Errorf("plugin shutdown timed out")
	}
}

// CreateMiddleware creates the ML abuse detection middleware
func (p *MLAbusePlugin) CreateMiddleware() (func(http.Handler) http.Handler, error) {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Debug: Always log that middleware is running
			p.host.Logger().Debug("ML abuse middleware invoked",
				"method", r.Method,
				"path", r.URL.Path,
				"enabled", p.config.Enabled)

			// Skip if not enabled
			if !p.config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			startTime := time.Now()

			// Extract client IP
			clientIP := p.extractClientIP(r)

			// Skip whitelisted paths
			if p.isWhitelistedPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Analyze request behavior
			profile := p.analyzer.AnalyzeRequest(clientIP, r)

			// Perform anomaly detection
			anomalyScore := p.detector.DetectAnomaly(profile)

			// Check for LLM/AI-generated content if enabled
			var llmResult *LLMDetectionResult
			if p.config.LLMDetection && (r.Method == "POST" || r.Method == "PUT") {
				llmResult = p.predictor.DetectLLMContent(r)
			}

			// Make decision based on scores
			shouldBlock := p.makeDecision(anomalyScore, llmResult)

			// Record metrics
			p.metrics.RecordRequest(clientIP, anomalyScore, llmResult, shouldBlock)

			// Add headers for coordination with other plugins
			p.addIntelligenceHeaders(w, anomalyScore, llmResult)

			if shouldBlock {
				// Publish security threat event
				p.host.PublishEvent(plugin.PluginEvent{
					Type:      plugin.EventSecurityThreatDetected,
					Source:    p.Name(),
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"threat_type":        "ml_detected_anomaly",
						"severity":           p.determineSeverity(anomalyScore.Score),
						"client_ip":          clientIP,
						"user_agent":         r.UserAgent(),
						"endpoint":           r.URL.Path,
						"description":        fmt.Sprintf("ML detected anomalous behavior: %v", anomalyScore.Reasons),
						"confidence":         anomalyScore.Score,
						"recommended_action": "rate_limit",
					},
				})

				// Publish event for other plugins (backward compatibility)
				p.host.PublishEvent(plugin.PluginEvent{
					Type:      "ml.abuse.detected",
					Source:    p.Name(),
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"client_ip":     clientIP,
						"anomaly_score": anomalyScore.Score,
						"reasons":       anomalyScore.Reasons,
						"llm_detected":  llmResult != nil && llmResult.IsAIGenerated,
					},
				})

				// Return rate limit response
				http.Error(w, "Rate limit exceeded: Suspicious behavior detected", http.StatusTooManyRequests)
				return
			}

			// Check if we should request enhanced protection for sensitive endpoints
			if anomalyScore.Score > 0.6 && p.isSensitiveEndpoint(r.URL.Path) {
				p.requestEndpointProtection(r.URL.Path, "medium anomaly detected", "5m")
			}

			// Update behavior profile for future analysis
			go p.analyzer.UpdateProfile(clientIP, r, time.Since(startTime))

			next.ServeHTTP(w, r)
		})
	}, nil
}

// RegisterHandlers registers the plugin's HTTP handlers
func (p *MLAbusePlugin) RegisterHandlers(host plugin.PluginHost) error {
	host.RegisterHandler("/api/ml/status", plugin.WrapStandardHandler(p.handleStatus))
	host.RegisterHandler("/api/ml/metrics", plugin.WrapStandardHandler(p.handleMetrics))
	host.RegisterHandler("/api/ml/analyze", plugin.WrapStandardHandler(p.handleAnalyze))
	return nil
}

// Helper methods

func (p *MLAbusePlugin) isWhitelistedPath(path string) bool {
	// Whitelist certain paths that shouldn't be analyzed
	whitelisted := []string{
		"/health",
		"/metrics",
		"/api/ml/",
	}

	for _, prefix := range whitelisted {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}

func (p *MLAbusePlugin) extractClientIP(r *http.Request) string {
	// Check if we should trust proxy headers
	if xForwardedFor := r.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
		// Take the first IP in the chain
		if idx := strings.Index(xForwardedFor, ","); idx != -1 {
			return strings.TrimSpace(xForwardedFor[:idx])
		}
		return strings.TrimSpace(xForwardedFor)
	}

	// Check X-Real-IP
	if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
		return xRealIP
	}

	// Fall back to remote address
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

// makeDecision determines whether to block based on ML analysis
func (p *MLAbusePlugin) makeDecision(anomaly *AnomalyScore, llm *LLMDetectionResult) bool {
	// Block if anomaly score exceeds threshold
	if anomaly.Score >= p.config.AnomalyThreshold {
		return true
	}

	// Block if LLM content detected with high confidence
	if llm != nil && llm.IsAIGenerated && llm.SyntheticScore >= p.config.SyntheticThreshold {
		return true
	}

	// Block if prompt injection detected
	if llm != nil && llm.PromptInjection {
		return true
	}

	// Combined score analysis
	if anomaly.Score > 0.7 && llm != nil && llm.SyntheticScore > 0.6 {
		// Lower thresholds when both indicators present
		return true
	}

	return false
}

// addIntelligenceHeaders adds ML intelligence to response headers
func (p *MLAbusePlugin) addIntelligenceHeaders(w http.ResponseWriter, anomaly *AnomalyScore, llm *LLMDetectionResult) {
	// Always add basic headers for debugging
	w.Header().Set("X-ML-Plugin", fmt.Sprintf("%s/%s", p.Name(), p.Version()))
	w.Header().Set("X-ML-Enabled", fmt.Sprintf("%t", p.config.Enabled))
	w.Header().Set("X-ML-Threshold", fmt.Sprintf("%.3f", p.config.AnomalyThreshold))

	// Add analysis results
	w.Header().Set("X-ML-Anomaly-Score", fmt.Sprintf("%.3f", anomaly.Score))
	w.Header().Set("X-ML-Anomaly-Type", anomaly.AnomalyType)
	w.Header().Set("X-ML-Confidence", fmt.Sprintf("%.3f", anomaly.Confidence))

	if llm != nil {
		w.Header().Set("X-ML-LLM-Analyzed", "true")
		if llm.IsAIGenerated {
			w.Header().Set("X-ML-LLM-Detected", "true")
			w.Header().Set("X-ML-Synthetic-Score", fmt.Sprintf("%.3f", llm.SyntheticScore))
		} else {
			w.Header().Set("X-ML-LLM-Detected", "false")
		}
	} else {
		w.Header().Set("X-ML-LLM-Analyzed", "false")
	}
}

// Background tasks

func (p *MLAbusePlugin) updateModels(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Get recent behavior data
	recentData := p.analyzer.GetRecentBehaviorData()

	// Update anomaly detection model
	if err := p.detector.UpdateModel(recentData); err != nil {
		p.host.Logger().Error("Failed to update ML model", "error", err)
		return err
	}

	p.host.Logger().Debug("ML model updated", "data_points", len(recentData))
	return nil
}

func (p *MLAbusePlugin) cleanup(ctx context.Context) error {
	// Clean up old behavior profiles
	cleaned := p.analyzer.CleanupOldProfiles()

	// Report metrics
	p.metrics.ReportStatistics()

	p.host.Logger().Debug("ML cleanup completed", "profiles_cleaned", cleaned)
	return nil
}

// Event handlers

func (p *MLAbusePlugin) handleRateLimitEvent(event plugin.PluginEvent) error {
	// Extract event data
	data := event.Data

	clientIP, _ := data["client_ip"].(string)
	reason, _ := data["reason"].(string)

	// Update behavior profile with violation
	p.analyzer.RecordViolation(clientIP, reason)

	// Trigger immediate anomaly check
	profile := p.analyzer.GetProfile(clientIP)
	if profile != nil {
		anomaly := p.detector.DetectAnomaly(profile)
		if anomaly.Score > p.config.AnomalyThreshold {
			// Escalate to longer ban
			p.host.PublishEvent(plugin.PluginEvent{
				Type:      "ml.abuse.escalate",
				Source:    p.Name(),
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"client_ip": clientIP,
					"duration":  "72h",
					"reason":    "ML detected persistent abuse pattern",
				},
			})
		}
	}

	return nil
}

// HTTP handlers

func (p *MLAbusePlugin) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"plugin":        p.Name(),
		"version":       p.Version(),
		"enabled":       p.config.Enabled,
		"threshold":     p.config.AnomalyThreshold,
		"llm_detection": p.config.LLMDetection,
		"metrics":       p.metrics.GetCurrentMetrics(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (p *MLAbusePlugin) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := p.metrics.GetCurrentMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func (p *MLAbusePlugin) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientIP string `json:"client_ip"`
		Text     string `json:"text"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Get behavior profile
	profile := p.analyzer.GetProfile(req.ClientIP)
	if profile == nil {
		http.Error(w, "No profile found", http.StatusNotFound)
		return
	}

	// Analyze
	anomaly := p.detector.DetectAnomaly(profile)

	response := map[string]interface{}{
		"client_ip":     req.ClientIP,
		"anomaly_score": anomaly.Score,
		"anomaly_type":  anomaly.AnomalyType,
		"reasons":       anomaly.Reasons,
		"confidence":    anomaly.Confidence,
	}

	// LLM analysis if text provided
	if req.Text != "" && p.config.LLMDetection {
		llmResult := p.predictor.AnalyzeText(req.Text)
		response["llm_analysis"] = llmResult
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// determineSeverity determines threat severity based on anomaly score
func (p *MLAbusePlugin) determineSeverity(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

// isSensitiveEndpoint checks if an endpoint is considered sensitive
func (p *MLAbusePlugin) isSensitiveEndpoint(path string) bool {
	sensitiveEndpoints := []string{
		"/pks/add",
		"/admin",
		"/api",
		"/auth",
		"/config",
	}

	for _, sensitive := range sensitiveEndpoints {
		if strings.HasPrefix(path, sensitive) {
			return true
		}
	}
	return false
}

// requestEndpointProtection requests temporary protection for an endpoint
func (p *MLAbusePlugin) requestEndpointProtection(path, reason, duration string) {
	protectionReq := plugin.EndpointProtectionRequest{
		Action:      "protect",
		Paths:       []string{path},
		Reason:      reason,
		RequesterID: p.Name(),
		Temporary:   true,
		Duration:    duration,
		Priority:    5, // Medium priority
	}

	event := plugin.PluginEvent{
		Type:      plugin.EventEndpointProtectionRequest,
		Source:    p.Name(),
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"action":       protectionReq.Action,
			"paths":        protectionReq.Paths,
			"reason":       protectionReq.Reason,
			"requester_id": protectionReq.RequesterID,
			"temporary":    protectionReq.Temporary,
			"duration":     protectionReq.Duration,
			"priority":     protectionReq.Priority,
		},
	}

	if err := p.host.PublishEvent(event); err != nil {
		p.host.Logger().Error("Failed to request endpoint protection", "error", err, "path", path)
	} else {
		p.host.Logger().Info("Requested endpoint protection", "path", path, "reason", reason, "duration", duration)
	}
}

// GetPlugin returns a new instance of the plugin for dynamic loading
func GetPlugin() plugin.Plugin {
	return &MLAbusePlugin{}
}
