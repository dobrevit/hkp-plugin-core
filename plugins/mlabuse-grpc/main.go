// ML Abuse Detection Plugin - gRPC Implementation
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
	PluginName    = "ml-abuse-detector"
	PluginVersion = "1.0.0"
	Priority      = 30
)

// MLAbusePlugin implements gRPC-based ML abuse detection
type MLAbusePlugin struct {
	proto.UnimplementedHKPPluginServer
	config    *MLConfig
	analyzer  *BehaviorAnalyzer
	detector  *AnomalyDetector
	predictor *LLMPredictor
	metrics   *MetricsCollector
	mu        sync.RWMutex
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
	KeyOperationRatio float64
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

// NewMLAbusePlugin creates a new ML abuse detection plugin
func NewMLAbusePlugin() *MLAbusePlugin {
	return &MLAbusePlugin{
		config: &MLConfig{
			Enabled:              true,
			AnomalyThreshold:     0.85,
			BehaviorWindowSize:   100,
			UpdateInterval:       "5m",
			LLMDetection:         true,
			SyntheticThreshold:   0.75,
			MaxMemoryMB:          256,
			EnableRealtimeUpdate: true,
		},
	}
}

// Initialize implements the gRPC HKPPlugin interface
func (p *MLAbusePlugin) Initialize(ctx context.Context, req *proto.InitRequest) (*proto.InitResponse, error) {
	// Parse configuration
	if req.ConfigJson != "" {
		if err := json.Unmarshal([]byte(req.ConfigJson), p.config); err != nil {
			return &proto.InitResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to parse config: %v", err),
			}, nil
		}
	}

	// Initialize components
	p.analyzer = NewBehaviorAnalyzer(p.config.BehaviorWindowSize)
	p.detector = NewAnomalyDetector(p.config.ModelPath, p.config.AnomalyThreshold)
	p.predictor = NewLLMPredictor(p.config.SyntheticThreshold)
	p.metrics = NewMetricsCollector()

	// Load ML models
	if err := p.detector.LoadModel(); err != nil {
		return &proto.InitResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to load anomaly detection model: %v", err),
		}, nil
	}

	log.Printf("ML Abuse Detection plugin initialized - threshold: %.3f, llm_detection: %t",
		p.config.AnomalyThreshold, p.config.LLMDetection)

	return &proto.InitResponse{
		Success: true,
		Info: &proto.PluginInfo{
			Name:        PluginName,
			Version:     PluginVersion,
			Description: "Machine Learning-based abuse detection with LLM detection capabilities",
		},
	}, nil
}

// HandleHTTPRequest implements HTTP request processing with ML analysis
func (p *MLAbusePlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
	// Skip if not enabled
	if !p.config.Enabled {
		return &proto.HTTPResponse{
			StatusCode:    200,
			ContinueChain: true,
		}, nil
	}

	// Skip whitelisted paths
	if p.isWhitelistedPath(req.Path) {
		return &proto.HTTPResponse{
			StatusCode:    200,
			ContinueChain: true,
		}, nil
	}

	startTime := time.Now()

	// Extract client IP
	clientIP := p.extractClientIP(req)

	// Analyze request behavior
	profile := p.analyzer.AnalyzeHTTPRequest(clientIP, req)

	// Perform anomaly detection
	anomalyScore := p.detector.DetectAnomaly(profile)

	// Check for LLM/AI-generated content if enabled
	var llmResult *LLMDetectionResult
	if p.config.LLMDetection && (req.Method == "POST" || req.Method == "PUT") {
		llmResult = p.predictor.DetectLLMContentFromHTTP(req)
	}

	// Make decision based on scores
	shouldBlock := p.makeDecision(anomalyScore, llmResult)

	// Record metrics
	p.metrics.RecordRequest(clientIP, anomalyScore, llmResult, shouldBlock)

	// Create response headers with intelligence data
	headers := p.createIntelligenceHeaders(anomalyScore, llmResult)

	if shouldBlock {
		log.Printf("ML abuse detected: client=%s, score=%.3f, reasons=%v",
			clientIP, anomalyScore.Score, anomalyScore.Reasons)

		return &proto.HTTPResponse{
			StatusCode:    429,
			Body:          []byte("Rate limit exceeded: Suspicious behavior detected"),
			Headers:       headers,
			ContinueChain: false,
		}, nil
	}

	// Check if we should trigger enhanced monitoring
	if anomalyScore.Score > 0.6 && p.isSensitiveEndpoint(req.Path) {
		log.Printf("Enhanced monitoring triggered for %s (score: %.3f)", req.Path, anomalyScore.Score)
	}

	// Update behavior profile for future analysis
	go p.analyzer.UpdateProfile(clientIP, req, time.Since(startTime))

	return &proto.HTTPResponse{
		StatusCode:    200,
		Headers:       headers,
		ContinueChain: true,
	}, nil
}

// HandleKeyChange processes key change events
func (p *MLAbusePlugin) HandleKeyChange(ctx context.Context, req *proto.KeyChangeEvent) (*proto.Event, error) {
	// Analyze key submission patterns for ML abuse detection
	if req.ChangeType == proto.KeyChangeEvent_CREATE {
		// Check for suspicious key submission patterns
		p.analyzer.AnalyzeKeySubmission(req.Fingerprint, req.KeyData)
	}

	eventData := map[string]string{
		"fingerprint": req.Fingerprint,
		"analyzed":    "true",
	}

	dataBytes, err := json.Marshal(eventData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event data: %w", err)
	}

	return &proto.Event{
		Type:      "ml.key.analyzed",
		Source:    PluginName,
		Timestamp: time.Now().Unix(),
		Data:      dataBytes,
	}, nil
}

// CheckRateLimit implements rate limiting with ML enhancement
func (p *MLAbusePlugin) CheckRateLimit(ctx context.Context, req *proto.RateLimitCheck) (*proto.RateLimitResponse, error) {
	if !p.config.Enabled {
		return &proto.RateLimitResponse{Allowed: true}, nil
	}

	// Get behavior profile
	profile := p.analyzer.GetProfile(req.Identifier)
	if profile == nil {
		return &proto.RateLimitResponse{Allowed: true}, nil
	}

	// Perform anomaly detection
	anomalyScore := p.detector.DetectAnomaly(profile)

	// Enhanced rate limiting based on ML analysis
	if anomalyScore.Score >= p.config.AnomalyThreshold {
		return &proto.RateLimitResponse{
			Allowed:           false,
			RetryAfterSeconds: 300, // 5 minutes
			Reason:            fmt.Sprintf("ML detected anomalous behavior (score: %.3f)", anomalyScore.Score),
		}, nil
	}

	// Progressive rate limiting based on anomaly score
	if anomalyScore.Score > 0.7 {
		return &proto.RateLimitResponse{
			Allowed:           false,
			RetryAfterSeconds: 60, // 1 minute
			Reason:            "Suspicious behavior detected",
		}, nil
	}

	return &proto.RateLimitResponse{Allowed: true}, nil
}

// ReportThreat processes threat reports
func (p *MLAbusePlugin) ReportThreat(ctx context.Context, req *proto.ThreatInfo) (*proto.Empty, error) {
	// Use threat reports to enhance ML models
	if len(req.Indicators) > 0 {
		if clientIP, exists := req.Indicators["client_ip"]; exists {
			p.analyzer.RecordThreat(clientIP, req.Type, req.Description)
		}
	}

	return &proto.Empty{}, nil
}

// HealthCheck implements health checking
func (p *MLAbusePlugin) HealthCheck(ctx context.Context, req *proto.Empty) (*proto.HealthStatus, error) {
	status := proto.HealthStatus_HEALTHY
	message := "ML Abuse Detection plugin is healthy"

	// Check if models are loaded
	if !p.detector.IsModelLoaded() {
		status = proto.HealthStatus_UNHEALTHY
		message = "ML models not loaded"
	}

	// Check memory usage
	if p.metrics.GetMemoryUsageMB() > float64(p.config.MaxMemoryMB) {
		status = proto.HealthStatus_DEGRADED
		message = "High memory usage detected"
	}

	return &proto.HealthStatus{
		Status:    status,
		Message:   message,
		Timestamp: time.Now().Unix(),
		Details: map[string]string{
			"enabled":            fmt.Sprintf("%t", p.config.Enabled),
			"anomaly_threshold":  fmt.Sprintf("%.3f", p.config.AnomalyThreshold),
			"llm_detection":      fmt.Sprintf("%t", p.config.LLMDetection),
			"model_loaded":       fmt.Sprintf("%t", p.detector.IsModelLoaded()),
			"memory_usage_mb":    fmt.Sprintf("%.1f", p.metrics.GetMemoryUsageMB()),
			"requests_processed": fmt.Sprintf("%d", p.metrics.GetRequestCount()),
			"anomalies_detected": fmt.Sprintf("%d", p.metrics.GetAnomalyCount()),
		},
	}, nil
}

// Helper methods

func (p *MLAbusePlugin) isWhitelistedPath(path string) bool {
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

func (p *MLAbusePlugin) extractClientIP(req *proto.HTTPRequest) string {
	// Check X-Forwarded-For
	if xForwardedFor, exists := req.Headers["X-Forwarded-For"]; exists {
		if idx := strings.Index(xForwardedFor, ","); idx != -1 {
			return strings.TrimSpace(xForwardedFor[:idx])
		}
		return strings.TrimSpace(xForwardedFor)
	}

	// Check X-Real-IP
	if xRealIP, exists := req.Headers["X-Real-IP"]; exists {
		return xRealIP
	}

	// Use remote address
	return req.RemoteAddr
}

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
		return true
	}

	return false
}

func (p *MLAbusePlugin) createIntelligenceHeaders(anomaly *AnomalyScore, llm *LLMDetectionResult) map[string]string {
	headers := map[string]string{
		"X-ML-Plugin":        fmt.Sprintf("%s/%s", PluginName, PluginVersion),
		"X-ML-Enabled":       fmt.Sprintf("%t", p.config.Enabled),
		"X-ML-Threshold":     fmt.Sprintf("%.3f", p.config.AnomalyThreshold),
		"X-ML-Anomaly-Score": fmt.Sprintf("%.3f", anomaly.Score),
		"X-ML-Anomaly-Type":  anomaly.AnomalyType,
		"X-ML-Confidence":    fmt.Sprintf("%.3f", anomaly.Confidence),
	}

	if llm != nil {
		headers["X-ML-LLM-Analyzed"] = "true"
		if llm.IsAIGenerated {
			headers["X-ML-LLM-Detected"] = "true"
			headers["X-ML-Synthetic-Score"] = fmt.Sprintf("%.3f", llm.SyntheticScore)
		} else {
			headers["X-ML-LLM-Detected"] = "false"
		}
	} else {
		headers["X-ML-LLM-Analyzed"] = "false"
	}

	return headers
}

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

// GetInfo returns plugin information
func (p *MLAbusePlugin) GetInfo(ctx context.Context, req *proto.Empty) (*proto.PluginInfo, error) {
	return &proto.PluginInfo{
		Name:         PluginName,
		Version:      PluginVersion,
		Description:  "Machine Learning-based abuse detection with LLM detection capabilities",
		Capabilities: []string{"http_middleware", "threat_detection", "rate_limiting"},
		Metadata: map[string]string{
			"priority":   fmt.Sprintf("%d", Priority),
			"ml_enabled": fmt.Sprintf("%t", p.config.LLMDetection),
			"threshold":  fmt.Sprintf("%.3f", p.config.AnomalyThreshold),
		},
	}, nil
}

// SubscribeEvents implements event subscription (simplified)
func (p *MLAbusePlugin) SubscribeEvents(req *proto.EventFilter, stream proto.HKPPlugin_SubscribeEventsServer) error {
	// For this demo, we'll just keep the stream open
	<-stream.Context().Done()
	return nil
}

// PublishEvent publishes an event
func (p *MLAbusePlugin) PublishEvent(ctx context.Context, req *proto.Event) (*proto.Empty, error) {
	// For now, just log the event
	log.Printf("Event published: type=%s, source=%s", req.Type, req.Source)
	return &proto.Empty{}, nil
}

// QueryStorage implements storage querying (not used in this plugin)
func (p *MLAbusePlugin) QueryStorage(ctx context.Context, req *proto.StorageQuery) (*proto.StorageResponse, error) {
	return &proto.StorageResponse{
		Success: false,
		Error:   "Storage queries not supported by ML abuse detection plugin",
	}, nil
}

// Shutdown gracefully stops the plugin
func (p *MLAbusePlugin) Shutdown(ctx context.Context, req *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	log.Printf("ML Abuse Detection plugin shutting down...")

	// Save model state if enabled
	if p.config.EnableRealtimeUpdate {
		if err := p.detector.SaveModel(); err != nil {
			log.Printf("Failed to save model state during shutdown: %v", err)
		}
	}

	return &proto.ShutdownResponse{
		Success: true,
	}, nil
}

func main() {
	// Get gRPC address from environment
	address := os.Getenv("PLUGIN_GRPC_ADDRESS")
	if address == "" {
		address = "localhost:50002"
	}

	// Create listener
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create and register plugin
	plugin := NewMLAbusePlugin()
	proto.RegisterHKPPluginServer(grpcServer, plugin)

	// Register health service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	log.Printf("ML Abuse Detection gRPC plugin starting on %s", address)

	// Start serving
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
