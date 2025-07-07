// ML Rate Limiting Plugin - gRPC Implementation
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
)

// Plugin constants
const (
	PluginName    = "ratelimit-ml"
	PluginVersion = "1.0.0"
	Priority      = 25
)

// MLRateLimitPlugin implements gRPC-based ML rate limiting
type MLRateLimitPlugin struct {
	proto.UnimplementedHKPPluginServer
	config          *MLRateLimitConfig
	anomalyDetector *AnomalyDetector
	patternAnalyzer *PatternAnalyzer
	predictor       *TrafficPredictor
	coordinator     *RateLimitCoordinator
	metrics         *MLMetrics
	mu              sync.RWMutex
}

// MLRateLimitConfig holds configuration
type MLRateLimitConfig struct {
	Enabled              bool    `json:"enabled"`
	ModelPath            string  `json:"modelPath"`
	AnomalyThreshold     float64 `json:"anomalyThreshold"`
	PredictionWindow     string  `json:"predictionWindow"`
	LearningEnabled      bool    `json:"learningEnabled"`
	CoordinationEnabled  bool    `json:"coordinationEnabled"`
	BlockDuration        string  `json:"blockDuration"`
	EscalationMultiplier float64 `json:"escalationMultiplier"`
}

// TrafficPattern represents analyzed traffic patterns
type TrafficPattern struct {
	ClientIP       string
	RequestRate    float64
	BurstPattern   []int
	Periodicity    float64
	Entropy        float64
	Predictability float64
	AnomalyScore   float64
	IsAnomalous    bool
	LastUpdated    time.Time
}

// NewMLRateLimitPlugin creates a new ML rate limiting plugin
func NewMLRateLimitPlugin() *MLRateLimitPlugin {
	config := &MLRateLimitConfig{
		Enabled:              true,
		ModelPath:            "/var/lib/hockeypuck/plugins/ml/models/",
		AnomalyThreshold:     0.7,
		PredictionWindow:     "5m",
		LearningEnabled:      true,
		CoordinationEnabled:  true,
		BlockDuration:        "15m",
		EscalationMultiplier: 2.0,
	}

	return &MLRateLimitPlugin{
		config:          config,
		anomalyDetector: NewAnomalyDetector(config.ModelPath, config.AnomalyThreshold),
		patternAnalyzer: NewPatternAnalyzer(),
		predictor:       NewTrafficPredictor(),
		coordinator:     NewRateLimitCoordinator(),
		metrics:         NewMLMetrics(),
	}
}

// Initialize implements the gRPC HKPPlugin interface
func (p *MLRateLimitPlugin) Initialize(ctx context.Context, req *proto.InitRequest) (*proto.InitResponse, error) {
	// Parse configuration
	if req.ConfigJson != "" {
		if err := json.Unmarshal([]byte(req.ConfigJson), p.config); err != nil {
			return &proto.InitResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to parse config: %v", err),
			}, nil
		}
	}

	// Initialize ML components
	if err := p.anomalyDetector.Initialize(); err != nil {
		return &proto.InitResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to initialize anomaly detector: %v", err),
		}, nil
	}

	log.Printf("ML Rate Limiting plugin initialized - enabled: %t, learning: %t, threshold: %.3f",
		p.config.Enabled, p.config.LearningEnabled, p.config.AnomalyThreshold)

	return &proto.InitResponse{
		Success: true,
		Info: &proto.PluginInfo{
			Name:        PluginName,
			Version:     PluginVersion,
			Description: "Machine learning extensions for advanced rate limiting with pattern analysis",
			Capabilities: []string{"rate_limiting", "ml_analysis", "traffic_prediction", "anomaly_detection"},
		},
	}, nil
}

// HandleHTTPRequest implements HTTP request processing with ML analysis
func (p *MLRateLimitPlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
	// Skip if not enabled
	if !p.config.Enabled {
		return &proto.HTTPResponse{
			StatusCode:    200,
			ContinueChain: true,
		}, nil
	}

	// Extract client IP
	clientIP := p.extractClientIP(req)

	// Analyze traffic pattern
	pattern := p.patternAnalyzer.AnalyzeRequest(clientIP, req)

	// Perform anomaly detection
	anomalyScore := p.anomalyDetector.DetectAnomaly(pattern)

	// Predict future traffic
	prediction := p.predictor.PredictTraffic(clientIP, pattern)

	// Check if we should block based on ML analysis
	shouldBlock, blockReason, blockDuration := p.shouldBlockRequest(pattern, anomalyScore, prediction)

	// Record metrics
	p.metrics.RecordRequest(clientIP, pattern, anomalyScore, shouldBlock)

	// Create response headers with ML intelligence
	headers := p.createMLHeaders(pattern, anomalyScore, prediction)

	if shouldBlock {
		log.Printf("ML rate limit triggered: client=%s, score=%.3f, reason=%s",
			clientIP, anomalyScore, blockReason)

		// Coordinate with other rate limiting plugins
		if p.config.CoordinationEnabled {
			p.coordinator.NotifyBlock(clientIP, blockReason, blockDuration)
		}

		return &proto.HTTPResponse{
			StatusCode:    429,
			Body:          []byte(fmt.Sprintf("Rate limit exceeded: %s", blockReason)),
			Headers:       headers,
			ContinueChain: false,
		}, nil
	}

	// Update learning model if enabled
	if p.config.LearningEnabled {
		go p.anomalyDetector.UpdateModel(pattern)
	}

	return &proto.HTTPResponse{
		StatusCode:    200,
		Headers:       headers,
		ContinueChain: true,
	}, nil
}

// CheckRateLimit implements ML-enhanced rate limiting
func (p *MLRateLimitPlugin) CheckRateLimit(ctx context.Context, req *proto.RateLimitCheck) (*proto.RateLimitResponse, error) {
	if !p.config.Enabled {
		return &proto.RateLimitResponse{Allowed: true}, nil
	}

	// Get current pattern for this client
	pattern := p.patternAnalyzer.GetPattern(req.Identifier)
	if pattern == nil {
		return &proto.RateLimitResponse{Allowed: true}, nil
	}

	// Perform real-time anomaly detection
	anomalyScore := p.anomalyDetector.DetectAnomaly(pattern)

	// Check prediction model
	prediction := p.predictor.PredictTraffic(req.Identifier, pattern)

	// Determine if rate limit should apply
	shouldLimit, reason, retryAfter := p.shouldBlockRequest(pattern, anomalyScore, prediction)

	if shouldLimit {
		return &proto.RateLimitResponse{
			Allowed:           false,
			RetryAfterSeconds: int32(retryAfter.Seconds()),
			Reason:            reason,
		}, nil
	}

	return &proto.RateLimitResponse{Allowed: true}, nil
}

// Helper methods

func (p *MLRateLimitPlugin) extractClientIP(req *proto.HTTPRequest) string {
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

func (p *MLRateLimitPlugin) shouldBlockRequest(pattern *TrafficPattern, anomalyScore float64, prediction *TrafficPrediction) (bool, string, time.Duration) {
	blockDuration, _ := time.ParseDuration(p.config.BlockDuration)

	// Check anomaly score
	if anomalyScore >= p.config.AnomalyThreshold {
		return true, fmt.Sprintf("ML anomaly detected (score: %.3f)", anomalyScore), blockDuration
	}

	// Check traffic burst patterns
	if pattern.RequestRate > 50.0 && pattern.Entropy < 0.3 {
		return true, "Suspicious traffic burst pattern detected", blockDuration
	}

	// Check prediction model warnings
	if prediction != nil && prediction.RiskLevel == "high" {
		return true, fmt.Sprintf("Traffic prediction indicates high risk: %s", prediction.Warning), blockDuration
	}

	// Check for bot-like behavior
	if pattern.Predictability > 0.9 && pattern.RequestRate > 10.0 {
		return true, "Bot-like behavior pattern detected", blockDuration / 2
	}

	return false, "", 0
}

func (p *MLRateLimitPlugin) createMLHeaders(pattern *TrafficPattern, anomalyScore float64, prediction *TrafficPrediction) map[string]string {
	headers := map[string]string{
		"X-ML-RateLimit-Plugin":      fmt.Sprintf("%s/%s", PluginName, PluginVersion),
		"X-ML-Anomaly-Score":         fmt.Sprintf("%.3f", anomalyScore),
		"X-ML-Request-Rate":          fmt.Sprintf("%.1f", pattern.RequestRate),
		"X-ML-Entropy":               fmt.Sprintf("%.3f", pattern.Entropy),
		"X-ML-Predictability":        fmt.Sprintf("%.3f", pattern.Predictability),
		"X-ML-Learning-Enabled":      fmt.Sprintf("%t", p.config.LearningEnabled),
	}

	if prediction != nil {
		headers["X-ML-Risk-Level"] = prediction.RiskLevel
		if prediction.Warning != "" {
			headers["X-ML-Warning"] = prediction.Warning
		}
	}

	return headers
}

// Required gRPC methods

func (p *MLRateLimitPlugin) GetInfo(ctx context.Context, req *proto.Empty) (*proto.PluginInfo, error) {
	return &proto.PluginInfo{
		Name:        PluginName,
		Version:     PluginVersion,
		Description: "Machine learning extensions for advanced rate limiting with pattern analysis",
		Capabilities: []string{"rate_limiting", "ml_analysis", "traffic_prediction", "anomaly_detection"},
		Metadata: map[string]string{
			"priority":           fmt.Sprintf("%d", Priority),
			"anomaly_threshold":  fmt.Sprintf("%.3f", p.config.AnomalyThreshold),
			"learning_enabled":   fmt.Sprintf("%t", p.config.LearningEnabled),
			"coordination":       fmt.Sprintf("%t", p.config.CoordinationEnabled),
		},
	}, nil
}

func (p *MLRateLimitPlugin) HandleKeyChange(ctx context.Context, req *proto.KeyChangeEvent) (*proto.Event, error) {
	// ML rate limiting typically doesn't process key changes directly
	eventData := map[string]string{
		"fingerprint": req.Fingerprint,
		"ml_analyzed": "false",
	}

	dataBytes, _ := json.Marshal(eventData)

	return &proto.Event{
		Type:      "ml-ratelimit.key.skipped",
		Source:    PluginName,
		Timestamp: time.Now().Unix(),
		Data:      dataBytes,
	}, nil
}

func (p *MLRateLimitPlugin) SubscribeEvents(req *proto.EventFilter, stream proto.HKPPlugin_SubscribeEventsServer) error {
	<-stream.Context().Done()
	return nil
}

func (p *MLRateLimitPlugin) PublishEvent(ctx context.Context, req *proto.Event) (*proto.Empty, error) {
	// Could use events from other plugins to enhance ML model
	return &proto.Empty{}, nil
}

func (p *MLRateLimitPlugin) QueryStorage(ctx context.Context, req *proto.StorageQuery) (*proto.StorageResponse, error) {
	return &proto.StorageResponse{
		Success: false,
		Error:   "Storage queries not supported by ML rate limiting plugin",
	}, nil
}

func (p *MLRateLimitPlugin) ReportThreat(ctx context.Context, req *proto.ThreatInfo) (*proto.Empty, error) {
	// Use threat reports to enhance anomaly detection
	if len(req.Indicators) > 0 {
		if clientIP, exists := req.Indicators["client_ip"]; exists {
			p.anomalyDetector.RecordThreat(clientIP, req.Type, req.Description)
		}
	}
	return &proto.Empty{}, nil
}

func (p *MLRateLimitPlugin) HealthCheck(ctx context.Context, req *proto.Empty) (*proto.HealthStatus, error) {
	status := proto.HealthStatus_HEALTHY
	message := "ML rate limiting plugin is healthy"

	// Check if ML model is loaded
	if !p.anomalyDetector.IsModelLoaded() {
		status = proto.HealthStatus_DEGRADED
		message = "ML model not fully loaded"
	}

	// Check metrics collection
	requestCount := p.metrics.GetRequestCount()
	if requestCount == 0 {
		status = proto.HealthStatus_DEGRADED
		message = "No traffic processed yet"
	}

	return &proto.HealthStatus{
		Status:    status,
		Message:   message,
		Timestamp: time.Now().Unix(),
		Details: map[string]string{
			"enabled":            fmt.Sprintf("%t", p.config.Enabled),
			"learning_enabled":   fmt.Sprintf("%t", p.config.LearningEnabled),
			"anomaly_threshold":  fmt.Sprintf("%.3f", p.config.AnomalyThreshold),
			"model_loaded":       fmt.Sprintf("%t", p.anomalyDetector.IsModelLoaded()),
			"requests_processed": fmt.Sprintf("%d", requestCount),
			"patterns_learned":   fmt.Sprintf("%d", p.patternAnalyzer.GetPatternCount()),
		},
	}, nil
}

func (p *MLRateLimitPlugin) Shutdown(ctx context.Context, req *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	log.Printf("ML rate limiting plugin shutting down...")

	// Save ML model if learning was enabled
	if p.config.LearningEnabled {
		if err := p.anomalyDetector.SaveModel(); err != nil {
			log.Printf("Failed to save ML model during shutdown: %v", err)
		}
	}

	return &proto.ShutdownResponse{Success: true}, nil
}

func main() {
	// Get gRPC address from environment
	address := os.Getenv("PLUGIN_GRPC_ADDRESS")
	if address == "" {
		address = "localhost:50004"
	}

	// Create listener
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create and register plugin
	plugin := NewMLRateLimitPlugin()
	proto.RegisterHKPPluginServer(grpcServer, plugin)

	// Register health service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	log.Printf("ML Rate Limiting gRPC plugin starting on %s", address)

	// Start serving
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}