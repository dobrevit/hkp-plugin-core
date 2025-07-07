// Package server provides a gRPC server framework for HKP plugins
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// PluginImplementation is the interface that plugin developers must implement
type PluginImplementation interface {
	// Initialize is called when the plugin starts
	Initialize(config map[string]interface{}) error

	// GetInfo returns plugin metadata
	GetInfo() PluginInfo

	// HandleHTTPRequest processes HTTP requests
	HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error)

	// HandleKeyChange processes key change events
	HandleKeyChange(ctx context.Context, event *proto.KeyChangeEvent) error

	// Shutdown is called when the plugin stops
	Shutdown() error
}

// PluginInfo contains plugin metadata
type PluginInfo struct {
	Name         string
	Version      string
	Description  string
	Capabilities []string
	Metadata     map[string]string
}

// PluginServer implements the gRPC HKPPlugin service
type PluginServer struct {
	proto.UnimplementedHKPPluginServer

	impl         PluginImplementation
	logger       *logrus.Logger
	grpcServer   *grpc.Server
	healthServer *health.Server
	address      string
	initialized  bool
	mutex        sync.RWMutex

	// Event handling
	eventHandlers map[string][]EventHandler
	eventMutex    sync.RWMutex

	// Shutdown handling
	shutdownCh chan struct{}
	shutdownWg sync.WaitGroup
}

// EventHandler processes events
type EventHandler func(ctx context.Context, event *proto.Event) error

// Options for creating a plugin server
type Options struct {
	// Logger to use
	Logger *logrus.Logger
	// Address to listen on (default: from environment)
	Address string
	// Maximum message size (default: 4MB)
	MaxMessageSize int
	// Enable reflection for debugging
	EnableReflection bool
}

// NewPluginServer creates a new plugin server
func NewPluginServer(impl PluginImplementation, opts *Options) *PluginServer {
	if opts == nil {
		opts = &Options{}
	}

	if opts.Logger == nil {
		opts.Logger = logrus.New()
	}

	if opts.Address == "" {
		// Get address from environment
		opts.Address = os.Getenv("PLUGIN_GRPC_ADDRESS")
		if opts.Address == "" {
			opts.Address = "localhost:50051"
		}
	}

	if opts.MaxMessageSize == 0 {
		opts.MaxMessageSize = 4 * 1024 * 1024 // 4MB
	}

	return &PluginServer{
		impl:          impl,
		logger:        opts.Logger,
		address:       opts.Address,
		eventHandlers: make(map[string][]EventHandler),
		shutdownCh:    make(chan struct{}),
	}
}

// Run starts the gRPC server and blocks until shutdown
func (s *PluginServer) Run() error {
	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Start server
	if err := s.Start(); err != nil {
		return err
	}

	// Wait for shutdown signal
	select {
	case sig := <-sigCh:
		s.logger.WithField("signal", sig).Info("Received shutdown signal")
	case <-s.shutdownCh:
		s.logger.Info("Shutdown requested")
	}

	// Graceful shutdown
	return s.Stop()
}

// Start begins serving gRPC requests
func (s *PluginServer) Start() error {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// Create gRPC server
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(4 * 1024 * 1024),
		grpc.MaxSendMsgSize(4 * 1024 * 1024),
	}
	s.grpcServer = grpc.NewServer(opts...)

	// Register services
	proto.RegisterHKPPluginServer(s.grpcServer, s)

	// Register health service
	s.healthServer = health.NewServer()
	grpc_health_v1.RegisterHealthServer(s.grpcServer, s.healthServer)
	s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// Enable reflection for debugging
	reflection.Register(s.grpcServer)

	// Start serving
	s.logger.WithField("address", s.address).Info("Starting gRPC server")

	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			s.logger.WithError(err).Error("gRPC server failed")
		}
	}()

	return nil
}

// Stop gracefully shuts down the server
func (s *PluginServer) Stop() error {
	s.logger.Info("Stopping gRPC server")

	// Mark as not serving
	if s.healthServer != nil {
		s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	}

	// Shutdown implementation
	if err := s.impl.Shutdown(); err != nil {
		s.logger.WithError(err).Warn("Plugin shutdown error")
	}

	// Stop gRPC server
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}

	// Wait for all goroutines
	s.shutdownWg.Wait()

	s.logger.Info("gRPC server stopped")
	return nil
}

// gRPC method implementations

func (s *PluginServer) Initialize(ctx context.Context, req *proto.InitRequest) (*proto.InitResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.initialized {
		return &proto.InitResponse{
			Success: false,
			Error:   "already initialized",
		}, nil
	}

	// Parse configuration
	var config map[string]interface{}
	if req.ConfigJson != "" {
		if err := json.Unmarshal([]byte(req.ConfigJson), &config); err != nil {
			return &proto.InitResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid config: %v", err),
			}, nil
		}
	}

	// Initialize implementation
	if err := s.impl.Initialize(config); err != nil {
		return &proto.InitResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// Get plugin info
	info := s.impl.GetInfo()

	s.initialized = true

	return &proto.InitResponse{
		Success: true,
		Info: &proto.PluginInfo{
			Name:         info.Name,
			Version:      info.Version,
			Description:  info.Description,
			Capabilities: info.Capabilities,
			Metadata:     info.Metadata,
		},
	}, nil
}

func (s *PluginServer) Shutdown(ctx context.Context, req *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	s.logger.WithField("reason", req.Reason).Info("Shutdown requested")

	// Trigger shutdown
	close(s.shutdownCh)

	return &proto.ShutdownResponse{
		Success: true,
	}, nil
}

func (s *PluginServer) GetInfo(ctx context.Context, req *proto.Empty) (*proto.PluginInfo, error) {
	info := s.impl.GetInfo()

	return &proto.PluginInfo{
		Name:         info.Name,
		Version:      info.Version,
		Description:  info.Description,
		Capabilities: info.Capabilities,
		Metadata:     info.Metadata,
	}, nil
}

func (s *PluginServer) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
	s.mutex.RLock()
	if !s.initialized {
		s.mutex.RUnlock()
		return &proto.HTTPResponse{
			StatusCode: 503,
			Body:       []byte("Plugin not initialized"),
		}, nil
	}
	s.mutex.RUnlock()

	// Call implementation
	return s.impl.HandleHTTPRequest(ctx, req)
}

func (s *PluginServer) HandleKeyChange(ctx context.Context, event *proto.KeyChangeEvent) (*proto.Event, error) {
	s.mutex.RLock()
	if !s.initialized {
		s.mutex.RUnlock()
		return nil, fmt.Errorf("plugin not initialized")
	}
	s.mutex.RUnlock()

	// Call implementation
	if err := s.impl.HandleKeyChange(ctx, event); err != nil {
		return nil, err
	}

	// Return empty event for now
	return &proto.Event{
		Type:      "key_change_processed",
		Timestamp: time.Now().Unix(),
		Source:    s.impl.GetInfo().Name,
	}, nil
}

func (s *PluginServer) HealthCheck(ctx context.Context, req *proto.Empty) (*proto.HealthStatus, error) {
	s.mutex.RLock()
	initialized := s.initialized
	s.mutex.RUnlock()

	if !initialized {
		return &proto.HealthStatus{
			Status:    proto.HealthStatus_UNHEALTHY,
			Message:   "Not initialized",
			Timestamp: time.Now().Unix(),
		}, nil
	}

	return &proto.HealthStatus{
		Status:    proto.HealthStatus_HEALTHY,
		Message:   "OK",
		Timestamp: time.Now().Unix(),
		Details: map[string]string{
			"plugin_name":    s.impl.GetInfo().Name,
			"plugin_version": s.impl.GetInfo().Version,
		},
	}, nil
}

// Event subscription handling

func (s *PluginServer) SubscribeEvents(filter *proto.EventFilter, stream proto.HKPPlugin_SubscribeEventsServer) error {
	// This would be implemented based on your event system
	// For now, just block until context is cancelled
	<-stream.Context().Done()
	return nil
}

func (s *PluginServer) PublishEvent(ctx context.Context, event *proto.Event) (*proto.Empty, error) {
	s.eventMutex.RLock()
	handlers := s.eventHandlers[event.Type]
	s.eventMutex.RUnlock()

	for _, handler := range handlers {
		if err := handler(ctx, event); err != nil {
			s.logger.WithError(err).WithField("event_type", event.Type).Warn("Event handler error")
		}
	}

	return &proto.Empty{}, nil
}

// Storage operations (these would typically proxy to the host)

func (s *PluginServer) QueryStorage(ctx context.Context, query *proto.StorageQuery) (*proto.StorageResponse, error) {
	// This would be implemented to communicate with the host
	return &proto.StorageResponse{
		Success: false,
		Error:   "Storage queries not implemented",
	}, nil
}

// Rate limiting

func (s *PluginServer) CheckRateLimit(ctx context.Context, check *proto.RateLimitCheck) (*proto.RateLimitResponse, error) {
	// Default implementation - always allow
	return &proto.RateLimitResponse{
		Allowed: true,
	}, nil
}

// Threat reporting

func (s *PluginServer) ReportThreat(ctx context.Context, threat *proto.ThreatInfo) (*proto.Empty, error) {
	s.logger.WithFields(logrus.Fields{
		"threat_id":    threat.Id,
		"threat_level": threat.Level.String(),
		"threat_type":  threat.Type,
	}).Warn("Threat reported")

	return &proto.Empty{}, nil
}

// Helper methods

// RegisterEventHandler registers a handler for specific event types
func (s *PluginServer) RegisterEventHandler(eventType string, handler EventHandler) {
	s.eventMutex.Lock()
	defer s.eventMutex.Unlock()

	s.eventHandlers[eventType] = append(s.eventHandlers[eventType], handler)
}
