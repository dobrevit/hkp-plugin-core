// Package client provides gRPC client for communicating with plugins from Hockeypuck
package client

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
	"github.com/dobrevit/hkp-plugin-core/pkg/lifecycle"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// PluginClient manages gRPC connections to plugins
type PluginClient struct {
	manager     *lifecycle.Manager
	connections map[string]*grpc.ClientConn
	clients     map[string]proto.HKPPluginClient
	mutex       sync.RWMutex
	logger      *logrus.Logger
}

// NewPluginClient creates a new plugin client
func NewPluginClient(manager *lifecycle.Manager, logger *logrus.Logger) *PluginClient {
	return &PluginClient{
		manager:     manager,
		connections: make(map[string]*grpc.ClientConn),
		clients:     make(map[string]proto.HKPPluginClient),
		logger:      logger,
	}
}

// ConnectToPlugins establishes connections to all running plugins
func (pc *PluginClient) ConnectToPlugins() error {
	pluginNames := pc.manager.ListPlugins()

	for _, name := range pluginNames {
		if err := pc.ConnectToPlugin(name); err != nil {
			pc.logger.WithError(err).WithField("plugin", name).Warn("Failed to connect to plugin")
		}
	}

	return nil
}

// ConnectToPlugin establishes a connection to a specific plugin
func (pc *PluginClient) ConnectToPlugin(pluginName string) error {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	// Check if already connected
	if _, exists := pc.clients[pluginName]; exists {
		return nil
	}

	// Get plugin process info
	proc, exists := pc.manager.GetPlugin(pluginName)
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}

	// Create gRPC connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, proc.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to plugin %s: %w", pluginName, err)
	}

	// Create client
	client := proto.NewHKPPluginClient(conn)

	// Store connection and client
	pc.connections[pluginName] = conn
	pc.clients[pluginName] = client

	pc.logger.WithField("plugin", pluginName).Info("Connected to plugin")
	return nil
}

// DisconnectFromPlugin closes connection to a specific plugin
func (pc *PluginClient) DisconnectFromPlugin(pluginName string) error {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if conn, exists := pc.connections[pluginName]; exists {
		conn.Close()
		delete(pc.connections, pluginName)
		delete(pc.clients, pluginName)
		pc.logger.WithField("plugin", pluginName).Info("Disconnected from plugin")
	}

	return nil
}

// Close closes all plugin connections
func (pc *PluginClient) Close() error {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	for name, conn := range pc.connections {
		conn.Close()
		pc.logger.WithField("plugin", name).Debug("Closed plugin connection")
	}

	pc.connections = make(map[string]*grpc.ClientConn)
	pc.clients = make(map[string]proto.HKPPluginClient)

	return nil
}

// HTTPRequestMiddleware processes HTTP requests through plugins
func (pc *PluginClient) HTTPRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Convert HTTP request to protobuf
		pbReq := &proto.HTTPRequest{
			Id:          fmt.Sprintf("req_%d", time.Now().UnixNano()),
			Method:      r.Method,
			Path:        r.URL.Path,
			Headers:     make(map[string]string),
			RemoteAddr:  r.RemoteAddr,
			QueryParams: make(map[string]string),
		}

		// Copy headers
		for key, values := range r.Header {
			if len(values) > 0 {
				pbReq.Headers[key] = values[0]
			}
		}

		// Copy query parameters
		for key, values := range r.URL.Query() {
			if len(values) > 0 {
				pbReq.QueryParams[key] = values[0]
			}
		}

		// Process through plugins
		if handled := pc.processHTTPRequestThroughPlugins(w, r, pbReq); handled {
			return // Plugin handled the request
		}

		// Continue to next handler if no plugin handled it
		next.ServeHTTP(w, r)
	})
}

// processHTTPRequestThroughPlugins sends request to all plugins
func (pc *PluginClient) processHTTPRequestThroughPlugins(w http.ResponseWriter, r *http.Request, pbReq *proto.HTTPRequest) bool {
	pc.mutex.RLock()
	clients := make(map[string]proto.HKPPluginClient)
	for name, client := range pc.clients {
		clients[name] = client
	}
	pc.mutex.RUnlock()

	for pluginName, client := range clients {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		resp, err := client.HandleHTTPRequest(ctx, pbReq)
		cancel()

		if err != nil {
			pc.logger.WithError(err).WithField("plugin", pluginName).Debug("Plugin HTTP call failed")
			continue
		}

		// Check if plugin wants to handle the request
		if resp.StatusCode != 200 || !resp.ContinueChain {
			// Plugin is handling the request
			for key, value := range resp.Headers {
				w.Header().Set(key, value)
			}
			w.WriteHeader(int(resp.StatusCode))
			w.Write(resp.Body)

			pc.logger.WithFields(logrus.Fields{
				"plugin":      pluginName,
				"status_code": resp.StatusCode,
				"path":        r.URL.Path,
			}).Info("Plugin handled HTTP request")

			return true
		}
	}

	return false // No plugin handled the request
}

// NotifyKeyChange sends key change events to all plugins
func (pc *PluginClient) NotifyKeyChange(changeType proto.KeyChangeEvent_ChangeType, fingerprint string, keyData []byte) error {
	event := &proto.KeyChangeEvent{
		Id:          fmt.Sprintf("key_%d", time.Now().UnixNano()),
		ChangeType:  changeType,
		Fingerprint: fingerprint,
		KeyData:     keyData,
		Timestamp:   time.Now().Unix(),
	}

	pc.mutex.RLock()
	clients := make(map[string]proto.HKPPluginClient)
	for name, client := range pc.clients {
		clients[name] = client
	}
	pc.mutex.RUnlock()

	for pluginName, client := range clients {
		go func(name string, c proto.HKPPluginClient) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			_, err := c.HandleKeyChange(ctx, event)
			if err != nil {
				pc.logger.WithError(err).WithFields(logrus.Fields{
					"plugin":      name,
					"fingerprint": fingerprint,
					"change_type": changeType.String(),
				}).Warn("Plugin key change notification failed")
			}
		}(pluginName, client)
	}

	return nil
}

// CheckRateLimit checks rate limits across all plugins
func (pc *PluginClient) CheckRateLimit(identifier, action string, metadata map[string]string) (*proto.RateLimitResponse, error) {
	check := &proto.RateLimitCheck{
		Identifier: identifier,
		Action:     action,
		Metadata:   metadata,
	}

	pc.mutex.RLock()
	clients := make(map[string]proto.HKPPluginClient)
	for name, client := range pc.clients {
		clients[name] = client
	}
	pc.mutex.RUnlock()

	for pluginName, client := range clients {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

		resp, err := client.CheckRateLimit(ctx, check)
		cancel()

		if err != nil {
			pc.logger.WithError(err).WithField("plugin", pluginName).Debug("Rate limit check failed")
			continue
		}

		// If any plugin denies the request, return the denial
		if !resp.Allowed {
			pc.logger.WithFields(logrus.Fields{
				"plugin":     pluginName,
				"identifier": identifier,
				"action":     action,
				"reason":     resp.Reason,
			}).Info("Rate limit denied by plugin")

			return resp, nil
		}
	}

	// All plugins allowed the request
	return &proto.RateLimitResponse{
		Allowed: true,
	}, nil
}

// GetPluginHealth checks health of all connected plugins
func (pc *PluginClient) GetPluginHealth() map[string]*proto.HealthStatus {
	pc.mutex.RLock()
	clients := make(map[string]proto.HKPPluginClient)
	for name, client := range pc.clients {
		clients[name] = client
	}
	pc.mutex.RUnlock()

	results := make(map[string]*proto.HealthStatus)

	for pluginName, client := range clients {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

		status, err := client.HealthCheck(ctx, &proto.Empty{})
		cancel()

		if err != nil {
			results[pluginName] = &proto.HealthStatus{
				Status:    proto.HealthStatus_UNHEALTHY,
				Message:   fmt.Sprintf("Health check failed: %v", err),
				Timestamp: time.Now().Unix(),
			}
		} else {
			results[pluginName] = status
		}
	}

	return results
}

// QueryStorage proxies storage queries to plugins that support it
func (pc *PluginClient) QueryStorage(queryType proto.StorageQuery_QueryType, query string, options map[string]string) (*proto.StorageResponse, error) {
	pbQuery := &proto.StorageQuery{
		Type:    queryType,
		Query:   query,
		Options: options,
	}

	pc.mutex.RLock()
	clients := make(map[string]proto.HKPPluginClient)
	for name, client := range pc.clients {
		clients[name] = client
	}
	pc.mutex.RUnlock()

	// Try each plugin until one handles the query
	for pluginName, client := range clients {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		resp, err := client.QueryStorage(ctx, pbQuery)
		cancel()

		if err != nil {
			pc.logger.WithError(err).WithField("plugin", pluginName).Debug("Storage query failed")
			continue
		}

		if resp.Success {
			pc.logger.WithField("plugin", pluginName).Debug("Storage query handled by plugin")
			return resp, nil
		}
	}

	return &proto.StorageResponse{
		Success: false,
		Error:   "No plugin handled the storage query",
	}, nil
}

// ReportThreat sends threat information to all plugins
func (pc *PluginClient) ReportThreat(threatLevel proto.ThreatInfo_ThreatLevel, threatType, description, source string, indicators map[string]string) error {
	threat := &proto.ThreatInfo{
		Id:          fmt.Sprintf("threat_%d", time.Now().UnixNano()),
		Level:       threatLevel,
		Type:        threatType,
		Description: description,
		Source:      source,
		Indicators:  indicators,
		Timestamp:   time.Now().Unix(),
	}

	pc.mutex.RLock()
	clients := make(map[string]proto.HKPPluginClient)
	for name, client := range pc.clients {
		clients[name] = client
	}
	pc.mutex.RUnlock()

	for pluginName, client := range clients {
		go func(name string, c proto.HKPPluginClient) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := c.ReportThreat(ctx, threat)
			if err != nil {
				pc.logger.WithError(err).WithFields(logrus.Fields{
					"plugin":       name,
					"threat_type":  threatType,
					"threat_level": threatLevel.String(),
				}).Warn("Threat report to plugin failed")
			}
		}(pluginName, client)
	}

	return nil
}

// HealthCheck performs health check on a specific plugin
func (pc *PluginClient) HealthCheck(ctx context.Context) error {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()

	// Check all connected plugins
	for pluginName, client := range pc.clients {
		healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		status, err := client.HealthCheck(healthCtx, &proto.Empty{})
		cancel()

		if err != nil {
			return fmt.Errorf("plugin %s health check failed: %w", pluginName, err)
		}

		if status.Status != proto.HealthStatus_HEALTHY {
			return fmt.Errorf("plugin %s is unhealthy: %s", pluginName, status.Message)
		}
	}

	return nil
}

// GetConnectedPlugins returns list of currently connected plugins
func (pc *PluginClient) GetConnectedPlugins() []string {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()

	plugins := make([]string, 0, len(pc.clients))
	for name := range pc.clients {
		plugins = append(plugins, name)
	}

	return plugins
}
