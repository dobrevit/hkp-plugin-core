// Package client provides Hockeypuck integration for gRPC plugins
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/config"
	"github.com/dobrevit/hkp-plugin-core/pkg/discovery"
	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
	"github.com/dobrevit/hkp-plugin-core/pkg/health"
	"github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
	"github.com/dobrevit/hkp-plugin-core/pkg/lifecycle"
	"github.com/sirupsen/logrus"
)

// HockeypuckPluginHost provides the integration between Hockeypuck and gRPC plugins
type HockeypuckPluginHost struct {
	discoverer       *discovery.Discoverer
	registry         *discovery.Registry
	lifecycleManager *lifecycle.Manager
	pluginClient     *PluginClient
	healthMonitor    *health.Monitor
	healthHandler    *health.HealthHandler
	settings         *config.Settings
	logger           *logrus.Logger
	initialized      bool
}

// NewHockeypuckPluginHost creates a new Hockeypuck plugin host
func NewHockeypuckPluginHost(settings *config.Settings, logger *logrus.Logger) *HockeypuckPluginHost {
	// Create discoverer
	discoverer := discovery.NewDiscoverer([]string{settings.Plugins.Directory}, logger)
	
	// Create registry
	registry := discovery.NewRegistry(logger)
	
	// Create lifecycle manager
	lifecycleConfig := lifecycle.DefaultConfig()
	lifecycleConfig.StartupTimeout = 30 * time.Second
	lifecycleConfig.HealthCheckInterval = 10 * time.Second
	lifecycleConfig.ShutdownTimeout = 10 * time.Second
	
	lifecycleManager := lifecycle.NewManager(lifecycleConfig, logger)
	
	// Create plugin client
	pluginClient := NewPluginClient(lifecycleManager, logger)
	
	// Create health monitor
	healthConfig := health.DefaultMonitorConfig()
	healthMonitor := health.NewMonitor(healthConfig, logger, lifecycleManager)
	
	// Create health handler
	healthHandler := health.NewHealthHandler(healthMonitor, logger)
	
	return &HockeypuckPluginHost{
		discoverer:       discoverer,
		registry:         registry,
		lifecycleManager: lifecycleManager,
		pluginClient:     pluginClient,
		healthMonitor:    healthMonitor,
		healthHandler:    healthHandler,
		settings:         settings,
		logger:           logger,
	}
}

// Initialize discovers and starts all plugins
func (h *HockeypuckPluginHost) Initialize(ctx context.Context) error {
	if h.initialized {
		return fmt.Errorf("plugin host already initialized")
	}
	
	h.logger.Info("Initializing Hockeypuck gRPC plugin host")
	
	// Start lifecycle manager
	if err := h.lifecycleManager.Start(); err != nil {
		return fmt.Errorf("failed to start lifecycle manager: %w", err)
	}
	
	// Start health monitor
	if err := h.healthMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start health monitor: %w", err)
	}
	
	// Discover plugins
	plugins, err := h.discoverer.DiscoverPlugins()
	if err != nil {
		return fmt.Errorf("failed to discover plugins: %w", err)
	}
	
	h.logger.WithField("count", len(plugins)).Info("Discovered plugins")
	
	// Register and start plugins
	startedCount := 0
	for _, plugin := range plugins {
		// Register plugin
		if err := h.registry.Register(plugin); err != nil {
			h.logger.WithError(err).WithField("plugin", plugin.Info.Name).Warn("Failed to register plugin")
			continue
		}
		
		// Start plugin process
		if err := h.lifecycleManager.StartPlugin(plugin); err != nil {
			h.logger.WithError(err).WithField("plugin", plugin.Info.Name).Error("Failed to start plugin")
			continue
		}
		
		startedCount++
	}
	
	// Wait a moment for plugins to start
	time.Sleep(2 * time.Second)
	
	// Connect to started plugins
	if err := h.pluginClient.ConnectToPlugins(); err != nil {
		h.logger.WithError(err).Warn("Some plugin connections failed")
	}
	
	// Register plugins with health monitor
	for _, pluginName := range h.pluginClient.GetConnectedPlugins() {
		h.healthMonitor.RegisterPlugin(pluginName, h.pluginClient)
	}
	
	h.initialized = true
	h.logger.WithFields(logrus.Fields{
		"discovered": len(plugins),
		"started":    startedCount,
		"connected":  len(h.pluginClient.GetConnectedPlugins()),
	}).Info("Hockeypuck plugin host initialized")
	
	return nil
}

// Shutdown gracefully stops all plugins
func (h *HockeypuckPluginHost) Shutdown(ctx context.Context) error {
	if !h.initialized {
		return nil
	}
	
	h.logger.Info("Shutting down Hockeypuck plugin host")
	
	// Stop health monitor
	if err := h.healthMonitor.Stop(); err != nil {
		h.logger.WithError(err).Warn("Error stopping health monitor")
	}
	
	// Close plugin connections
	if err := h.pluginClient.Close(); err != nil {
		h.logger.WithError(err).Warn("Error closing plugin connections")
	}
	
	// Stop lifecycle manager (this stops all plugins)
	if err := h.lifecycleManager.Stop(); err != nil {
		h.logger.WithError(err).Warn("Error stopping lifecycle manager")
	}
	
	h.initialized = false
	h.logger.Info("Plugin host shutdown complete")
	
	return nil
}

// GetHTTPMiddleware returns HTTP middleware for plugin integration
func (h *HockeypuckPluginHost) GetHTTPMiddleware() func(http.Handler) http.Handler {
	if !h.initialized {
		// Return pass-through middleware if not initialized
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	
	return h.pluginClient.HTTPRequestMiddleware
}

// NotifyKeyChange notifies plugins of key changes (Hockeypuck storage integration)
func (h *HockeypuckPluginHost) NotifyKeyChange(change hkpstorage.KeyChange) error {
	if !h.initialized {
		return nil
	}
	
	// Convert Hockeypuck KeyChange to protobuf
	var changeType proto.KeyChangeEvent_ChangeType
	var fingerprint string
	
	// Determine change type and extract fingerprint from change string
	switch change.(type) {
	case hkpstorage.KeyAdded:
		changeType = proto.KeyChangeEvent_CREATE
		if ka, ok := change.(hkpstorage.KeyAdded); ok {
			fingerprint = ka.ID
		}
	case hkpstorage.KeyRemoved:
		changeType = proto.KeyChangeEvent_DELETE
		if kr, ok := change.(hkpstorage.KeyRemoved); ok {
			fingerprint = kr.ID
		}
	default:
		changeType = proto.KeyChangeEvent_UPDATE
		// Extract fingerprint from change string if possible
		changeStr := change.String()
		if len(changeStr) > 0 {
			// Simple extraction - in practice this would be more sophisticated
			fingerprint = "unknown"
		}
	}
	
	// For now, we don't have direct access to key data from the interface
	// In a real integration, this would be passed separately or extracted differently
	keyData := []byte{}
	
	return h.pluginClient.NotifyKeyChange(changeType, fingerprint, keyData)
}

// CheckRateLimit checks if a request should be rate limited
func (h *HockeypuckPluginHost) CheckRateLimit(remoteAddr, operation string) (allowed bool, retryAfter int, reason string) {
	if !h.initialized {
		return true, 0, "" // Allow if plugins not initialized
	}
	
	metadata := map[string]string{
		"remote_addr": remoteAddr,
		"timestamp":   fmt.Sprintf("%d", time.Now().Unix()),
	}
	
	resp, err := h.pluginClient.CheckRateLimit(remoteAddr, operation, metadata)
	if err != nil {
		h.logger.WithError(err).Debug("Rate limit check failed, allowing request")
		return true, 0, ""
	}
	
	return resp.Allowed, int(resp.RetryAfterSeconds), resp.Reason
}

// ReportSuspiciousActivity reports suspicious activity to plugins
func (h *HockeypuckPluginHost) ReportSuspiciousActivity(remoteAddr, description string, severity string) error {
	if !h.initialized {
		return nil
	}
	
	var level proto.ThreatInfo_ThreatLevel
	switch severity {
	case "low":
		level = proto.ThreatInfo_LOW
	case "medium":
		level = proto.ThreatInfo_MEDIUM
	case "high":
		level = proto.ThreatInfo_HIGH
	case "critical":
		level = proto.ThreatInfo_CRITICAL
	default:
		level = proto.ThreatInfo_LOW
	}
	
	indicators := map[string]string{
		"remote_addr": remoteAddr,
		"timestamp":   time.Now().Format(time.RFC3339),
	}
	
	return h.pluginClient.ReportThreat(level, "suspicious_activity", description, "hockeypuck", indicators)
}

// GetPluginStatus returns status of all plugins for monitoring/admin endpoints
func (h *HockeypuckPluginHost) GetPluginStatus() map[string]interface{} {
	if !h.initialized {
		return map[string]interface{}{
			"enabled":     false,
			"initialized": false,
		}
	}
	
	connectedPlugins := h.pluginClient.GetConnectedPlugins()
	allPlugins := h.registry.List()
	
	pluginDetails := make([]map[string]interface{}, 0, len(allPlugins))
	for _, plugin := range allPlugins {
		connected := false
		for _, name := range connectedPlugins {
			if name == plugin.Info.Name {
				connected = true
				break
			}
		}
		
		pluginDetails = append(pluginDetails, map[string]interface{}{
			"name":        plugin.Info.Name,
			"version":     plugin.Info.Version,
			"description": plugin.Info.Description,
			"connected":   connected,
			"executable":  plugin.ExecutablePath,
		})
	}
	
	return map[string]interface{}{
		"enabled":     true,
		"initialized": h.initialized,
		"total":       len(allPlugins),
		"connected":   len(connectedPlugins),
		"plugins":     pluginDetails,
	}
}

// GetPluginHealth returns health status of all plugins from the health monitor
func (h *HockeypuckPluginHost) GetPluginHealth() map[string]interface{} {
	if !h.initialized {
		return map[string]interface{}{
			"status": "not_initialized",
		}
	}
	
	healthData := h.healthMonitor.GetAllHealth()
	result := make(map[string]interface{})
	
	healthyCount := 0
	for name, pluginHealth := range healthData {
		healthy := pluginHealth.Status == health.Healthy
		if healthy {
			healthyCount++
		}
		
		result[name] = map[string]interface{}{
			"status":           pluginHealth.Status.String(),
			"lastCheckTime":    pluginHealth.LastCheckTime,
			"lastHealthyTime":  pluginHealth.LastHealthyTime,
			"failureCount":     pluginHealth.FailureCount,
			"restartCount":     pluginHealth.RestartCount,
			"errorMessage":     pluginHealth.ErrorMessage,
			"responseTime":     pluginHealth.ResponseTime.String(),
			"healthy":          healthy,
		}
	}
	
	result["overall_status"] = map[string]interface{}{
		"healthy":       healthyCount == len(healthData),
		"total_plugins": len(healthData),
		"healthy_count": healthyCount,
	}
	
	return result
}

// RestartPlugin restarts a specific plugin
func (h *HockeypuckPluginHost) RestartPlugin(pluginName string) error {
	if !h.initialized {
		return fmt.Errorf("plugin host not initialized")
	}
	
	// Disconnect from plugin
	h.pluginClient.DisconnectFromPlugin(pluginName)
	
	// Get plugin info from registry
	plugin, exists := h.registry.Get(pluginName)
	if !exists {
		return fmt.Errorf("plugin %s not found in registry", pluginName)
	}
	
	// Stop the plugin process
	if err := h.lifecycleManager.StopPlugin(pluginName); err != nil {
		h.logger.WithError(err).WithField("plugin", pluginName).Warn("Error stopping plugin for restart")
	}
	
	// Wait a moment
	time.Sleep(1 * time.Second)
	
	// Start the plugin again
	if err := h.lifecycleManager.StartPlugin(*plugin); err != nil {
		return fmt.Errorf("failed to restart plugin %s: %w", pluginName, err)
	}
	
	// Wait for it to start
	time.Sleep(2 * time.Second)
	
	// Reconnect
	if err := h.pluginClient.ConnectToPlugin(pluginName); err != nil {
		h.logger.WithError(err).WithField("plugin", pluginName).Warn("Failed to reconnect after restart")
	}
	
	h.logger.WithField("plugin", pluginName).Info("Plugin restarted successfully")
	return nil
}

// HandlePluginManagementEndpoint provides HTTP endpoint for plugin management
func (h *HockeypuckPluginHost) HandlePluginManagementEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/plugins/status":
		h.handlePluginStatus(w, r)
	case "/plugins/health":
		h.handlePluginHealth(w, r)
	case "/plugins/restart":
		h.handlePluginRestart(w, r)
	default:
		// Delegate to health handler for health monitoring endpoints
		if len(r.URL.Path) > 8 && r.URL.Path[:8] == "/health/" {
			h.healthHandler.HandlePluginHealth(w, r)
		} else if r.URL.Path == "/health" {
			h.healthHandler.HandleHealth(w, r)
		} else if r.URL.Path == "/health/liveness" {
			h.healthHandler.HandleLiveness(w, r)
		} else if r.URL.Path == "/health/readiness" {
			h.healthHandler.HandleReadiness(w, r)
		} else {
			http.NotFound(w, r)
		}
	}
}

func (h *HockeypuckPluginHost) handlePluginStatus(w http.ResponseWriter, r *http.Request) {
	status := h.GetPluginStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (h *HockeypuckPluginHost) handlePluginHealth(w http.ResponseWriter, r *http.Request) {
	health := h.GetPluginHealth()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (h *HockeypuckPluginHost) handlePluginRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	pluginName := r.URL.Query().Get("plugin")
	if pluginName == "" {
		http.Error(w, "Plugin name required", http.StatusBadRequest)
		return
	}
	
	if err := h.RestartPlugin(pluginName); err != nil {
		http.Error(w, fmt.Sprintf("Failed to restart plugin: %v", err), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Plugin restarted successfully",
		"plugin":  pluginName,
	})
}