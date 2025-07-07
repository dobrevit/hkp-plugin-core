// Package health provides HTTP handlers for plugin health monitoring
package health

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// HealthHandler provides HTTP endpoints for plugin health monitoring
type HealthHandler struct {
	monitor *Monitor
	logger  *logrus.Logger
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(monitor *Monitor, logger *logrus.Logger) *HealthHandler {
	return &HealthHandler{
		monitor: monitor,
		logger:  logger,
	}
}

// HealthResponse represents the JSON response for health checks
type HealthResponse struct {
	Status    string                     `json:"status"`
	Timestamp time.Time                  `json:"timestamp"`
	Plugins   map[string]*PluginHealth   `json:"plugins"`
	Summary   HealthSummary              `json:"summary"`
}

// HealthSummary provides a summary of overall plugin health
type HealthSummary struct {
	TotalPlugins    int `json:"totalPlugins"`
	HealthyPlugins  int `json:"healthyPlugins"`
	UnhealthyPlugins int `json:"unhealthyPlugins"`
	RestartingPlugins int `json:"restartingPlugins"`
	FailedPlugins   int `json:"failedPlugins"`
}

// HandleHealth handles GET /health requests
func (h *HealthHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get all plugin health information
	pluginHealth := h.monitor.GetAllHealth()
	
	// Calculate summary statistics
	summary := h.calculateSummary(pluginHealth)
	
	// Determine overall status
	overallStatus := "healthy"
	if summary.FailedPlugins > 0 {
		overallStatus = "critical"
	} else if summary.UnhealthyPlugins > 0 || summary.RestartingPlugins > 0 {
		overallStatus = "degraded"
	}
	
	// Create response
	response := HealthResponse{
		Status:    overallStatus,
		Timestamp: time.Now(),
		Plugins:   pluginHealth,
		Summary:   summary,
	}
	
	// Set appropriate HTTP status code
	statusCode := http.StatusOK
	if overallStatus == "critical" {
		statusCode = http.StatusServiceUnavailable
	} else if overallStatus == "degraded" {
		statusCode = http.StatusPartialContent
	}
	
	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to encode health response")
	}
}

// HandlePluginHealth handles GET /health/{pluginName} requests
func (h *HealthHandler) HandlePluginHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract plugin name from URL
	pluginName := r.URL.Path[len("/health/"):]
	if pluginName == "" {
		http.Error(w, "Plugin name required", http.StatusBadRequest)
		return
	}

	// Get plugin health
	health, exists := h.monitor.GetHealth(pluginName)
	if !exists {
		http.Error(w, "Plugin not found", http.StatusNotFound)
		return
	}

	// Create response
	response := map[string]interface{}{
		"plugin": health,
		"timestamp": time.Now(),
	}

	// Set appropriate HTTP status code
	statusCode := http.StatusOK
	if health.Status == Failed {
		statusCode = http.StatusServiceUnavailable
	} else if health.Status == Unhealthy || health.Status == Restarting {
		statusCode = http.StatusPartialContent
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to encode plugin health response")
	}
}

// HandleRestart handles POST /health/{pluginName}/restart requests
func (h *HealthHandler) HandleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract plugin name from URL
	pluginName := r.URL.Path[len("/health/"):]
	if pluginName == "" {
		http.Error(w, "Plugin name required", http.StatusBadRequest)
		return
	}
	
	// Remove "/restart" suffix
	if len(pluginName) > 8 && pluginName[len(pluginName)-8:] == "/restart" {
		pluginName = pluginName[:len(pluginName)-8]
	}

	// Check if plugin exists
	if _, exists := h.monitor.GetHealth(pluginName); !exists {
		http.Error(w, "Plugin not found", http.StatusNotFound)
		return
	}

	// Trigger restart
	go h.monitor.AttemptRestart(pluginName)

	// Send response
	response := map[string]interface{}{
		"message": fmt.Sprintf("Restart initiated for plugin %s", pluginName),
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to encode restart response")
	}
}

// HandleLiveness handles GET /health/liveness requests (for Kubernetes)
func (h *HealthHandler) HandleLiveness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Liveness check - just check if monitoring is running
	response := map[string]interface{}{
		"status": "alive",
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to encode liveness response")
	}
}

// HandleReadiness handles GET /health/readiness requests (for Kubernetes)
func (h *HealthHandler) HandleReadiness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Readiness check - check if all plugins are healthy
	isReady := h.monitor.IsHealthy()
	
	response := map[string]interface{}{
		"status": "ready",
		"ready": isReady,
		"timestamp": time.Now(),
	}

	statusCode := http.StatusOK
	if !isReady {
		statusCode = http.StatusServiceUnavailable
		response["status"] = "not ready"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to encode readiness response")
	}
}

// calculateSummary calculates health summary statistics
func (h *HealthHandler) calculateSummary(pluginHealth map[string]*PluginHealth) HealthSummary {
	summary := HealthSummary{
		TotalPlugins: len(pluginHealth),
	}

	for _, health := range pluginHealth {
		switch health.Status {
		case Healthy:
			summary.HealthyPlugins++
		case Unhealthy, Degraded:
			summary.UnhealthyPlugins++
		case Restarting:
			summary.RestartingPlugins++
		case Failed:
			summary.FailedPlugins++
		}
	}

	return summary
}

// RegisterRoutes registers health check routes with a HTTP mux
func (h *HealthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/health/", h.HandlePluginHealth)
	mux.HandleFunc("/health/liveness", h.HandleLiveness)
	mux.HandleFunc("/health/readiness", h.HandleReadiness)
}