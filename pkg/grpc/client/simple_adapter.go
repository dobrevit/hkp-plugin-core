// Package client provides a simple adapter for easy Hockeypuck integration
package client

import (
	"context"
	"net/http"

	"github.com/dobrevit/hkp-plugin-core/pkg/config"
	"github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
	"github.com/sirupsen/logrus"
)

// SimplePluginAdapter provides a minimal interface for Hockeypuck integration
type SimplePluginAdapter struct {
	host *HockeypuckPluginHost
}

// NewSimplePluginAdapter creates a new simple adapter
func NewSimplePluginAdapter(pluginDir string, logger *logrus.Logger) *SimplePluginAdapter {
	settings := &config.Settings{
		Plugins: config.PluginConfig{
			Enabled:   true,
			Directory: pluginDir,
		},
	}
	
	host := NewHockeypuckPluginHost(settings, logger)
	
	return &SimplePluginAdapter{
		host: host,
	}
}

// Start initializes and starts the plugin system
func (s *SimplePluginAdapter) Start(ctx context.Context) error {
	return s.host.Initialize(ctx)
}

// Stop shuts down the plugin system
func (s *SimplePluginAdapter) Stop(ctx context.Context) error {
	return s.host.Shutdown(ctx)
}

// HTTPMiddleware returns middleware for HTTP request processing
func (s *SimplePluginAdapter) HTTPMiddleware() func(http.Handler) http.Handler {
	return s.host.GetHTTPMiddleware()
}

// OnKeyChange notifies plugins of key changes
func (s *SimplePluginAdapter) OnKeyChange(change hkpstorage.KeyChange) error {
	return s.host.NotifyKeyChange(change)
}

// CheckRateLimit checks if a request should be rate limited
func (s *SimplePluginAdapter) CheckRateLimit(remoteAddr, operation string) (allowed bool, retryAfter int, reason string) {
	return s.host.CheckRateLimit(remoteAddr, operation)
}

// ReportSuspiciousActivity reports suspicious activity to plugins
func (s *SimplePluginAdapter) ReportSuspiciousActivity(remoteAddr, description string, severity string) error {
	return s.host.ReportSuspiciousActivity(remoteAddr, description, severity)
}

// GetStatus returns plugin status for monitoring
func (s *SimplePluginAdapter) GetStatus() map[string]interface{} {
	return s.host.GetPluginStatus()
}

// GetHealth returns plugin health status
func (s *SimplePluginAdapter) GetHealth() map[string]interface{} {
	return s.host.GetPluginHealth()
}

// HandleManagement handles plugin management HTTP endpoints
func (s *SimplePluginAdapter) HandleManagement(w http.ResponseWriter, r *http.Request) {
	s.host.HandlePluginManagementEndpoint(w, r)
}

// Example usage documentation for Hockeypuck developers:
//
// // In your Hockeypuck server initialization:
// pluginAdapter := client.NewSimplePluginAdapter("/etc/hockeypuck/plugins", logger)
// 
// // Start plugins
// if err := pluginAdapter.Start(ctx); err != nil {
//     logger.WithError(err).Error("Failed to start plugins")
// }
// 
// // Add HTTP middleware
// handler = pluginAdapter.HTTPMiddleware()(handler)
// 
// // Add plugin management endpoints
// mux.HandleFunc("/plugins/", pluginAdapter.HandleManagement)
// 
// // In your key storage notification code:
// pluginAdapter.OnKeyChange(hkpstorage.KeyChange{
//     ChangeType:  hkpstorage.KeyAdded,
//     Fingerprint: fingerprint,
//     PrimaryKey:  key,
// })
// 
// // In your HTTP handlers for rate limiting:
// if allowed, retryAfter, reason := pluginAdapter.CheckRateLimit(r.RemoteAddr, "lookup"); !allowed {
//     w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
//     http.Error(w, fmt.Sprintf("Rate limited: %s", reason), http.StatusTooManyRequests)
//     return
// }
// 
// // For reporting suspicious activity:
// pluginAdapter.ReportSuspiciousActivity(r.RemoteAddr, "Multiple failed requests", "medium")
// 
// // During shutdown:
// pluginAdapter.Stop(ctx)