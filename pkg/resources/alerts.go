package resources

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// AlertManager handles resource violation alerts
type AlertManager struct {
	alerters    []Alerter
	rateLimiter map[string]*RateLimit
	config      *AlertConfig
	mutex       sync.RWMutex
	logger      *slog.Logger
}

// Alerter defines interface for sending alerts
type Alerter interface {
	SendAlert(alert *Alert) error
	GetAlerterType() AlerterType
}

// AlerterType represents different types of alerters
type AlerterType string

const (
	AlerterTypeLog     AlerterType = "log"
	AlerterTypeEmail   AlerterType = "email"
	AlerterTypeSlack   AlerterType = "slack"
	AlerterTypeWebhook AlerterType = "webhook"
)

// Alert represents a resource violation alert
type Alert struct {
	ID          string                 `json:"id"`
	Type        AlertType              `json:"type"`
	Severity    Severity               `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	PluginName  string                 `json:"plugin_name"`
	Resource    ResourceType           `json:"resource"`
	Violation   *ResourceViolation     `json:"violation"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertType represents different types of alerts
type AlertType string

const (
	AlertTypeResourceViolation AlertType = "resource_violation"
	AlertTypePluginFailure     AlertType = "plugin_failure"
	AlertTypeSecurityEvent     AlertType = "security_event"
	AlertTypeSystemHealth      AlertType = "system_health"
)

// AlertConfig contains alerting configuration
type AlertConfig struct {
	EnabledAlerters    []AlerterType               `json:"enabled_alerters"`
	RateLimitWindow    time.Duration               `json:"rate_limit_window"`
	MaxAlertsPerWindow int                         `json:"max_alerts_per_window"`
	SeverityThresholds map[Severity]bool           `json:"severity_thresholds"`
	Cooldowns          map[AlertType]time.Duration `json:"cooldowns"`
}

// RateLimit tracks alert rate limiting
type RateLimit struct {
	Window      time.Duration
	MaxAlerts   int
	AlertCount  int
	WindowStart time.Time
	mutex       sync.Mutex
}

// NewAlertManager creates a new alert manager
func NewAlertManager() *AlertManager {
	config := DefaultAlertConfig()
	am := &AlertManager{
		alerters:    make([]Alerter, 0),
		rateLimiter: make(map[string]*RateLimit),
		config:      config,
		logger:      slog.Default(),
	}

	// Register default alerters
	am.RegisterAlerter(NewLogAlerter())

	return am
}

// RegisterAlerter registers a new alerter
func (am *AlertManager) RegisterAlerter(alerter Alerter) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	am.alerters = append(am.alerters, alerter)
}

// SendAlert sends an alert through all registered alerters
func (am *AlertManager) SendAlert(violation *ResourceViolation) {
	alert := am.createAlertFromViolation(violation)

	// Check rate limiting
	if !am.checkRateLimit(alert) {
		am.logger.Debug("Alert rate limited", "alert_id", alert.ID, "plugin", alert.PluginName)
		return
	}

	// Check severity threshold
	if !am.checkSeverityThreshold(alert.Severity) {
		return
	}

	// Send through all enabled alerters
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	for _, alerter := range am.alerters {
		if am.isAlerterEnabled(alerter.GetAlerterType()) {
			if err := alerter.SendAlert(alert); err != nil {
				am.logger.Error("Failed to send alert",
					"alerter", alerter.GetAlerterType(),
					"error", err,
					"alert_id", alert.ID)
			}
		}
	}
}

// createAlertFromViolation creates an alert from a resource violation
func (am *AlertManager) createAlertFromViolation(violation *ResourceViolation) *Alert {
	id := fmt.Sprintf("%s-%s-%d", violation.PluginName, violation.ResourceType, violation.Timestamp.Unix())

	title := fmt.Sprintf("Resource Violation: %s", violation.ResourceType)
	description := fmt.Sprintf("Plugin %s exceeded %s limit. Limit: %.2f, Actual: %.2f",
		violation.PluginName, violation.ResourceType, violation.Limit, violation.Actual)

	return &Alert{
		ID:          id,
		Type:        AlertTypeResourceViolation,
		Severity:    violation.Severity,
		Title:       title,
		Description: description,
		PluginName:  violation.PluginName,
		Resource:    violation.ResourceType,
		Violation:   violation,
		Timestamp:   violation.Timestamp,
		Metadata: map[string]interface{}{
			"exceed_ratio": violation.Actual / violation.Limit,
			"action_taken": violation.Action,
		},
	}
}

// checkRateLimit checks if alert is within rate limits
func (am *AlertManager) checkRateLimit(alert *Alert) bool {
	key := fmt.Sprintf("%s-%s", alert.PluginName, alert.Resource)

	am.mutex.Lock()
	defer am.mutex.Unlock()

	rateLimit, exists := am.rateLimiter[key]
	if !exists {
		rateLimit = &RateLimit{
			Window:      am.config.RateLimitWindow,
			MaxAlerts:   am.config.MaxAlertsPerWindow,
			WindowStart: time.Now(),
		}
		am.rateLimiter[key] = rateLimit
	}

	rateLimit.mutex.Lock()
	defer rateLimit.mutex.Unlock()

	now := time.Now()

	// Reset window if expired
	if now.Sub(rateLimit.WindowStart) > rateLimit.Window {
		rateLimit.AlertCount = 0
		rateLimit.WindowStart = now
	}

	// Check if under limit
	if rateLimit.AlertCount >= rateLimit.MaxAlerts {
		return false
	}

	rateLimit.AlertCount++
	return true
}

// checkSeverityThreshold checks if alert severity meets threshold
func (am *AlertManager) checkSeverityThreshold(severity Severity) bool {
	enabled, exists := am.config.SeverityThresholds[severity]
	return !exists || enabled
}

// isAlerterEnabled checks if an alerter type is enabled
func (am *AlertManager) isAlerterEnabled(alerterType AlerterType) bool {
	for _, enabled := range am.config.EnabledAlerters {
		if enabled == alerterType {
			return true
		}
	}
	return false
}

// LogAlerter sends alerts to the log
type LogAlerter struct {
	logger *slog.Logger
}

// NewLogAlerter creates a new log alerter
func NewLogAlerter() *LogAlerter {
	return &LogAlerter{
		logger: slog.Default(),
	}
}

// SendAlert sends an alert to the log
func (la *LogAlerter) SendAlert(alert *Alert) error {
	level := la.severityToLogLevel(alert.Severity)

	la.logger.Log(context.TODO(), level, "Resource Alert",
		"alert_id", alert.ID,
		"type", alert.Type,
		"severity", alert.Severity,
		"plugin", alert.PluginName,
		"resource", alert.Resource,
		"title", alert.Title,
		"description", alert.Description,
		"metadata", alert.Metadata,
	)

	return nil
}

// GetAlerterType returns the alerter type
func (la *LogAlerter) GetAlerterType() AlerterType {
	return AlerterTypeLog
}

// severityToLogLevel converts severity to slog level
func (la *LogAlerter) severityToLogLevel(severity Severity) slog.Level {
	switch severity {
	case SeverityInfo:
		return slog.LevelInfo
	case SeverityWarning:
		return slog.LevelWarn
	case SeverityError:
		return slog.LevelError
	case SeverityCritical:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WebhookAlerter sends alerts to a webhook endpoint
type WebhookAlerter struct {
	url     string
	timeout time.Duration
}

// NewWebhookAlerter creates a new webhook alerter
func NewWebhookAlerter(url string, timeout time.Duration) *WebhookAlerter {
	return &WebhookAlerter{
		url:     url,
		timeout: timeout,
	}
}

// SendAlert sends an alert to a webhook
func (wa *WebhookAlerter) SendAlert(alert *Alert) error {
	// Implementation would send HTTP POST to webhook URL
	// For now, this is a placeholder
	return fmt.Errorf("webhook alerter not implemented")
}

// GetAlerterType returns the alerter type
func (wa *WebhookAlerter) GetAlerterType() AlerterType {
	return AlerterTypeWebhook
}

// DefaultAlertConfig returns a default alert configuration
func DefaultAlertConfig() *AlertConfig {
	return &AlertConfig{
		EnabledAlerters:    []AlerterType{AlerterTypeLog},
		RateLimitWindow:    5 * time.Minute,
		MaxAlertsPerWindow: 10,
		SeverityThresholds: map[Severity]bool{
			SeverityInfo:     false, // Don't alert on info
			SeverityWarning:  true,
			SeverityError:    true,
			SeverityCritical: true,
		},
		Cooldowns: map[AlertType]time.Duration{
			AlertTypeResourceViolation: 1 * time.Minute,
			AlertTypePluginFailure:     30 * time.Second,
			AlertTypeSecurityEvent:     0, // No cooldown for security events
		},
	}
}

// ResourceLimitManager manages resource limits for plugins
type ResourceLimitManager struct {
	limits map[string]*ResourceLimits
	mutex  sync.RWMutex
}

// NewResourceLimitManager creates a new resource limit manager
func NewResourceLimitManager() *ResourceLimitManager {
	return &ResourceLimitManager{
		limits: make(map[string]*ResourceLimits),
	}
}

// SetLimits sets resource limits for a plugin
func (rlm *ResourceLimitManager) SetLimits(pluginName string, limits *ResourceLimits) {
	rlm.mutex.Lock()
	defer rlm.mutex.Unlock()

	rlm.limits[pluginName] = limits
}

// GetLimits gets resource limits for a plugin
func (rlm *ResourceLimitManager) GetLimits(pluginName string) (*ResourceLimits, bool) {
	rlm.mutex.RLock()
	defer rlm.mutex.RUnlock()

	limits, exists := rlm.limits[pluginName]
	return limits, exists
}

// RemoveLimits removes resource limits for a plugin
func (rlm *ResourceLimitManager) RemoveLimits(pluginName string) {
	rlm.mutex.Lock()
	defer rlm.mutex.Unlock()

	delete(rlm.limits, pluginName)
}

// GetAllLimits returns all configured limits
func (rlm *ResourceLimitManager) GetAllLimits() map[string]*ResourceLimits {
	rlm.mutex.RLock()
	defer rlm.mutex.RUnlock()

	// Return copy
	result := make(map[string]*ResourceLimits)
	for k, v := range rlm.limits {
		result[k] = &ResourceLimits{
			MaxMemoryMB:     v.MaxMemoryMB,
			MaxCPUPercent:   v.MaxCPUPercent,
			MaxGoroutines:   v.MaxGoroutines,
			MaxFileHandles:  v.MaxFileHandles,
			MaxConnections:  v.MaxConnections,
			MaxDiskIOBPS:    v.MaxDiskIOBPS,
			MaxNetworkIOBPS: v.MaxNetworkIOBPS,
		}
	}

	return result
}

// DefaultResourceLimits returns default resource limits
func DefaultResourceLimits() *ResourceLimits {
	return &ResourceLimits{
		MaxMemoryMB:     512,      // 512MB
		MaxCPUPercent:   25.0,     // 25% CPU
		MaxGoroutines:   100,      // 100 goroutines
		MaxFileHandles:  50,       // 50 file handles
		MaxConnections:  20,       // 20 network connections
		MaxDiskIOBPS:    10485760, // 10MB/s disk I/O
		MaxNetworkIOBPS: 5242880,  // 5MB/s network I/O
	}
}
