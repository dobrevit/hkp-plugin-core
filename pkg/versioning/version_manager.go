// Package versioning provides multi-version plugin support with canary deployments
package versioning

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/pkg/security"
)

// VersionManager manages multiple versions of plugins with canary deployments
type VersionManager struct {
	plugins     map[string]*PluginVersions
	deployments map[string]*CanaryDeployment
	auditLogger security.SecurityAuditLogger
	config      *VersionConfig
	mutex       sync.RWMutex
	logger      *slog.Logger
	running     bool
	stopChan    chan struct{}
}

// PluginVersions holds multiple versions of a plugin
type PluginVersions struct {
	Name           string
	CurrentVersion string
	Versions       map[string]*PluginVersion
	CanaryVersion  string
	CanaryPercent  float64
	VersionHistory []VersionHistoryEntry
	mutex          sync.RWMutex
}

// PluginVersion represents a specific version of a plugin
type PluginVersion struct {
	Plugin       plugin.Plugin
	Version      string
	Status       VersionStatus
	LoadTime     time.Time
	LastAccessed time.Time
	RequestCount int64
	ErrorCount   int64
	HealthScore  float64
	Metadata     map[string]interface{}
	Dependencies []plugin.PluginDependency
	Config       map[string]interface{}
}

// VersionStatus represents the status of a plugin version
type VersionStatus string

const (
	VersionStatusLoading    VersionStatus = "loading"
	VersionStatusActive     VersionStatus = "active"
	VersionStatusCanary     VersionStatus = "canary"
	VersionStatusDeprecated VersionStatus = "deprecated"
	VersionStatusFailed     VersionStatus = "failed"
	VersionStatusRetired    VersionStatus = "retired"
)

// VersionHistoryEntry tracks version deployment history
type VersionHistoryEntry struct {
	Version       string
	Action        string
	Timestamp     time.Time
	Success       bool
	ErrorMessage  string
	CanaryPercent float64
	Duration      time.Duration
}

// CanaryDeployment manages canary deployment configuration
type CanaryDeployment struct {
	PluginName       string
	OldVersion       string
	NewVersion       string
	CanaryPercent    float64
	StartTime        time.Time
	Duration         time.Duration
	SuccessThreshold float64
	ErrorThreshold   float64
	AutoPromote      bool
	AutoRollback     bool
	Status           CanaryStatus
	Metrics          *CanaryMetrics
	Config           *CanaryConfig
	mutex            sync.RWMutex
}

// CanaryStatus represents the status of a canary deployment
type CanaryStatus string

const (
	CanaryStatusPending     CanaryStatus = "pending"
	CanaryStatusActive      CanaryStatus = "active"
	CanaryStatusPromoting   CanaryStatus = "promoting"
	CanaryStatusRollingBack CanaryStatus = "rolling_back"
	CanaryStatusCompleted   CanaryStatus = "completed"
	CanaryStatusFailed      CanaryStatus = "failed"
)

// CanaryMetrics tracks canary deployment metrics
type CanaryMetrics struct {
	TotalRequests         int64
	CanaryRequests        int64
	CanaryErrors          int64
	CanarySuccesses       int64
	CanaryErrorRate       float64
	CanarySuccessRate     float64
	CanaryResponseTime    time.Duration
	ProductionErrorRate   float64
	ProductionSuccessRate float64
	HealthScore           float64
	LastUpdated           time.Time
}

// CanaryConfig contains canary deployment configuration
type CanaryConfig struct {
	InitialPercent     float64             `json:"initial_percent"`
	IncrementPercent   float64             `json:"increment_percent"`
	IncrementInterval  time.Duration       `json:"increment_interval"`
	MaxPercent         float64             `json:"max_percent"`
	SuccessThreshold   float64             `json:"success_threshold"`
	ErrorThreshold     float64             `json:"error_threshold"`
	MinRequests        int64               `json:"min_requests"`
	ObservationPeriod  time.Duration       `json:"observation_period"`
	AutoPromote        bool                `json:"auto_promote"`
	AutoRollback       bool                `json:"auto_rollback"`
	NotificationConfig *NotificationConfig `json:"notification_config"`
}

// NotificationConfig contains notification settings for canary deployments
type NotificationConfig struct {
	EnableNotifications bool     `json:"enable_notifications"`
	WebhookURL          string   `json:"webhook_url"`
	EmailRecipients     []string `json:"email_recipients"`
	SlackChannel        string   `json:"slack_channel"`
	NotifyOnStart       bool     `json:"notify_on_start"`
	NotifyOnComplete    bool     `json:"notify_on_complete"`
	NotifyOnFailure     bool     `json:"notify_on_failure"`
}

// VersionConfig contains version management configuration
type VersionConfig struct {
	MaxVersionsPerPlugin   int           `json:"max_versions_per_plugin"`
	DefaultCanaryConfig    *CanaryConfig `json:"default_canary_config"`
	AutoCleanupOldVersions bool          `json:"auto_cleanup_old_versions"`
	CleanupThreshold       time.Duration `json:"cleanup_threshold"`
	HealthCheckInterval    time.Duration `json:"health_check_interval"`
	MetricsRetentionPeriod time.Duration `json:"metrics_retention_period"`
	EnableVersionHistory   bool          `json:"enable_version_history"`
	HistoryRetentionPeriod time.Duration `json:"history_retention_period"`
}

// NewVersionManager creates a new version manager
func NewVersionManager(
	auditLogger security.SecurityAuditLogger,
	config *VersionConfig,
	logger *slog.Logger,
) *VersionManager {
	if logger == nil {
		logger = slog.Default()
	}

	if config == nil {
		config = DefaultVersionConfig()
	}

	return &VersionManager{
		plugins:     make(map[string]*PluginVersions),
		deployments: make(map[string]*CanaryDeployment),
		auditLogger: auditLogger,
		config:      config,
		logger:      logger,
		stopChan:    make(chan struct{}),
	}
}

// Start starts the version manager
func (vm *VersionManager) Start(ctx context.Context) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if vm.running {
		return fmt.Errorf("version manager is already running")
	}

	vm.running = true

	// Start background monitoring
	go vm.startCanaryMonitoring(ctx)
	go vm.startHealthChecking(ctx)
	go vm.startCleanupRoutine(ctx)

	vm.logger.Info("Version manager started")
	return nil
}

// Stop stops the version manager
func (vm *VersionManager) Stop() error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if !vm.running {
		return nil
	}

	vm.running = false
	close(vm.stopChan)

	vm.logger.Info("Version manager stopped")
	return nil
}

// RegisterPluginVersion registers a new plugin version
func (vm *VersionManager) RegisterPluginVersion(
	pluginName string,
	version string,
	pluginInstance plugin.Plugin,
	config map[string]interface{},
) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	versions, exists := vm.plugins[pluginName]
	if !exists {
		versions = &PluginVersions{
			Name:     pluginName,
			Versions: make(map[string]*PluginVersion),
		}
		vm.plugins[pluginName] = versions
	}

	versions.mutex.Lock()
	defer versions.mutex.Unlock()

	// Check if version already exists
	if _, exists := versions.Versions[version]; exists {
		return fmt.Errorf("version %s already exists for plugin %s", version, pluginName)
	}

	// Create plugin version
	pluginVersion := &PluginVersion{
		Plugin:       pluginInstance,
		Version:      version,
		Status:       VersionStatusLoading,
		LoadTime:     time.Now(),
		LastAccessed: time.Now(),
		HealthScore:  100.0,
		Metadata:     make(map[string]interface{}),
		Dependencies: pluginInstance.Dependencies(),
		Config:       config,
	}

	versions.Versions[version] = pluginVersion

	// If this is the first version, make it current
	if versions.CurrentVersion == "" {
		versions.CurrentVersion = version
		pluginVersion.Status = VersionStatusActive
	}

	// Add to version history
	if vm.config.EnableVersionHistory {
		versions.VersionHistory = append(versions.VersionHistory, VersionHistoryEntry{
			Version:   version,
			Action:    "registered",
			Timestamp: time.Now(),
			Success:   true,
		})
	}

	// Log the registration
	vm.auditLogger.LogSecurityEvent("plugin_version_registered", map[string]interface{}{
		"plugin_name": pluginName,
		"version":     version,
		"timestamp":   time.Now(),
	})

	vm.logger.Info("Plugin version registered",
		"plugin", pluginName,
		"version", version)

	return nil
}

// GetPluginVersion returns the appropriate version for a request
func (vm *VersionManager) GetPluginVersion(pluginName string, forCanary bool) (*PluginVersion, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	versions, exists := vm.plugins[pluginName]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginName)
	}

	versions.mutex.RLock()
	defer versions.mutex.RUnlock()

	// Check if we should use canary version
	if forCanary && versions.CanaryVersion != "" {
		if canaryVersion, exists := versions.Versions[versions.CanaryVersion]; exists {
			canaryVersion.LastAccessed = time.Now()
			canaryVersion.RequestCount++
			return canaryVersion, nil
		}
	}

	// Use current version
	currentVersion, exists := versions.Versions[versions.CurrentVersion]
	if !exists {
		return nil, fmt.Errorf("current version %s not found for plugin %s", versions.CurrentVersion, pluginName)
	}

	currentVersion.LastAccessed = time.Now()
	currentVersion.RequestCount++
	return currentVersion, nil
}

// StartCanaryDeployment starts a canary deployment for a plugin
func (vm *VersionManager) StartCanaryDeployment(
	pluginName string,
	newVersion string,
	canaryConfig *CanaryConfig,
) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	versions, exists := vm.plugins[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}

	versions.mutex.Lock()
	defer versions.mutex.Unlock()

	// Check if new version exists
	newVersionInstance, exists := versions.Versions[newVersion]
	if !exists {
		return fmt.Errorf("version %s not found for plugin %s", newVersion, pluginName)
	}

	// Check if canary deployment already exists
	if _, exists := vm.deployments[pluginName]; exists {
		return fmt.Errorf("canary deployment already active for plugin %s", pluginName)
	}

	// Use default config if not provided
	if canaryConfig == nil {
		canaryConfig = vm.config.DefaultCanaryConfig
	}

	// Create canary deployment
	deployment := &CanaryDeployment{
		PluginName:       pluginName,
		OldVersion:       versions.CurrentVersion,
		NewVersion:       newVersion,
		CanaryPercent:    canaryConfig.InitialPercent,
		StartTime:        time.Now(),
		Duration:         canaryConfig.ObservationPeriod,
		SuccessThreshold: canaryConfig.SuccessThreshold,
		ErrorThreshold:   canaryConfig.ErrorThreshold,
		AutoPromote:      canaryConfig.AutoPromote,
		AutoRollback:     canaryConfig.AutoRollback,
		Status:           CanaryStatusActive,
		Config:           canaryConfig,
		Metrics: &CanaryMetrics{
			LastUpdated: time.Now(),
		},
	}

	vm.deployments[pluginName] = deployment

	// Set canary version
	versions.CanaryVersion = newVersion
	versions.CanaryPercent = canaryConfig.InitialPercent
	newVersionInstance.Status = VersionStatusCanary

	// Add to version history
	if vm.config.EnableVersionHistory {
		versions.VersionHistory = append(versions.VersionHistory, VersionHistoryEntry{
			Version:       newVersion,
			Action:        "canary_started",
			Timestamp:     time.Now(),
			Success:       true,
			CanaryPercent: canaryConfig.InitialPercent,
		})
	}

	// Log the canary deployment
	vm.auditLogger.LogSecurityEvent("canary_deployment_started", map[string]interface{}{
		"plugin_name":    pluginName,
		"old_version":    versions.CurrentVersion,
		"new_version":    newVersion,
		"canary_percent": canaryConfig.InitialPercent,
		"timestamp":      time.Now(),
	})

	vm.logger.Info("Canary deployment started",
		"plugin", pluginName,
		"old_version", versions.CurrentVersion,
		"new_version", newVersion,
		"canary_percent", canaryConfig.InitialPercent)

	return nil
}

// ShouldUseCanary determines if a request should use the canary version
func (vm *VersionManager) ShouldUseCanary(pluginName string, requestID string) bool {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	deployment, exists := vm.deployments[pluginName]
	if !exists || deployment.Status != CanaryStatusActive {
		return false
	}

	versions, exists := vm.plugins[pluginName]
	if !exists || versions.CanaryVersion == "" {
		return false
	}

	// Simple hash-based traffic splitting
	// In production, you'd want a more sophisticated approach
	hash := simpleHash(requestID)
	return float64(hash%100) < versions.CanaryPercent
}

// RecordCanaryMetrics records metrics for a canary deployment
func (vm *VersionManager) RecordCanaryMetrics(pluginName string, success bool, responseTime time.Duration) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	deployment, exists := vm.deployments[pluginName]
	if !exists {
		return
	}

	deployment.mutex.Lock()
	defer deployment.mutex.Unlock()

	deployment.Metrics.CanaryRequests++
	deployment.Metrics.TotalRequests++

	if success {
		deployment.Metrics.CanarySuccesses++
	} else {
		deployment.Metrics.CanaryErrors++
	}

	// Update rates
	if deployment.Metrics.CanaryRequests > 0 {
		deployment.Metrics.CanaryErrorRate = float64(deployment.Metrics.CanaryErrors) / float64(deployment.Metrics.CanaryRequests)
		deployment.Metrics.CanarySuccessRate = float64(deployment.Metrics.CanarySuccesses) / float64(deployment.Metrics.CanaryRequests)
	}

	deployment.Metrics.CanaryResponseTime = responseTime
	deployment.Metrics.LastUpdated = time.Now()

	// Calculate health score
	deployment.Metrics.HealthScore = calculateHealthScore(deployment.Metrics)
}

// PromoteCanary promotes a canary deployment to production
func (vm *VersionManager) PromoteCanary(pluginName string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	deployment, exists := vm.deployments[pluginName]
	if !exists {
		return fmt.Errorf("no canary deployment found for plugin %s", pluginName)
	}

	versions, exists := vm.plugins[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}

	deployment.mutex.Lock()
	defer deployment.mutex.Unlock()

	versions.mutex.Lock()
	defer versions.mutex.Unlock()

	// Update deployment status
	deployment.Status = CanaryStatusPromoting

	// Mark old version as deprecated
	if oldVersion, exists := versions.Versions[deployment.OldVersion]; exists {
		oldVersion.Status = VersionStatusDeprecated
	}

	// Promote canary to current
	if newVersion, exists := versions.Versions[deployment.NewVersion]; exists {
		newVersion.Status = VersionStatusActive
	}

	oldVersion := versions.CurrentVersion
	versions.CurrentVersion = deployment.NewVersion
	versions.CanaryVersion = ""
	versions.CanaryPercent = 0

	// Complete deployment
	deployment.Status = CanaryStatusCompleted

	// Add to version history
	if vm.config.EnableVersionHistory {
		versions.VersionHistory = append(versions.VersionHistory, VersionHistoryEntry{
			Version:   deployment.NewVersion,
			Action:    "promoted",
			Timestamp: time.Now(),
			Success:   true,
			Duration:  time.Since(deployment.StartTime),
		})
	}

	// Log the promotion
	vm.auditLogger.LogSecurityEvent("canary_deployment_promoted", map[string]interface{}{
		"plugin_name": pluginName,
		"old_version": oldVersion,
		"new_version": deployment.NewVersion,
		"timestamp":   time.Now(),
		"duration":    time.Since(deployment.StartTime),
	})

	vm.logger.Info("Canary deployment promoted",
		"plugin", pluginName,
		"old_version", oldVersion,
		"new_version", deployment.NewVersion)

	// Clean up deployment
	delete(vm.deployments, pluginName)

	return nil
}

// RollbackCanary rolls back a canary deployment
func (vm *VersionManager) RollbackCanary(pluginName string, reason string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	deployment, exists := vm.deployments[pluginName]
	if !exists {
		return fmt.Errorf("no canary deployment found for plugin %s", pluginName)
	}

	versions, exists := vm.plugins[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}

	deployment.mutex.Lock()
	defer deployment.mutex.Unlock()

	versions.mutex.Lock()
	defer versions.mutex.Unlock()

	// Update deployment status
	deployment.Status = CanaryStatusRollingBack

	// Mark canary version as failed
	if canaryVersion, exists := versions.Versions[deployment.NewVersion]; exists {
		canaryVersion.Status = VersionStatusFailed
	}

	// Reset canary settings
	versions.CanaryVersion = ""
	versions.CanaryPercent = 0

	// Complete rollback
	deployment.Status = CanaryStatusFailed

	// Add to version history
	if vm.config.EnableVersionHistory {
		versions.VersionHistory = append(versions.VersionHistory, VersionHistoryEntry{
			Version:      deployment.NewVersion,
			Action:       "rolled_back",
			Timestamp:    time.Now(),
			Success:      false,
			ErrorMessage: reason,
			Duration:     time.Since(deployment.StartTime),
		})
	}

	// Log the rollback
	vm.auditLogger.LogSecurityEvent("canary_deployment_rolled_back", map[string]interface{}{
		"plugin_name": pluginName,
		"old_version": deployment.OldVersion,
		"new_version": deployment.NewVersion,
		"reason":      reason,
		"timestamp":   time.Now(),
		"duration":    time.Since(deployment.StartTime),
	})

	vm.logger.Warn("Canary deployment rolled back",
		"plugin", pluginName,
		"old_version", deployment.OldVersion,
		"new_version", deployment.NewVersion,
		"reason", reason)

	// Clean up deployment
	delete(vm.deployments, pluginName)

	return nil
}

// GetVersionStatus returns the version status for a plugin
func (vm *VersionManager) GetVersionStatus(pluginName string) (map[string]interface{}, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	versions, exists := vm.plugins[pluginName]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginName)
	}

	versions.mutex.RLock()
	defer versions.mutex.RUnlock()

	status := map[string]interface{}{
		"plugin_name":     pluginName,
		"current_version": versions.CurrentVersion,
		"canary_version":  versions.CanaryVersion,
		"canary_percent":  versions.CanaryPercent,
		"versions":        make(map[string]interface{}),
	}

	versionDetails := make(map[string]interface{})
	for version, pluginVersion := range versions.Versions {
		versionDetails[version] = map[string]interface{}{
			"status":        pluginVersion.Status,
			"load_time":     pluginVersion.LoadTime,
			"last_accessed": pluginVersion.LastAccessed,
			"request_count": pluginVersion.RequestCount,
			"error_count":   pluginVersion.ErrorCount,
			"health_score":  pluginVersion.HealthScore,
		}
	}
	status["versions"] = versionDetails

	// Add canary deployment info if active
	if deployment, exists := vm.deployments[pluginName]; exists {
		deployment.mutex.RLock()
		status["canary_deployment"] = map[string]interface{}{
			"status":            deployment.Status,
			"start_time":        deployment.StartTime,
			"canary_percent":    deployment.CanaryPercent,
			"success_threshold": deployment.SuccessThreshold,
			"error_threshold":   deployment.ErrorThreshold,
			"metrics":           deployment.Metrics,
		}
		deployment.mutex.RUnlock()
	}

	return status, nil
}

// startCanaryMonitoring starts monitoring canary deployments
func (vm *VersionManager) startCanaryMonitoring(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-vm.stopChan:
			return
		case <-ticker.C:
			vm.monitorCanaryDeployments()
		}
	}
}

// monitorCanaryDeployments monitors active canary deployments
func (vm *VersionManager) monitorCanaryDeployments() {
	vm.mutex.RLock()
	deployments := make([]*CanaryDeployment, 0, len(vm.deployments))
	for _, deployment := range vm.deployments {
		deployments = append(deployments, deployment)
	}
	vm.mutex.RUnlock()

	for _, deployment := range deployments {
		vm.checkCanaryDeployment(deployment)
	}
}

// checkCanaryDeployment checks if a canary deployment should be promoted or rolled back
func (vm *VersionManager) checkCanaryDeployment(deployment *CanaryDeployment) {
	deployment.mutex.RLock()
	pluginName := deployment.PluginName
	status := deployment.Status
	metrics := deployment.Metrics
	config := deployment.Config
	startTime := deployment.StartTime
	deployment.mutex.RUnlock()

	if status != CanaryStatusActive {
		return
	}

	// Check if we have enough data
	if metrics.CanaryRequests < config.MinRequests {
		return
	}

	// Check if observation period has passed
	if time.Since(startTime) < config.ObservationPeriod {
		return
	}

	// Check error threshold
	if metrics.CanaryErrorRate > config.ErrorThreshold {
		if deployment.AutoRollback {
			vm.RollbackCanary(pluginName, fmt.Sprintf("error rate %.2f%% exceeds threshold %.2f%%",
				metrics.CanaryErrorRate*100, config.ErrorThreshold*100))
		}
		return
	}

	// Check success threshold
	if metrics.CanarySuccessRate >= config.SuccessThreshold {
		if deployment.AutoPromote {
			vm.PromoteCanary(pluginName)
		}
		return
	}

	// Gradually increase canary percentage
	if config.IncrementPercent > 0 && deployment.CanaryPercent < config.MaxPercent {
		vm.incrementCanaryPercent(pluginName, config.IncrementPercent)
	}
}

// incrementCanaryPercent increases the canary percentage
func (vm *VersionManager) incrementCanaryPercent(pluginName string, increment float64) {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	versions, exists := vm.plugins[pluginName]
	if !exists {
		return
	}

	deployment, exists := vm.deployments[pluginName]
	if !exists {
		return
	}

	versions.mutex.Lock()
	deployment.mutex.Lock()
	defer versions.mutex.Unlock()
	defer deployment.mutex.Unlock()

	newPercent := deployment.CanaryPercent + increment
	if newPercent > deployment.Config.MaxPercent {
		newPercent = deployment.Config.MaxPercent
	}

	deployment.CanaryPercent = newPercent
	versions.CanaryPercent = newPercent

	vm.logger.Info("Canary percentage increased",
		"plugin", pluginName,
		"old_percent", deployment.CanaryPercent-increment,
		"new_percent", newPercent)
}

// startHealthChecking starts health checking for plugin versions
func (vm *VersionManager) startHealthChecking(ctx context.Context) {
	ticker := time.NewTicker(vm.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-vm.stopChan:
			return
		case <-ticker.C:
			vm.performHealthChecks()
		}
	}
}

// performHealthChecks performs health checks on all plugin versions
func (vm *VersionManager) performHealthChecks() {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	for _, versions := range vm.plugins {
		versions.mutex.RLock()
		for _, version := range versions.Versions {
			vm.checkVersionHealth(version)
		}
		versions.mutex.RUnlock()
	}
}

// checkVersionHealth checks the health of a plugin version
func (vm *VersionManager) checkVersionHealth(version *PluginVersion) {
	// Calculate health score based on error rate and recency
	errorRate := float64(0)
	if version.RequestCount > 0 {
		errorRate = float64(version.ErrorCount) / float64(version.RequestCount)
	}

	// Simple health score calculation
	healthScore := 100.0 - (errorRate * 100)
	if healthScore < 0 {
		healthScore = 0
	}

	// Reduce score if version hasn't been accessed recently
	timeSinceAccess := time.Since(version.LastAccessed)
	if timeSinceAccess > time.Hour {
		healthScore *= 0.8
	}

	version.HealthScore = healthScore
}

// startCleanupRoutine starts the cleanup routine for old versions
func (vm *VersionManager) startCleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-vm.stopChan:
			return
		case <-ticker.C:
			if vm.config.AutoCleanupOldVersions {
				vm.cleanupOldVersions()
			}
		}
	}
}

// cleanupOldVersions removes old, unused plugin versions
func (vm *VersionManager) cleanupOldVersions() {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	for _, versions := range vm.plugins {
		versions.mutex.Lock()
		vm.cleanupPluginVersions(versions)
		versions.mutex.Unlock()
	}
}

// cleanupPluginVersions cleans up old versions for a specific plugin
func (vm *VersionManager) cleanupPluginVersions(versions *PluginVersions) {
	if len(versions.Versions) <= vm.config.MaxVersionsPerPlugin {
		return
	}

	// Find candidates for cleanup
	candidates := make([]*PluginVersion, 0)
	for _, version := range versions.Versions {
		if version.Status == VersionStatusDeprecated &&
			time.Since(version.LastAccessed) > vm.config.CleanupThreshold {
			candidates = append(candidates, version)
		}
	}

	// Sort by last accessed time (oldest first)
	// Implementation omitted for brevity

	// Remove excess versions
	toRemove := len(versions.Versions) - vm.config.MaxVersionsPerPlugin
	if toRemove > len(candidates) {
		toRemove = len(candidates)
	}

	for i := 0; i < toRemove; i++ {
		version := candidates[i]
		delete(versions.Versions, version.Version)

		vm.logger.Info("Cleaned up old plugin version",
			"plugin", versions.Name,
			"version", version.Version,
			"last_accessed", version.LastAccessed)
	}
}

// DefaultVersionConfig returns default version management configuration
func DefaultVersionConfig() *VersionConfig {
	return &VersionConfig{
		MaxVersionsPerPlugin:   5,
		AutoCleanupOldVersions: true,
		CleanupThreshold:       24 * time.Hour,
		HealthCheckInterval:    5 * time.Minute,
		MetricsRetentionPeriod: 7 * 24 * time.Hour,
		EnableVersionHistory:   true,
		HistoryRetentionPeriod: 30 * 24 * time.Hour,
		DefaultCanaryConfig: &CanaryConfig{
			InitialPercent:    5.0,
			IncrementPercent:  5.0,
			IncrementInterval: 10 * time.Minute,
			MaxPercent:        50.0,
			SuccessThreshold:  0.99,
			ErrorThreshold:    0.01,
			MinRequests:       100,
			ObservationPeriod: 30 * time.Minute,
			AutoPromote:       true,
			AutoRollback:      true,
		},
	}
}

// Helper functions

// simpleHash creates a simple hash for traffic splitting
func simpleHash(s string) int {
	hash := uint32(0)
	for _, c := range s {
		hash = hash*31 + uint32(c)
	}
	// Use unsigned arithmetic to avoid negative values
	return int(hash & 0x7FFFFFFF) // Keep positive by masking the sign bit
}

// calculateHealthScore calculates health score based on metrics
func calculateHealthScore(metrics *CanaryMetrics) float64 {
	if metrics.CanaryRequests == 0 {
		return 100.0
	}

	// Base score on success rate
	score := metrics.CanarySuccessRate * 100

	// Adjust based on error rate
	if metrics.CanaryErrorRate > 0.05 {
		score *= 0.5
	} else if metrics.CanaryErrorRate > 0.01 {
		score *= 0.8
	}

	// Ensure score is within bounds
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}
