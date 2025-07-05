package recovery

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/pkg/security"
)

// RecoveryManager manages automatic failure recovery for plugins
type RecoveryManager struct {
	circuitBreakers    map[string]*CircuitBreaker
	recoveryStrategies map[string]RecoveryStrategy
	pluginManager      PluginManagerInterface
	auditLogger        security.SecurityAuditLogger
	config             *RecoveryConfig
	healthCheckers     map[string]*HealthChecker
	mutex              sync.RWMutex
	logger             *slog.Logger
	running            bool
	stopChan           chan struct{}
}

// RecoveryConfig contains configuration for the recovery manager
type RecoveryConfig struct {
	// Global settings
	EnableAutoRecovery    bool          `json:"enable_auto_recovery"`
	HealthCheckInterval   time.Duration `json:"health_check_interval"`
	MaxRecoveryAttempts   int           `json:"max_recovery_attempts"`
	RecoveryBackoffFactor float64       `json:"recovery_backoff_factor"`

	// Circuit breaker defaults
	DefaultCircuitBreaker *CircuitBreakerConfig `json:"default_circuit_breaker"`

	// Recovery strategies
	DefaultRecoveryStrategy  string                            `json:"default_recovery_strategy"`
	PluginRecoveryStrategies map[string]string                 `json:"plugin_recovery_strategies"`
	RecoveryStrategyConfigs  map[string]map[string]interface{} `json:"recovery_strategy_configs"`

	// Health checking
	EnableHealthChecking   bool          `json:"enable_health_checking"`
	HealthCheckTimeout     time.Duration `json:"health_check_timeout"`
	HealthCheckConcurrency int           `json:"health_check_concurrency"`

	// Alerting
	EnableAlerting  bool             `json:"enable_alerting"`
	AlertThresholds *AlertThresholds `json:"alert_thresholds"`
}

// AlertThresholds defines when to send alerts
type AlertThresholds struct {
	ConsecutiveFailures int           `json:"consecutive_failures"`
	FailureRate         float64       `json:"failure_rate"`
	RecoveryTime        time.Duration `json:"recovery_time"`
}

// PluginManagerInterface defines the interface for plugin management
type PluginManagerInterface interface {
	GetPlugin(name string) (plugin.Plugin, bool)
	ListPlugins() []plugin.Plugin
	LoadPlugin(ctx context.Context, plugin plugin.Plugin, config map[string]interface{}) error
	// Add methods for restarting/reloading plugins
}

// RecoveryStrategy defines how to recover from different types of failures
type RecoveryStrategy interface {
	// CanRecover determines if this strategy can handle the failure
	CanRecover(failure *FailureInfo) bool

	// Recover attempts to recover from the failure
	Recover(ctx context.Context, pluginName string, failure *FailureInfo) error

	// GetName returns the strategy name
	GetName() string

	// GetPriority returns strategy priority (higher = more preferred)
	GetPriority() int
}

// HealthChecker performs health checks on plugins
type HealthChecker struct {
	pluginName       string
	config           *HealthCheckConfig
	lastCheck        time.Time
	lastResult       *HealthCheckResult
	consecutiveFails int
	mutex            sync.RWMutex
}

// HealthCheckConfig contains health check configuration
type HealthCheckConfig struct {
	Interval     time.Duration          `json:"interval"`
	Timeout      time.Duration          `json:"timeout"`
	MaxFailures  int                    `json:"max_failures"`
	CheckType    string                 `json:"check_type"`
	CustomChecks map[string]interface{} `json:"custom_checks"`
}

// HealthCheckResult contains the result of a health check
type HealthCheckResult struct {
	Healthy   bool                   `json:"healthy"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  time.Duration          `json:"duration"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details"`
	CheckType string                 `json:"check_type"`
}

// NewRecoveryManager creates a new recovery manager
func NewRecoveryManager(
	pluginManager PluginManagerInterface,
	auditLogger security.SecurityAuditLogger,
	config *RecoveryConfig,
	logger *slog.Logger,
) *RecoveryManager {
	if logger == nil {
		logger = slog.Default()
	}

	if config == nil {
		config = DefaultRecoveryConfig()
	}

	rm := &RecoveryManager{
		circuitBreakers:    make(map[string]*CircuitBreaker),
		recoveryStrategies: make(map[string]RecoveryStrategy),
		healthCheckers:     make(map[string]*HealthChecker),
		pluginManager:      pluginManager,
		auditLogger:        auditLogger,
		config:             config,
		logger:             logger,
		stopChan:           make(chan struct{}),
	}

	// Register default recovery strategies
	rm.registerDefaultStrategies()

	return rm
}

// Start starts the recovery manager
func (rm *RecoveryManager) Start(ctx context.Context) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if rm.running {
		return fmt.Errorf("recovery manager is already running")
	}

	rm.running = true

	// Initialize circuit breakers for existing plugins
	rm.initializeCircuitBreakers()

	// Start health checking if enabled
	if rm.config.EnableHealthChecking {
		go rm.startHealthChecking(ctx)
	}

	// Start recovery monitoring
	go rm.startRecoveryMonitoring(ctx)

	rm.logger.Info("Recovery manager started",
		"auto_recovery", rm.config.EnableAutoRecovery,
		"health_checking", rm.config.EnableHealthChecking)

	return nil
}

// Stop stops the recovery manager
func (rm *RecoveryManager) Stop() error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if !rm.running {
		return nil
	}

	rm.running = false
	close(rm.stopChan)

	rm.logger.Info("Recovery manager stopped")
	return nil
}

// RegisterPlugin registers a plugin with the recovery manager
func (rm *RecoveryManager) RegisterPlugin(pluginName string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	return rm.registerPluginInternal(pluginName)
}

// UnregisterPlugin unregisters a plugin from the recovery manager
func (rm *RecoveryManager) UnregisterPlugin(pluginName string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	delete(rm.circuitBreakers, pluginName)
	delete(rm.healthCheckers, pluginName)

	rm.logger.Info("Plugin unregistered from recovery manager", "plugin", pluginName)
	return nil
}

// ExecuteWithRecovery executes an operation with circuit breaker protection
func (rm *RecoveryManager) ExecuteWithRecovery(
	ctx context.Context,
	pluginName string,
	operation func(ctx context.Context) error,
) error {
	cb, exists := rm.circuitBreakers[pluginName]
	if !exists {
		// Register plugin automatically if not found
		if err := rm.RegisterPlugin(pluginName); err != nil {
			return fmt.Errorf("failed to register plugin for recovery: %w", err)
		}
		cb = rm.circuitBreakers[pluginName]
	}

	return cb.Execute(ctx, operation)
}

// RecordFailure records a failure for a plugin
func (rm *RecoveryManager) RecordFailure(pluginName string, failure *FailureInfo) {
	rm.mutex.RLock()
	cb, exists := rm.circuitBreakers[pluginName]
	rm.mutex.RUnlock()

	if !exists {
		rm.logger.Warn("Circuit breaker not found for plugin", "plugin", pluginName)
		return
	}

	// Create a dummy error for the circuit breaker
	err := fmt.Errorf("plugin failure: %s (%s)", failure.Message, failure.Type)
	cb.recordResult(err)

	// Log the failure for audit
	rm.auditLogger.LogFailureRecovery(pluginName, string(failure.Type), "recorded", true)

	// Attempt recovery if enabled
	if rm.config.EnableAutoRecovery {
		go rm.attemptRecovery(pluginName, failure)
	}
}

// attemptRecovery attempts to recover a failed plugin
func (rm *RecoveryManager) attemptRecovery(pluginName string, failure *FailureInfo) {
	strategy := rm.selectRecoveryStrategy(pluginName, failure)
	if strategy == nil {
		rm.logger.Warn("No recovery strategy found",
			"plugin", pluginName,
			"failure_type", failure.Type)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rm.logger.Info("Attempting recovery",
		"plugin", pluginName,
		"strategy", strategy.GetName(),
		"failure_type", failure.Type)

	err := strategy.Recover(ctx, pluginName, failure)
	success := err == nil

	rm.auditLogger.LogFailureRecovery(
		pluginName,
		string(failure.Type),
		strategy.GetName(),
		success,
	)

	if success {
		rm.logger.Info("Plugin recovery successful",
			"plugin", pluginName,
			"strategy", strategy.GetName())

		// Reset circuit breaker on successful recovery
		if cb, exists := rm.circuitBreakers[pluginName]; exists {
			cb.Reset()
		}
	} else {
		rm.logger.Error("Plugin recovery failed",
			"plugin", pluginName,
			"strategy", strategy.GetName(),
			"error", err)
	}
}

// selectRecoveryStrategy selects the best recovery strategy for a failure
func (rm *RecoveryManager) selectRecoveryStrategy(pluginName string, failure *FailureInfo) RecoveryStrategy {
	// Check plugin-specific strategy first
	if strategyName, exists := rm.config.PluginRecoveryStrategies[pluginName]; exists {
		if strategy, found := rm.recoveryStrategies[strategyName]; found {
			if strategy.CanRecover(failure) {
				return strategy
			}
		}
	}

	// Find best strategy by priority and capability
	var bestStrategy RecoveryStrategy
	var bestPriority int

	for _, strategy := range rm.recoveryStrategies {
		if strategy.CanRecover(failure) && strategy.GetPriority() > bestPriority {
			bestStrategy = strategy
			bestPriority = strategy.GetPriority()
		}
	}

	return bestStrategy
}

// onCircuitBreakerStateChange handles circuit breaker state changes
func (rm *RecoveryManager) onCircuitBreakerStateChange(pluginName string, from, to CircuitBreakerState) {
	rm.logger.Info("Circuit breaker state changed",
		"plugin", pluginName,
		"from", from,
		"to", to)

	// Log state change for audit
	rm.auditLogger.LogSecurityEvent("circuit_breaker_state_change", map[string]interface{}{
		"plugin_name": pluginName,
		"from_state":  from,
		"to_state":    to,
		"timestamp":   time.Now(),
	})

	// Send alerts if configured
	if rm.config.EnableAlerting && to == StateOpen {
		rm.sendAlert(pluginName, "circuit_breaker_open", map[string]interface{}{
			"from_state": from,
			"to_state":   to,
		})
	}
}

// initializeCircuitBreakers creates circuit breakers for existing plugins
func (rm *RecoveryManager) initializeCircuitBreakers() {
	plugins := rm.pluginManager.ListPlugins()
	for _, p := range plugins {
		rm.registerPluginInternal(p.Name())
	}
}

// registerPluginInternal registers a plugin without acquiring the mutex (internal use)
func (rm *RecoveryManager) registerPluginInternal(pluginName string) error {
	// Create circuit breaker
	config := rm.config.DefaultCircuitBreaker
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}

	cb := NewCircuitBreaker(pluginName, config, rm.logger)
	cb.SetStateChangeCallback(rm.onCircuitBreakerStateChange)
	rm.circuitBreakers[pluginName] = cb

	// Create health checker
	if rm.config.EnableHealthChecking {
		healthConfig := &HealthCheckConfig{
			Interval:    rm.config.HealthCheckInterval,
			Timeout:     rm.config.HealthCheckTimeout,
			MaxFailures: 3,
			CheckType:   "basic",
		}

		rm.healthCheckers[pluginName] = &HealthChecker{
			pluginName: pluginName,
			config:     healthConfig,
		}
	}

	rm.logger.Info("Plugin registered with recovery manager", "plugin", pluginName)
	return nil
}

// startHealthChecking starts the health checking goroutine
func (rm *RecoveryManager) startHealthChecking(ctx context.Context) {
	ticker := time.NewTicker(rm.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopChan:
			return
		case <-ticker.C:
			rm.performHealthChecks()
		}
	}
}

// performHealthChecks performs health checks on all registered plugins
func (rm *RecoveryManager) performHealthChecks() {
	rm.mutex.RLock()
	checkers := make([]*HealthChecker, 0, len(rm.healthCheckers))
	for _, checker := range rm.healthCheckers {
		checkers = append(checkers, checker)
	}
	rm.mutex.RUnlock()

	// Limit concurrency
	semaphore := make(chan struct{}, rm.config.HealthCheckConcurrency)

	for _, checker := range checkers {
		go func(hc *HealthChecker) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			rm.performHealthCheck(hc)
		}(checker)
	}
}

// performHealthCheck performs a health check on a single plugin
func (rm *RecoveryManager) performHealthCheck(checker *HealthChecker) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), checker.config.Timeout)
	defer cancel()

	result := &HealthCheckResult{
		Timestamp: start,
		CheckType: checker.config.CheckType,
		Details:   make(map[string]interface{}),
	}

	// Perform the actual health check
	healthy, message := rm.doHealthCheck(ctx, checker.pluginName)

	result.Healthy = healthy
	result.Message = message
	result.Duration = time.Since(start)

	checker.mutex.Lock()
	checker.lastCheck = start
	checker.lastResult = result

	if healthy {
		checker.consecutiveFails = 0
	} else {
		checker.consecutiveFails++
	}

	shouldAlert := checker.consecutiveFails >= checker.config.MaxFailures
	checker.mutex.Unlock()

	if !healthy {
		rm.logger.Warn("Health check failed",
			"plugin", checker.pluginName,
			"consecutive_fails", checker.consecutiveFails,
			"message", message)

		if shouldAlert {
			failure := &FailureInfo{
				Type:        FailureTypeHealthCheck,
				Timestamp:   start,
				Message:     message,
				Recoverable: true,
				Severity:    "warning",
				Context: map[string]interface{}{
					"consecutive_failures": checker.consecutiveFails,
					"check_duration":       result.Duration,
				},
			}

			rm.RecordFailure(checker.pluginName, failure)
		}
	}
}

// doHealthCheck performs the actual health check logic
func (rm *RecoveryManager) doHealthCheck(ctx context.Context, pluginName string) (bool, string) {
	// Get plugin
	plugin, exists := rm.pluginManager.GetPlugin(pluginName)
	if !exists {
		return false, "plugin not found"
	}

	// Basic check - plugin exists
	// Note: In a full implementation, you'd add proper health check methods
	if plugin == nil {
		return false, "plugin is nil"
	}

	// TODO: Add more sophisticated health checks
	// - Memory usage checks
	// - Response time checks
	// - Custom plugin health endpoints

	return true, "healthy"
}

// startRecoveryMonitoring starts monitoring for recovery opportunities
func (rm *RecoveryManager) startRecoveryMonitoring(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopChan:
			return
		case <-ticker.C:
			rm.monitorRecoveryOpportunities()
		}
	}
}

// monitorRecoveryOpportunities checks for plugins that might be ready for recovery
func (rm *RecoveryManager) monitorRecoveryOpportunities() {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	for pluginName, cb := range rm.circuitBreakers {
		metrics := cb.GetMetrics()

		// Check if circuit breaker is open and ready for retry
		if metrics.State == StateOpen && time.Now().After(metrics.NextRetryTime) {
			rm.logger.Debug("Circuit breaker ready for retry",
				"plugin", pluginName,
				"open_time", metrics.CircuitOpenTime)

			// The circuit breaker will automatically transition to half-open
			// on the next request
		}
	}
}

// sendAlert sends an alert for a plugin event
func (rm *RecoveryManager) sendAlert(pluginName, alertType string, details map[string]interface{}) {
	// This is a placeholder for alert implementation
	rm.logger.Warn("Plugin alert",
		"plugin", pluginName,
		"alert_type", alertType,
		"details", details)
}

// GetRecoveryStatus returns the current recovery status for all plugins
func (rm *RecoveryManager) GetRecoveryStatus() map[string]interface{} {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	status := map[string]interface{}{
		"running":         rm.running,
		"auto_recovery":   rm.config.EnableAutoRecovery,
		"health_checking": rm.config.EnableHealthChecking,
		"plugins":         make(map[string]interface{}),
	}

	plugins := make(map[string]interface{})

	for pluginName, cb := range rm.circuitBreakers {
		metrics := cb.GetMetrics()

		pluginStatus := map[string]interface{}{
			"circuit_breaker": metrics,
		}

		// Add health check info if available
		if hc, exists := rm.healthCheckers[pluginName]; exists {
			hc.mutex.RLock()
			pluginStatus["health_check"] = map[string]interface{}{
				"last_check":        hc.lastCheck,
				"last_result":       hc.lastResult,
				"consecutive_fails": hc.consecutiveFails,
			}
			hc.mutex.RUnlock()
		}

		plugins[pluginName] = pluginStatus
	}

	status["plugins"] = plugins
	return status
}

// registerDefaultStrategies registers default recovery strategies
func (rm *RecoveryManager) registerDefaultStrategies() {
	// Register restart strategy
	rm.recoveryStrategies["restart"] = &RestartStrategy{
		pluginManager: rm.pluginManager,
		logger:        rm.logger,
	}

	// Register reload strategy
	rm.recoveryStrategies["reload"] = &ReloadStrategy{
		pluginManager: rm.pluginManager,
		logger:        rm.logger,
	}

	// Register circuit breaker reset strategy
	rm.recoveryStrategies["reset"] = &ResetStrategy{
		recoveryManager: rm,
		logger:          rm.logger,
	}

	// Register graceful degradation strategy
	rm.recoveryStrategies["graceful_degradation"] = &GracefulDegradationStrategy{
		pluginManager: rm.pluginManager,
		logger:        rm.logger,
	}

	// Register backoff strategy
	rm.recoveryStrategies["backoff"] = NewBackoffStrategy(rm.pluginManager, rm.logger)
}

// DefaultRecoveryConfig returns a default recovery configuration
func DefaultRecoveryConfig() *RecoveryConfig {
	return &RecoveryConfig{
		EnableAutoRecovery:       true,
		HealthCheckInterval:      30 * time.Second,
		MaxRecoveryAttempts:      3,
		RecoveryBackoffFactor:    1.5,
		DefaultCircuitBreaker:    DefaultCircuitBreakerConfig(),
		DefaultRecoveryStrategy:  "restart",
		PluginRecoveryStrategies: make(map[string]string),
		RecoveryStrategyConfigs:  make(map[string]map[string]interface{}),
		EnableHealthChecking:     true,
		HealthCheckTimeout:       10 * time.Second,
		HealthCheckConcurrency:   5,
		EnableAlerting:           true,
		AlertThresholds: &AlertThresholds{
			ConsecutiveFailures: 3,
			FailureRate:         0.5,
			RecoveryTime:        5 * time.Minute,
		},
	}
}
