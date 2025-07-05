package recovery

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// RestartStrategy implements plugin restart recovery
type RestartStrategy struct {
	pluginManager PluginManagerInterface
	logger        *slog.Logger
}

// CanRecover determines if restart strategy can handle the failure
func (rs *RestartStrategy) CanRecover(failure *FailureInfo) bool {
	// Restart strategy can handle most failure types except unrecoverable ones
	switch failure.Type {
	case FailureTypeTimeout, FailureTypeError, FailureTypePanic, FailureTypeHealthCheck:
		return failure.Recoverable
	case FailureTypeResourceLimit:
		// Resource limits might be temporary
		return failure.Recoverable
	case FailureTypeInitialization:
		// Initialization failures are usually harder to recover from
		return failure.Severity != "critical"
	default:
		return false
	}
}

// Recover attempts to recover by restarting the plugin
func (rs *RestartStrategy) Recover(ctx context.Context, pluginName string, failure *FailureInfo) error {
	rs.logger.Info("Attempting plugin restart recovery",
		"plugin", pluginName,
		"failure_type", failure.Type)

	// Get the plugin
	currentPlugin, exists := rs.pluginManager.GetPlugin(pluginName)
	if !exists {
		return fmt.Errorf("plugin not found: %s", pluginName)
	}

	// Shutdown the current plugin
	if err := currentPlugin.Shutdown(ctx); err != nil {
		rs.logger.Warn("Failed to gracefully shutdown plugin during restart",
			"plugin", pluginName,
			"error", err)
		// Continue with restart anyway
	}

	// Wait a brief moment for cleanup
	time.Sleep(1 * time.Second)

	// Reinitialize the plugin
	// Note: This is a simplified implementation
	// In practice, you'd need to preserve the original configuration
	config := make(map[string]interface{})

	if err := rs.pluginManager.LoadPlugin(ctx, currentPlugin, config); err != nil {
		return fmt.Errorf("failed to restart plugin: %w", err)
	}

	rs.logger.Info("Plugin restart recovery successful", "plugin", pluginName)
	return nil
}

// GetName returns the strategy name
func (rs *RestartStrategy) GetName() string {
	return "restart"
}

// GetPriority returns the strategy priority
func (rs *RestartStrategy) GetPriority() int {
	return 100 // High priority for general failures
}

// ReloadStrategy implements plugin reload recovery
type ReloadStrategy struct {
	pluginManager PluginManagerInterface
	logger        *slog.Logger
}

// CanRecover determines if reload strategy can handle the failure
func (rs *ReloadStrategy) CanRecover(failure *FailureInfo) bool {
	// Reload is gentler than restart, good for configuration issues
	switch failure.Type {
	case FailureTypeTimeout, FailureTypeError:
		return failure.Severity != "critical"
	case FailureTypeHealthCheck:
		return true
	case FailureTypeInitialization:
		return failure.Severity == "warning"
	default:
		return false
	}
}

// Recover attempts to recover by reloading the plugin
func (rs *ReloadStrategy) Recover(ctx context.Context, pluginName string, failure *FailureInfo) error {
	rs.logger.Info("Attempting plugin reload recovery",
		"plugin", pluginName,
		"failure_type", failure.Type)

	// Get the plugin
	currentPlugin, exists := rs.pluginManager.GetPlugin(pluginName)
	if !exists {
		return fmt.Errorf("plugin not found: %s", pluginName)
	}

	// For reload, we don't shutdown completely, just reinitialize
	// This preserves more state than a full restart
	config := make(map[string]interface{})

	if err := currentPlugin.Initialize(ctx, nil, config); err != nil {
		return fmt.Errorf("failed to reload plugin: %w", err)
	}

	rs.logger.Info("Plugin reload recovery successful", "plugin", pluginName)
	return nil
}

// GetName returns the strategy name
func (rs *ReloadStrategy) GetName() string {
	return "reload"
}

// GetPriority returns the strategy priority
func (rs *ReloadStrategy) GetPriority() int {
	return 80 // Medium-high priority
}

// ResetStrategy implements circuit breaker reset recovery
type ResetStrategy struct {
	recoveryManager *RecoveryManager
	logger          *slog.Logger
}

// CanRecover determines if reset strategy can handle the failure
func (rs *ResetStrategy) CanRecover(failure *FailureInfo) bool {
	// Reset strategy is mainly for health check failures and minor issues
	switch failure.Type {
	case FailureTypeHealthCheck:
		return true
	case FailureTypeTimeout:
		return failure.Severity == "warning"
	default:
		return false
	}
}

// Recover attempts to recover by resetting the circuit breaker
func (rs *ResetStrategy) Recover(ctx context.Context, pluginName string, failure *FailureInfo) error {
	rs.logger.Info("Attempting circuit breaker reset recovery",
		"plugin", pluginName,
		"failure_type", failure.Type)

	rs.recoveryManager.mutex.RLock()
	cb, exists := rs.recoveryManager.circuitBreakers[pluginName]
	rs.recoveryManager.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("circuit breaker not found for plugin: %s", pluginName)
	}

	// Reset the circuit breaker
	cb.Reset()

	rs.logger.Info("Circuit breaker reset recovery successful", "plugin", pluginName)
	return nil
}

// GetName returns the strategy name
func (rs *ResetStrategy) GetName() string {
	return "reset"
}

// GetPriority returns the strategy priority
func (rs *ResetStrategy) GetPriority() int {
	return 60 // Lower priority, gentle recovery
}

// GracefulDegradationStrategy implements graceful degradation
type GracefulDegradationStrategy struct {
	pluginManager PluginManagerInterface
	logger        *slog.Logger
}

// CanRecover determines if graceful degradation can handle the failure
func (gds *GracefulDegradationStrategy) CanRecover(failure *FailureInfo) bool {
	// Graceful degradation is suitable for resource limit failures
	switch failure.Type {
	case FailureTypeResourceLimit:
		return true
	case FailureTypeTimeout:
		return failure.Severity != "critical"
	default:
		return false
	}
}

// Recover attempts to recover by gracefully degrading functionality
func (gds *GracefulDegradationStrategy) Recover(ctx context.Context, pluginName string, failure *FailureInfo) error {
	gds.logger.Info("Attempting graceful degradation recovery",
		"plugin", pluginName,
		"failure_type", failure.Type)

	// Implementation would vary based on plugin type
	// For example:
	// - Reduce processing frequency
	// - Disable non-essential features
	// - Switch to simpler algorithms
	// - Reduce memory usage

	// This is a placeholder implementation
	gds.logger.Info("Graceful degradation recovery applied", "plugin", pluginName)
	return nil
}

// GetName returns the strategy name
func (gds *GracefulDegradationStrategy) GetName() string {
	return "graceful_degradation"
}

// GetPriority returns the strategy priority
func (gds *GracefulDegradationStrategy) GetPriority() int {
	return 40 // Lower priority, used when other strategies aren't suitable
}

// BackoffStrategy implements exponential backoff recovery
type BackoffStrategy struct {
	pluginManager   PluginManagerInterface
	logger          *slog.Logger
	backoffAttempts map[string]int
	lastAttempt     map[string]time.Time
}

// NewBackoffStrategy creates a new backoff strategy
func NewBackoffStrategy(pluginManager PluginManagerInterface, logger *slog.Logger) *BackoffStrategy {
	return &BackoffStrategy{
		pluginManager:   pluginManager,
		logger:          logger,
		backoffAttempts: make(map[string]int),
		lastAttempt:     make(map[string]time.Time),
	}
}

// CanRecover determines if backoff strategy can handle the failure
func (bs *BackoffStrategy) CanRecover(failure *FailureInfo) bool {
	// Backoff is good for temporary failures that might resolve themselves
	switch failure.Type {
	case FailureTypeTimeout, FailureTypeError, FailureTypeHealthCheck:
		return failure.Severity != "critical"
	default:
		return false
	}
}

// Recover attempts to recover using exponential backoff
func (bs *BackoffStrategy) Recover(ctx context.Context, pluginName string, failure *FailureInfo) error {
	bs.logger.Info("Attempting backoff recovery",
		"plugin", pluginName,
		"failure_type", failure.Type)

	// Calculate backoff delay
	attempts := bs.backoffAttempts[pluginName]
	delay := time.Duration(attempts*attempts) * time.Second // Quadratic backoff
	if delay > 60*time.Second {
		delay = 60 * time.Second // Cap at 1 minute
	}

	lastAttempt := bs.lastAttempt[pluginName]
	if time.Since(lastAttempt) < delay {
		return fmt.Errorf("backoff period not elapsed, wait %v", delay-time.Since(lastAttempt))
	}

	// Record this attempt
	bs.backoffAttempts[pluginName] = attempts + 1
	bs.lastAttempt[pluginName] = time.Now()

	// Simple recovery - just wait and hope the issue resolves
	bs.logger.Info("Backoff recovery applied",
		"plugin", pluginName,
		"attempt", attempts+1,
		"delay", delay)

	return nil
}

// GetName returns the strategy name
func (bs *BackoffStrategy) GetName() string {
	return "backoff"
}

// GetPriority returns the strategy priority
func (bs *BackoffStrategy) GetPriority() int {
	return 20 // Low priority, used as last resort
}

// ResetBackoff resets the backoff counter for a plugin
func (bs *BackoffStrategy) ResetBackoff(pluginName string) {
	delete(bs.backoffAttempts, pluginName)
	delete(bs.lastAttempt, pluginName)
}

// CustomStrategy allows for plugin-specific recovery strategies
type CustomStrategy struct {
	name           string
	priority       int
	canRecoverFunc func(*FailureInfo) bool
	recoverFunc    func(context.Context, string, *FailureInfo) error
	logger         *slog.Logger
}

// NewCustomStrategy creates a new custom recovery strategy
func NewCustomStrategy(
	name string,
	priority int,
	canRecover func(*FailureInfo) bool,
	recover func(context.Context, string, *FailureInfo) error,
	logger *slog.Logger,
) *CustomStrategy {
	return &CustomStrategy{
		name:           name,
		priority:       priority,
		canRecoverFunc: canRecover,
		recoverFunc:    recover,
		logger:         logger,
	}
}

// CanRecover determines if custom strategy can handle the failure
func (cs *CustomStrategy) CanRecover(failure *FailureInfo) bool {
	return cs.canRecoverFunc(failure)
}

// Recover attempts to recover using the custom function
func (cs *CustomStrategy) Recover(ctx context.Context, pluginName string, failure *FailureInfo) error {
	cs.logger.Info("Attempting custom recovery",
		"plugin", pluginName,
		"strategy", cs.name,
		"failure_type", failure.Type)

	return cs.recoverFunc(ctx, pluginName, failure)
}

// GetName returns the strategy name
func (cs *CustomStrategy) GetName() string {
	return cs.name
}

// GetPriority returns the strategy priority
func (cs *CustomStrategy) GetPriority() int {
	return cs.priority
}

// RecoveryStrategyFactory creates recovery strategies based on configuration
type RecoveryStrategyFactory struct {
	logger *slog.Logger
}

// NewRecoveryStrategyFactory creates a new factory
func NewRecoveryStrategyFactory(logger *slog.Logger) *RecoveryStrategyFactory {
	return &RecoveryStrategyFactory{logger: logger}
}

// CreateStrategy creates a recovery strategy based on name and config
func (rsf *RecoveryStrategyFactory) CreateStrategy(
	name string,
	config map[string]interface{},
	pluginManager PluginManagerInterface,
) (RecoveryStrategy, error) {
	switch name {
	case "restart":
		return &RestartStrategy{
			pluginManager: pluginManager,
			logger:        rsf.logger,
		}, nil

	case "reload":
		return &ReloadStrategy{
			pluginManager: pluginManager,
			logger:        rsf.logger,
		}, nil

	case "reset":
		// Note: This requires the recovery manager, which creates a circular dependency
		// In practice, you'd pass the recovery manager or handle this differently
		return &ResetStrategy{
			logger: rsf.logger,
		}, nil

	case "graceful_degradation":
		return &GracefulDegradationStrategy{
			pluginManager: pluginManager,
			logger:        rsf.logger,
		}, nil

	case "backoff":
		return NewBackoffStrategy(pluginManager, rsf.logger), nil

	default:
		return nil, fmt.Errorf("unknown recovery strategy: %s", name)
	}
}
