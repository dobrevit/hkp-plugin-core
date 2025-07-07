package lifecycle

import (
	"fmt"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/discovery"
	"github.com/sirupsen/logrus"
)

// RestartPolicy defines how plugins should be restarted
type RestartPolicy struct {
	// Maximum number of restart attempts
	MaxAttempts int
	// Delay between restart attempts
	Delay time.Duration
	// Time window for counting failures
	Window time.Duration
	// Backoff multiplier for exponential backoff
	BackoffMultiplier float64
	// Maximum backoff delay
	MaxBackoff time.Duration
}

// DefaultRestartPolicy returns a sensible default restart policy
func DefaultRestartPolicy() *RestartPolicy {
	return &RestartPolicy{
		MaxAttempts:       3,
		Delay:             5 * time.Second,
		Window:            5 * time.Minute,
		BackoffMultiplier: 2.0,
		MaxBackoff:        1 * time.Minute,
	}
}

// RestartTracker tracks restart attempts for plugins
type RestartTracker struct {
	attempts map[string]*attemptRecord
	mutex    sync.RWMutex
	policy   *RestartPolicy
}

type attemptRecord struct {
	count       int
	lastAttempt time.Time
	nextDelay   time.Duration
}

// NewRestartTracker creates a new restart tracker
func NewRestartTracker(policy *RestartPolicy) *RestartTracker {
	if policy == nil {
		policy = DefaultRestartPolicy()
	}
	return &RestartTracker{
		attempts: make(map[string]*attemptRecord),
		policy:   policy,
	}
}

// ShouldRestart determines if a plugin should be restarted
func (rt *RestartTracker) ShouldRestart(pluginName string) (bool, time.Duration) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	record, exists := rt.attempts[pluginName]
	if !exists {
		record = &attemptRecord{
			count:       0,
			lastAttempt: time.Time{},
			nextDelay:   rt.policy.Delay,
		}
		rt.attempts[pluginName] = record
	}

	// Check if outside the failure window
	if time.Since(record.lastAttempt) > rt.policy.Window {
		// Reset the counter
		record.count = 0
		record.nextDelay = rt.policy.Delay
	}

	// Check if we've exceeded max attempts
	if record.count >= rt.policy.MaxAttempts {
		return false, 0
	}

	return true, record.nextDelay
}

// RecordRestart records a restart attempt
func (rt *RestartTracker) RecordRestart(pluginName string) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	record, exists := rt.attempts[pluginName]
	if !exists {
		record = &attemptRecord{
			count:       0,
			lastAttempt: time.Time{},
			nextDelay:   rt.policy.Delay,
		}
		rt.attempts[pluginName] = record
	}

	record.count++
	record.lastAttempt = time.Now()

	// Calculate next delay with exponential backoff
	record.nextDelay = time.Duration(float64(record.nextDelay) * rt.policy.BackoffMultiplier)
	if record.nextDelay > rt.policy.MaxBackoff {
		record.nextDelay = rt.policy.MaxBackoff
	}
}

// Reset clears restart attempts for a plugin
func (rt *RestartTracker) Reset(pluginName string) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	delete(rt.attempts, pluginName)
}

// RestartManager handles plugin restarts
type RestartManager struct {
	manager *Manager
	tracker *RestartTracker
	logger  *logrus.Logger
}

// NewRestartManager creates a new restart manager
func NewRestartManager(manager *Manager, policy *RestartPolicy, logger *logrus.Logger) *RestartManager {
	return &RestartManager{
		manager: manager,
		tracker: NewRestartTracker(policy),
		logger:  logger,
	}
}

// HandlePluginExit handles when a plugin exits unexpectedly
func (rm *RestartManager) HandlePluginExit(plugin discovery.DiscoveredPlugin, exitError error) {
	logger := rm.logger.WithField("plugin", plugin.Info.Name)
	
	// Check if we should restart
	shouldRestart, delay := rm.tracker.ShouldRestart(plugin.Info.Name)
	if !shouldRestart {
		logger.WithError(exitError).Error("Plugin crashed too many times, not restarting")
		return
	}

	// Record the restart attempt
	rm.tracker.RecordRestart(plugin.Info.Name)

	logger.WithField("delay", delay).Info("Scheduling plugin restart")

	// Schedule restart after delay
	time.AfterFunc(delay, func() {
		logger.Info("Restarting plugin")
		if err := rm.manager.StartPlugin(plugin); err != nil {
			logger.WithError(err).Error("Failed to restart plugin")
			// This will trigger another restart attempt if within limits
		} else {
			// Reset counter on successful restart
			rm.tracker.Reset(plugin.Info.Name)
		}
	})
}

// GracefulRestart performs a graceful restart of a plugin
func (rm *RestartManager) GracefulRestart(pluginName string) error {
	proc, exists := rm.manager.GetPlugin(pluginName)
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}

	plugin := proc.Plugin

	// Stop the plugin
	if err := rm.manager.StopPlugin(pluginName); err != nil {
		return fmt.Errorf("failed to stop plugin: %w", err)
	}

	// Wait a moment
	time.Sleep(1 * time.Second)

	// Start it again
	if err := rm.manager.StartPlugin(plugin); err != nil {
		return fmt.Errorf("failed to start plugin: %w", err)
	}

	return nil
}