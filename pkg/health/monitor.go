// Package health provides plugin health monitoring and restart capabilities
package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// HealthStatus represents the health status of a plugin
type HealthStatus int

const (
	Unknown HealthStatus = iota
	Healthy
	Unhealthy
	Degraded
	Restarting
	Failed
)

func (s HealthStatus) String() string {
	switch s {
	case Healthy:
		return "healthy"
	case Unhealthy:
		return "unhealthy"
	case Degraded:
		return "degraded"
	case Restarting:
		return "restarting"
	case Failed:
		return "failed"
	default:
		return "unknown"
	}
}

// PluginHealth contains health information for a plugin
type PluginHealth struct {
	Name            string        `json:"name"`
	Status          HealthStatus  `json:"status"`
	LastCheckTime   time.Time     `json:"lastCheckTime"`
	LastHealthyTime time.Time     `json:"lastHealthyTime"`
	FailureCount    int           `json:"failureCount"`
	RestartCount    int           `json:"restartCount"`
	ErrorMessage    string        `json:"errorMessage,omitempty"`
	ResponseTime    time.Duration `json:"responseTime"`
}

// MonitorConfig configures health monitoring behavior
type MonitorConfig struct {
	// How often to check plugin health
	CheckInterval time.Duration
	// How long to wait for health check response
	CheckTimeout time.Duration
	// Number of consecutive failures before marking unhealthy
	FailureThreshold int
	// Number of consecutive successes to mark healthy again
	SuccessThreshold int
	// Maximum number of restart attempts
	MaxRestarts int
	// Backoff strategy for restarts
	RestartBackoff time.Duration
	// Maximum restart backoff time
	MaxRestartBackoff time.Duration
}

// PluginHealthChecker interface for checking plugin health
type PluginHealthChecker interface {
	HealthCheck(ctx context.Context) error
}

// PluginRestarter interface for restarting plugins
type PluginRestarter interface {
	RestartPlugin(ctx context.Context, name string) error
}

// DefaultMonitorConfig returns default monitoring configuration
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		CheckInterval:     30 * time.Second,
		CheckTimeout:      10 * time.Second,
		FailureThreshold:  3,
		SuccessThreshold:  2,
		MaxRestarts:       5,
		RestartBackoff:    5 * time.Second,
		MaxRestartBackoff: 5 * time.Minute,
	}
}

// Monitor provides health monitoring for plugins
type Monitor struct {
	config         MonitorConfig
	logger         *logrus.Logger
	restarter      PluginRestarter
	clients        map[string]PluginHealthChecker
	health         map[string]*PluginHealth
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// NewMonitor creates a new health monitor
func NewMonitor(config MonitorConfig, logger *logrus.Logger, restarter PluginRestarter) *Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Monitor{
		config:    config,
		logger:    logger,
		restarter: restarter,
		clients:   make(map[string]PluginHealthChecker),
		health:    make(map[string]*PluginHealth),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start begins health monitoring
func (m *Monitor) Start() error {
	m.logger.Info("Starting plugin health monitor")
	
	// Start monitoring goroutine
	m.wg.Add(1)
	go m.monitorLoop()
	
	return nil
}

// Stop stops health monitoring
func (m *Monitor) Stop() error {
	m.logger.Info("Stopping plugin health monitor")
	
	m.cancel()
	m.wg.Wait()
	
	return nil
}

// RegisterPlugin registers a plugin for health monitoring
func (m *Monitor) RegisterPlugin(name string, client PluginHealthChecker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.clients[name] = client
	m.health[name] = &PluginHealth{
		Name:            name,
		Status:          Unknown,
		LastCheckTime:   time.Now(),
		LastHealthyTime: time.Now(),
		FailureCount:    0,
		RestartCount:    0,
	}
	
	m.logger.WithField("plugin", name).Info("Plugin registered for health monitoring")
}

// UnregisterPlugin removes a plugin from health monitoring
func (m *Monitor) UnregisterPlugin(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	delete(m.clients, name)
	delete(m.health, name)
	
	m.logger.WithField("plugin", name).Info("Plugin unregistered from health monitoring")
}

// GetHealth returns the health status of a specific plugin
func (m *Monitor) GetHealth(name string) (*PluginHealth, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	health, exists := m.health[name]
	if !exists {
		return nil, false
	}
	
	// Return a copy to avoid race conditions
	healthCopy := *health
	return &healthCopy, true
}

// GetAllHealth returns health status of all plugins
func (m *Monitor) GetAllHealth() map[string]*PluginHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	result := make(map[string]*PluginHealth)
	for name, health := range m.health {
		// Return copies to avoid race conditions
		healthCopy := *health
		result[name] = &healthCopy
	}
	
	return result
}

// IsHealthy returns true if all plugins are healthy
func (m *Monitor) IsHealthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	for _, health := range m.health {
		if health.Status != Healthy {
			return false
		}
	}
	
	return true
}

// GetUnhealthyPlugins returns names of unhealthy plugins
func (m *Monitor) GetUnhealthyPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var unhealthy []string
	for name, health := range m.health {
		if health.Status == Unhealthy || health.Status == Failed {
			unhealthy = append(unhealthy, name)
		}
	}
	
	return unhealthy
}

// monitorLoop runs the main health monitoring loop
func (m *Monitor) monitorLoop() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkAllPlugins()
		}
	}
}

// checkAllPlugins checks the health of all registered plugins
func (m *Monitor) checkAllPlugins() {
	m.mu.RLock()
	clients := make(map[string]PluginHealthChecker)
	for name, client := range m.clients {
		clients[name] = client
	}
	m.mu.RUnlock()
	
	// Check each plugin's health
	for name, client := range clients {
		go m.checkPluginHealth(name, client)
	}
}

// checkPluginHealth checks the health of a specific plugin
func (m *Monitor) checkPluginHealth(name string, client PluginHealthChecker) {
	start := time.Now()
	
	// Create timeout context for health check
	ctx, cancel := context.WithTimeout(m.ctx, m.config.CheckTimeout)
	defer cancel()
	
	// Perform health check
	err := client.HealthCheck(ctx)
	responseTime := time.Since(start)
	
	// Update health status
	m.updatePluginHealth(name, err, responseTime)
	
	// Log health check result
	logger := m.logger.WithFields(logrus.Fields{
		"plugin":       name,
		"responseTime": responseTime,
	})
	
	if err != nil {
		logger.WithError(err).Warn("Plugin health check failed")
	} else {
		logger.Debug("Plugin health check passed")
	}
}

// updatePluginHealth updates the health status of a plugin
func (m *Monitor) updatePluginHealth(name string, err error, responseTime time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	health, exists := m.health[name]
	if !exists {
		return
	}
	
	health.LastCheckTime = time.Now()
	health.ResponseTime = responseTime
	
	if err != nil {
		// Health check failed
		health.FailureCount++
		health.ErrorMessage = err.Error()
		
		// Check if we should mark as unhealthy
		if health.FailureCount >= m.config.FailureThreshold {
			if health.Status != Unhealthy && health.Status != Failed {
				health.Status = Unhealthy
				m.logger.WithFields(logrus.Fields{
					"plugin":       name,
					"failureCount": health.FailureCount,
				}).Warn("Plugin marked as unhealthy")
				
				// Attempt restart if configured
				go m.AttemptRestart(name)
			}
		}
	} else {
		// Health check passed
		health.ErrorMessage = ""
		health.LastHealthyTime = time.Now()
		
		// Check if we should mark as healthy
		if health.Status == Unhealthy || health.Status == Degraded {
			health.FailureCount = 0
			health.Status = Healthy
			m.logger.WithField("plugin", name).Info("Plugin marked as healthy")
		} else if health.Status == Unknown {
			health.Status = Healthy
			m.logger.WithField("plugin", name).Info("Plugin initial health check passed")
		}
	}
}

// AttemptRestart attempts to restart an unhealthy plugin
func (m *Monitor) AttemptRestart(name string) {
	m.mu.Lock()
	health, exists := m.health[name]
	if !exists {
		m.mu.Unlock()
		return
	}
	
	// Check if we've exceeded max restarts
	if health.RestartCount >= m.config.MaxRestarts {
		health.Status = Failed
		m.logger.WithFields(logrus.Fields{
			"plugin":       name,
			"restartCount": health.RestartCount,
		}).Error("Plugin failed - maximum restart attempts exceeded")
		m.mu.Unlock()
		return
	}
	
	health.Status = Restarting
	health.RestartCount++
	restartCount := health.RestartCount
	m.mu.Unlock()
	
	// Calculate backoff time
	backoffTime := m.config.RestartBackoff * time.Duration(restartCount)
	if backoffTime > m.config.MaxRestartBackoff {
		backoffTime = m.config.MaxRestartBackoff
	}
	
	m.logger.WithFields(logrus.Fields{
		"plugin":       name,
		"restartCount": restartCount,
		"backoffTime":  backoffTime,
	}).Info("Attempting plugin restart")
	
	// Wait for backoff period
	time.Sleep(backoffTime)
	
	// Attempt to restart the plugin
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := m.restarter.RestartPlugin(ctx, name); err != nil {
		m.logger.WithError(err).WithField("plugin", name).Error("Failed to restart plugin")
		
		m.mu.Lock()
		if health, exists := m.health[name]; exists {
			health.Status = Failed
			health.ErrorMessage = fmt.Sprintf("Restart failed: %v", err)
		}
		m.mu.Unlock()
	} else {
		m.logger.WithField("plugin", name).Info("Plugin restart completed")
		
		m.mu.Lock()
		if health, exists := m.health[name]; exists {
			health.Status = Unknown // Will be updated by next health check
			health.FailureCount = 0
		}
		m.mu.Unlock()
	}
}