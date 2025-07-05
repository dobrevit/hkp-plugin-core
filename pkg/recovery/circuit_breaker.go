// Package recovery provides automatic failure recovery with circuit breaker patterns
package recovery

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// CircuitBreakerState represents the current state of a circuit breaker
type CircuitBreakerState string

const (
	StateClosed    CircuitBreakerState = "closed"    // Normal operation
	StateOpen      CircuitBreakerState = "open"      // Failing, requests rejected
	StateHalfOpen  CircuitBreakerState = "half_open" // Testing if service recovered
	StateRepairing CircuitBreakerState = "repairing" // Actively attempting repair
)

// CircuitBreaker implements the circuit breaker pattern for plugin failures
type CircuitBreaker struct {
	name                string
	state               CircuitBreakerState
	config              *CircuitBreakerConfig
	failures            int64
	successes           int64
	requests            int64
	lastFailureTime     time.Time
	lastSuccessTime     time.Time
	stateChangeTime     time.Time
	halfOpenSuccesses   int64
	halfOpenFailures    int64
	healthCheckAttempts int64
	mutex               sync.RWMutex
	logger              *slog.Logger
	onStateChange       func(name string, from, to CircuitBreakerState)
}

// CircuitBreakerConfig contains circuit breaker configuration
type CircuitBreakerConfig struct {
	// Failure detection
	FailureThreshold int64         `json:"failure_threshold"` // Failures before opening circuit
	SuccessThreshold int64         `json:"success_threshold"` // Successes in half-open before closing
	Timeout          time.Duration `json:"timeout"`           // Time to wait before half-open

	// Health checking
	HealthCheckInterval time.Duration `json:"health_check_interval"` // Interval for active health checks
	HealthCheckTimeout  time.Duration `json:"health_check_timeout"`  // Timeout for health checks
	MaxHealthChecks     int64         `json:"max_health_checks"`     // Max consecutive health check failures

	// Recovery strategies
	RetryBackoffFactor float64       `json:"retry_backoff_factor"` // Exponential backoff multiplier
	MaxRetryInterval   time.Duration `json:"max_retry_interval"`   // Maximum retry interval
	EnableFastFail     bool          `json:"enable_fast_fail"`     // Fail fast when circuit is open

	// Monitoring
	SlidingWindowSize int64 `json:"sliding_window_size"` // Size of sliding window for metrics
	MinimumRequests   int64 `json:"minimum_requests"`    // Min requests before circuit can open
}

// CircuitBreakerMetrics contains metrics for circuit breaker monitoring
type CircuitBreakerMetrics struct {
	Name               string              `json:"name"`
	State              CircuitBreakerState `json:"state"`
	TotalRequests      int64               `json:"total_requests"`
	TotalFailures      int64               `json:"total_failures"`
	TotalSuccesses     int64               `json:"total_successes"`
	FailureRate        float64             `json:"failure_rate"`
	StateChanges       int64               `json:"state_changes"`
	LastFailure        time.Time           `json:"last_failure"`
	LastSuccess        time.Time           `json:"last_success"`
	StateChangeTime    time.Time           `json:"state_change_time"`
	UpSince            time.Time           `json:"up_since"`
	DownSince          time.Time           `json:"down_since"`
	CircuitOpenTime    time.Duration       `json:"circuit_open_time"`
	HealthCheckSuccess bool                `json:"health_check_success"`
	NextRetryTime      time.Time           `json:"next_retry_time"`
}

// FailureType represents different types of plugin failures
type FailureType string

const (
	FailureTypeTimeout        FailureType = "timeout"
	FailureTypeError          FailureType = "error"
	FailureTypeResourceLimit  FailureType = "resource_limit"
	FailureTypePanic          FailureType = "panic"
	FailureTypeHealthCheck    FailureType = "health_check"
	FailureTypeInitialization FailureType = "initialization"
)

// FailureInfo contains details about a plugin failure
type FailureInfo struct {
	Type        FailureType            `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Message     string                 `json:"message"`
	Stack       string                 `json:"stack,omitempty"`
	Context     map[string]interface{} `json:"context"`
	Recoverable bool                   `json:"recoverable"`
	Severity    string                 `json:"severity"`
}

// NewCircuitBreaker creates a new circuit breaker instance
func NewCircuitBreaker(name string, config *CircuitBreakerConfig, logger *slog.Logger) *CircuitBreaker {
	if logger == nil {
		logger = slog.Default()
	}

	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}

	cb := &CircuitBreaker{
		name:            name,
		state:           StateClosed,
		config:          config,
		stateChangeTime: time.Now(),
		logger:          logger,
	}

	return cb
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, operation func(ctx context.Context) error) error {
	// Check if circuit allows execution
	if !cb.allowRequest() {
		return cb.createCircuitOpenError()
	}

	// Execute operation with timeout
	operationCtx, cancel := context.WithTimeout(ctx, cb.config.HealthCheckTimeout)
	defer cancel()

	err := operation(operationCtx)

	// Record result
	cb.recordResult(err)

	return err
}

// allowRequest determines if a request should be allowed through the circuit
func (cb *CircuitBreaker) allowRequest() bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.requests++

	switch cb.state {
	case StateClosed:
		return true

	case StateOpen:
		if time.Since(cb.stateChangeTime) > cb.config.Timeout {
			cb.transitionTo(StateHalfOpen)
			return true
		}
		return false

	case StateHalfOpen:
		return true

	case StateRepairing:
		return false

	default:
		return false
	}
}

// recordResult records the result of an operation and updates circuit state
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	if err != nil {
		cb.recordFailure(err)
	} else {
		cb.recordSuccess()
	}

	cb.updateState()
}

// recordFailure records a failure and updates metrics
func (cb *CircuitBreaker) recordFailure(err error) {
	cb.failures++
	cb.lastFailureTime = time.Now()

	if cb.state == StateHalfOpen {
		cb.halfOpenFailures++
	}

	cb.logger.Warn("Circuit breaker recorded failure",
		"name", cb.name,
		"error", err.Error(),
		"failures", cb.failures,
		"state", cb.state)
}

// recordSuccess records a success and updates metrics
func (cb *CircuitBreaker) recordSuccess() {
	cb.successes++
	cb.lastSuccessTime = time.Now()

	if cb.state == StateHalfOpen {
		cb.halfOpenSuccesses++
	}

	cb.logger.Debug("Circuit breaker recorded success",
		"name", cb.name,
		"successes", cb.successes,
		"state", cb.state)
}

// updateState updates the circuit breaker state based on current metrics
func (cb *CircuitBreaker) updateState() {
	switch cb.state {
	case StateClosed:
		if cb.shouldOpen() {
			cb.transitionTo(StateOpen)
		}

	case StateHalfOpen:
		if cb.halfOpenSuccesses >= cb.config.SuccessThreshold {
			cb.transitionTo(StateClosed)
		} else if cb.halfOpenFailures > 0 {
			cb.transitionTo(StateOpen)
		}

	case StateOpen:
		// State transitions are handled in allowRequest()
	}
}

// shouldOpen determines if the circuit should transition to open state
func (cb *CircuitBreaker) shouldOpen() bool {
	if cb.requests < cb.config.MinimumRequests {
		return false
	}

	return cb.failures >= cb.config.FailureThreshold
}

// transitionTo transitions the circuit to a new state
func (cb *CircuitBreaker) transitionTo(newState CircuitBreakerState) {
	oldState := cb.state
	cb.state = newState
	cb.stateChangeTime = time.Now()

	// Reset counters based on new state
	switch newState {
	case StateClosed:
		cb.failures = 0
		cb.halfOpenSuccesses = 0
		cb.halfOpenFailures = 0
	case StateHalfOpen:
		cb.halfOpenSuccesses = 0
		cb.halfOpenFailures = 0
	case StateOpen:
		// Keep failure count for metrics
	}

	cb.logger.Info("Circuit breaker state transition",
		"name", cb.name,
		"from", oldState,
		"to", newState,
		"failures", cb.failures)

	// Notify state change callback
	if cb.onStateChange != nil {
		go cb.onStateChange(cb.name, oldState, newState)
	}
}

// createCircuitOpenError creates an error for when circuit is open
func (cb *CircuitBreaker) createCircuitOpenError() error {
	return fmt.Errorf("circuit breaker '%s' is open (state: %s, failures: %d)",
		cb.name, cb.state, cb.failures)
}

// GetMetrics returns current circuit breaker metrics
func (cb *CircuitBreaker) GetMetrics() *CircuitBreakerMetrics {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	failureRate := float64(0)
	if cb.requests > 0 {
		failureRate = float64(cb.failures) / float64(cb.requests)
	}

	var upSince, downSince time.Time
	var circuitOpenTime time.Duration

	switch cb.state {
	case StateClosed, StateHalfOpen:
		upSince = cb.stateChangeTime
	case StateOpen, StateRepairing:
		downSince = cb.stateChangeTime
		circuitOpenTime = time.Since(cb.stateChangeTime)
	}

	return &CircuitBreakerMetrics{
		Name:            cb.name,
		State:           cb.state,
		TotalRequests:   cb.requests,
		TotalFailures:   cb.failures,
		TotalSuccesses:  cb.successes,
		FailureRate:     failureRate,
		LastFailure:     cb.lastFailureTime,
		LastSuccess:     cb.lastSuccessTime,
		StateChangeTime: cb.stateChangeTime,
		UpSince:         upSince,
		DownSince:       downSince,
		CircuitOpenTime: circuitOpenTime,
		NextRetryTime:   cb.getNextRetryTime(),
	}
}

// getNextRetryTime calculates when the next retry attempt should occur
func (cb *CircuitBreaker) getNextRetryTime() time.Time {
	if cb.state != StateOpen {
		return time.Time{}
	}

	return cb.stateChangeTime.Add(cb.config.Timeout)
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	oldState := cb.state
	cb.state = StateClosed
	cb.failures = 0
	cb.successes = 0
	cb.requests = 0
	cb.halfOpenSuccesses = 0
	cb.stateChangeTime = time.Now()

	cb.logger.Info("Circuit breaker reset",
		"name", cb.name,
		"previous_state", oldState)
}

// ForceOpen forces the circuit breaker to open state
func (cb *CircuitBreaker) ForceOpen() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	if cb.state != StateOpen {
		cb.transitionTo(StateOpen)
	}
}

// SetStateChangeCallback sets a callback for state changes
func (cb *CircuitBreaker) SetStateChangeCallback(callback func(name string, from, to CircuitBreakerState)) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	cb.onStateChange = callback
}

// DefaultCircuitBreakerConfig returns a default circuit breaker configuration
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		FailureThreshold:    5,
		SuccessThreshold:    3,
		Timeout:             30 * time.Second,
		HealthCheckInterval: 10 * time.Second,
		HealthCheckTimeout:  5 * time.Second,
		MaxHealthChecks:     3,
		RetryBackoffFactor:  1.5,
		MaxRetryInterval:    5 * time.Minute,
		EnableFastFail:      true,
		SlidingWindowSize:   100,
		MinimumRequests:     10,
	}
}
