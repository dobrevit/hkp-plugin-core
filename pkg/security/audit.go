package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SecurityAuditEvent represents a security audit event
type SecurityAuditEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	Source    string                 `json:"source"`
	Actor     string                 `json:"actor,omitempty"`
	Target    string                 `json:"target,omitempty"`
	Result    string                 `json:"result"`
	Details   map[string]interface{} `json:"details"`
	Severity  SeverityLevel          `json:"severity"`
	RequestID string                 `json:"request_id,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
}

// SeverityLevel represents the severity of a security event
type SeverityLevel string

const (
	SeverityInfo     SeverityLevel = "info"
	SeverityWarning  SeverityLevel = "warning"
	SeverityError    SeverityLevel = "error"
	SeverityCritical SeverityLevel = "critical"
)

// FileSecurityAuditLogger implements SecurityAuditLogger using file-based logging
type FileSecurityAuditLogger struct {
	logPath    string
	logger     *slog.Logger
	file       *os.File
	mutex      sync.Mutex
	bufferSize int
	buffer     []*SecurityAuditEvent
}

// NewFileSecurityAuditLogger creates a new file-based security audit logger
func NewFileSecurityAuditLogger(logPath string) (*FileSecurityAuditLogger, error) {
	// Create log directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file for appending
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	// Create structured logger
	logger := slog.New(slog.NewJSONHandler(file, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}))

	return &FileSecurityAuditLogger{
		logPath:    logPath,
		logger:     logger,
		file:       file,
		bufferSize: 100,
		buffer:     make([]*SecurityAuditEvent, 0, 100),
	}, nil
}

// LogVerification logs a plugin verification event
func (fsal *FileSecurityAuditLogger) LogVerification(pluginPath string, result *VerificationResult) {
	severity := SeverityInfo
	eventResult := "success"

	if !result.Valid {
		severity = SeverityError
		eventResult = "failure"
	}

	details := map[string]interface{}{
		"plugin_path":       pluginPath,
		"algorithm":         result.Algorithm,
		"revocation_status": result.RevocationStatus,
	}

	if result.Certificate != nil {
		details["certificate"] = map[string]interface{}{
			"subject":       result.Certificate.Subject,
			"issuer":        result.Certificate.Issuer,
			"fingerprint":   result.Certificate.Fingerprint,
			"serial_number": result.Certificate.SerialNumber,
			"not_before":    result.Certificate.NotBefore,
			"not_after":     result.Certificate.NotAfter,
		}
	}

	if result.Error != "" {
		details["error"] = result.Error
	}

	event := &SecurityAuditEvent{
		Timestamp: result.Timestamp,
		EventType: "plugin_verification",
		Source:    "plugin_verifier",
		Target:    pluginPath,
		Result:    eventResult,
		Details:   details,
		Severity:  severity,
	}

	fsal.logEvent(event)
}

// LogCertificateOperation logs certificate management operations
func (fsal *FileSecurityAuditLogger) LogCertificateOperation(operation string, cert *CertificateInfo) {
	details := map[string]interface{}{
		"operation":     operation,
		"subject":       cert.Subject,
		"issuer":        cert.Issuer,
		"fingerprint":   cert.Fingerprint,
		"serial_number": cert.SerialNumber,
		"not_before":    cert.NotBefore,
		"not_after":     cert.NotAfter,
		"key_usage":     cert.KeyUsage,
	}

	severity := SeverityInfo
	if operation == "revoke" {
		severity = SeverityWarning
	}

	event := &SecurityAuditEvent{
		Timestamp: time.Now(),
		EventType: "certificate_operation",
		Source:    "certificate_store",
		Target:    cert.Fingerprint,
		Result:    "success",
		Details:   details,
		Severity:  severity,
	}

	fsal.logEvent(event)
}

// LogSecurityEvent logs a general security event
func (fsal *FileSecurityAuditLogger) LogSecurityEvent(eventType string, details map[string]interface{}) {
	severity := SeverityInfo
	if val, ok := details["severity"]; ok {
		if s, ok := val.(SeverityLevel); ok {
			severity = s
		}
	}

	event := &SecurityAuditEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		Source:    "security_system",
		Result:    "logged",
		Details:   details,
		Severity:  severity,
	}

	fsal.logEvent(event)
}

// LogPluginSecurityViolation logs security violations by plugins
func (fsal *FileSecurityAuditLogger) LogPluginSecurityViolation(pluginName string, violation string, details map[string]interface{}) {
	event := &SecurityAuditEvent{
		Timestamp: time.Now(),
		EventType: "security_violation",
		Source:    "sandbox_monitor",
		Target:    pluginName,
		Result:    "violation_detected",
		Details: map[string]interface{}{
			"violation_type": violation,
			"plugin_name":    pluginName,
			"details":        details,
		},
		Severity: SeverityCritical,
	}

	fsal.logEvent(event)
}

// LogResourceViolation logs resource limit violations
func (fsal *FileSecurityAuditLogger) LogResourceViolation(pluginName string, resource string, limit interface{}, actual interface{}) {
	event := &SecurityAuditEvent{
		Timestamp: time.Now(),
		EventType: "resource_violation",
		Source:    "resource_monitor",
		Target:    pluginName,
		Result:    "limit_exceeded",
		Details: map[string]interface{}{
			"plugin_name": pluginName,
			"resource":    resource,
			"limit":       limit,
			"actual":      actual,
		},
		Severity: SeverityWarning,
	}

	fsal.logEvent(event)
}

// LogFailureRecovery logs automatic failure recovery events
func (fsal *FileSecurityAuditLogger) LogFailureRecovery(pluginName string, failureType string, recoveryAction string, success bool) {
	result := "success"
	severity := SeverityInfo

	if !success {
		result = "failure"
		severity = SeverityError
	}

	event := &SecurityAuditEvent{
		Timestamp: time.Now(),
		EventType: "failure_recovery",
		Source:    "recovery_manager",
		Target:    pluginName,
		Result:    result,
		Details: map[string]interface{}{
			"plugin_name":     pluginName,
			"failure_type":    failureType,
			"recovery_action": recoveryAction,
			"success":         success,
		},
		Severity: severity,
	}

	fsal.logEvent(event)
}

// logEvent writes an audit event to the log
func (fsal *FileSecurityAuditLogger) logEvent(event *SecurityAuditEvent) {
	fsal.mutex.Lock()
	defer fsal.mutex.Unlock()

	// Log to structured logger
	fsal.logger.Log(context.TODO(), fsal.severityToLogLevel(event.Severity), "security_audit",
		"event_type", event.EventType,
		"source", event.Source,
		"target", event.Target,
		"result", event.Result,
		"severity", event.Severity,
		"details", event.Details,
	)

	// Add to buffer for batch processing
	fsal.buffer = append(fsal.buffer, event)

	// Flush buffer if full
	if len(fsal.buffer) >= fsal.bufferSize {
		fsal.flushBuffer()
	}
}

// severityToLogLevel converts security severity to slog level
func (fsal *FileSecurityAuditLogger) severityToLogLevel(severity SeverityLevel) slog.Level {
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

// flushBuffer writes buffered events to disk
func (fsal *FileSecurityAuditLogger) flushBuffer() {
	if len(fsal.buffer) == 0 {
		return
	}

	// Write each event as a separate JSON line
	for _, event := range fsal.buffer {
		eventData, err := json.Marshal(event)
		if err != nil {
			fsal.logger.Error("failed to marshal audit event", "error", err)
			continue
		}

		if _, err := fsal.file.Write(append(eventData, '\n')); err != nil {
			fsal.logger.Error("failed to write audit event", "error", err)
		}
	}

	// Sync to disk
	fsal.file.Sync()

	// Clear buffer
	fsal.buffer = fsal.buffer[:0]
}

// Flush forces a flush of buffered events
func (fsal *FileSecurityAuditLogger) Flush() {
	fsal.mutex.Lock()
	defer fsal.mutex.Unlock()
	fsal.flushBuffer()
}

// Close closes the audit logger
func (fsal *FileSecurityAuditLogger) Close() error {
	fsal.mutex.Lock()
	defer fsal.mutex.Unlock()

	// Flush remaining events
	fsal.flushBuffer()

	// Close file
	return fsal.file.Close()
}

// GetAuditEvents retrieves audit events from the log file
func (fsal *FileSecurityAuditLogger) GetAuditEvents(limit int, filter map[string]interface{}) ([]*SecurityAuditEvent, error) {
	// This is a simplified implementation
	// In production, you'd want to use a proper log aggregation system
	return nil, fmt.Errorf("not implemented - use external log aggregation system")
}
