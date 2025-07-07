// Package lifecycle manages plugin process lifecycle
package lifecycle

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/discovery"
	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/tomb.v2"
)

// PluginProcess represents a running plugin process
type PluginProcess struct {
	Plugin     discovery.DiscoveredPlugin
	Cmd        *exec.Cmd
	Client     proto.HKPPluginClient
	Conn       *grpc.ClientConn
	Address    string
	Started    time.Time
	LastHealth time.Time
	tomb       *tomb.Tomb
	logger     *logrus.Entry
}

// Manager handles plugin process lifecycle
type Manager struct {
	plugins      map[string]*PluginProcess
	pluginsMutex sync.RWMutex
	logger       *logrus.Logger
	tomb         *tomb.Tomb
	config       *Config
}

// Config contains lifecycle manager configuration
type Config struct {
	// Plugin startup timeout
	StartupTimeout time.Duration
	// Health check interval
	HealthCheckInterval time.Duration
	// Maximum restart attempts
	MaxRestarts int
	// Restart delay
	RestartDelay time.Duration
	// Shutdown timeout
	ShutdownTimeout time.Duration
	// Plugin environment variables
	Environment map[string]string
	// Plugin working directory
	WorkingDir string
	// gRPC dial timeout
	DialTimeout time.Duration
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		StartupTimeout:      30 * time.Second,
		HealthCheckInterval: 10 * time.Second,
		MaxRestarts:         3,
		RestartDelay:        5 * time.Second,
		ShutdownTimeout:     10 * time.Second,
		Environment:         make(map[string]string),
		WorkingDir:          "",
		DialTimeout:         5 * time.Second,
	}
}

// NewManager creates a new lifecycle manager
func NewManager(config *Config, logger *logrus.Logger) *Manager {
	if config == nil {
		config = DefaultConfig()
	}

	return &Manager{
		plugins: make(map[string]*PluginProcess),
		logger:  logger,
		config:  config,
		tomb:    &tomb.Tomb{},
	}
}

// Start begins the lifecycle manager
func (m *Manager) Start() error {
	m.tomb.Go(m.healthCheckLoop)
	return nil
}

// Stop gracefully shuts down all plugins and the manager
func (m *Manager) Stop() error {
	m.logger.Info("Stopping plugin lifecycle manager")

	// Stop all plugins
	m.StopAll()

	// Kill the tomb
	m.tomb.Kill(nil)
	return m.tomb.Wait()
}

// StartPlugin starts a plugin process
func (m *Manager) StartPlugin(plugin discovery.DiscoveredPlugin) error {
	m.pluginsMutex.Lock()
	defer m.pluginsMutex.Unlock()

	// Check if already running
	if _, exists := m.plugins[plugin.Info.Name]; exists {
		return fmt.Errorf("plugin %s is already running", plugin.Info.Name)
	}

	logger := m.logger.WithField("plugin", plugin.Info.Name)
	logger.Info("Starting plugin")

	// Create plugin process
	proc := &PluginProcess{
		Plugin: plugin,
		tomb:   &tomb.Tomb{},
		logger: logger,
	}

	// Start the process
	if err := m.launchProcess(proc); err != nil {
		return fmt.Errorf("failed to launch plugin: %w", err)
	}

	// Wait for gRPC connection
	if err := m.connectToPlugin(proc); err != nil {
		proc.Cmd.Process.Kill()
		return fmt.Errorf("failed to connect to plugin: %w", err)
	}

	// Initialize plugin
	if err := m.initializePlugin(proc); err != nil {
		proc.Cmd.Process.Kill()
		proc.Conn.Close()
		return fmt.Errorf("failed to initialize plugin: %w", err)
	}

	// Add to managed plugins
	m.plugins[plugin.Info.Name] = proc

	// Start monitoring
	proc.tomb.Go(func() error {
		return m.monitorProcess(proc)
	})

	logger.Info("Plugin started successfully")
	return nil
}

// launchProcess starts the plugin executable
func (m *Manager) launchProcess(proc *PluginProcess) error {
	// Find a free port for gRPC
	port := findFreePort()
	proc.Address = fmt.Sprintf("localhost:%d", port)

	// Build command
	cmd := exec.Command(proc.Plugin.ExecutablePath)

	// Set environment
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("PLUGIN_GRPC_ADDRESS=%s", proc.Address))
	cmd.Env = append(cmd.Env, fmt.Sprintf("PLUGIN_NAME=%s", proc.Plugin.Info.Name))
	cmd.Env = append(cmd.Env, fmt.Sprintf("PLUGIN_VERSION=%s", proc.Plugin.Info.Version))

	// Add custom environment
	for k, v := range m.config.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	// Set working directory
	if m.config.WorkingDir != "" {
		cmd.Dir = m.config.WorkingDir
	} else {
		cmd.Dir = filepath.Dir(proc.Plugin.ExecutablePath)
	}

	// Capture output
	cmd.Stdout = &logWriter{logger: proc.logger.WithField("stream", "stdout")}
	cmd.Stderr = &logWriter{logger: proc.logger.WithField("stream", "stderr")}

	// Start process
	if err := cmd.Start(); err != nil {
		return err
	}

	proc.Cmd = cmd
	proc.Started = time.Now()
	return nil
}

// connectToPlugin establishes gRPC connection
func (m *Manager) connectToPlugin(proc *PluginProcess) error {
	ctx, cancel := context.WithTimeout(context.Background(), m.config.StartupTimeout)
	defer cancel()

	// Wait for plugin to be ready
	time.Sleep(100 * time.Millisecond)

	// Try to connect
	var conn *grpc.ClientConn
	var err error

	for {
		conn, err = grpc.DialContext(ctx, proc.Address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err == nil {
			break
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout connecting to plugin: %w", err)
		case <-time.After(100 * time.Millisecond):
			// Retry
		}
	}

	proc.Conn = conn
	proc.Client = proto.NewHKPPluginClient(conn)
	return nil
}

// initializePlugin sends initialization request
func (m *Manager) initializePlugin(proc *PluginProcess) error {
	ctx, cancel := context.WithTimeout(context.Background(), m.config.DialTimeout)
	defer cancel()

	// Prepare initialization request
	initReq := &proto.InitRequest{
		ConfigJson:        "{}", // TODO: Load from plugin config
		HockeypuckVersion: "2.2.0",
		ProtocolVersion:   "1.0",
		Environment:       m.config.Environment,
	}

	// Send initialization
	resp, err := proc.Client.Initialize(ctx, initReq)
	if err != nil {
		return fmt.Errorf("initialization failed: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("plugin initialization failed: %s", resp.Error)
	}

	proc.LastHealth = time.Now()
	return nil
}

// StopPlugin gracefully stops a plugin
func (m *Manager) StopPlugin(name string) error {
	m.pluginsMutex.Lock()
	defer m.pluginsMutex.Unlock()

	proc, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	proc.logger.Info("Stopping plugin")

	// Send shutdown request
	ctx, cancel := context.WithTimeout(context.Background(), m.config.ShutdownTimeout)
	defer cancel()

	if proc.Client != nil {
		shutdownReq := &proto.ShutdownRequest{
			TimeoutSeconds: int32(m.config.ShutdownTimeout.Seconds()),
			Reason:         "Manager shutdown",
		}

		proc.Client.Shutdown(ctx, shutdownReq)
	}

	// Kill tomb
	proc.tomb.Kill(nil)

	// Wait for graceful shutdown
	done := make(chan struct{})
	go func() {
		proc.Cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Graceful shutdown
	case <-time.After(m.config.ShutdownTimeout):
		// Force kill
		proc.Cmd.Process.Kill()
	}

	// Close gRPC connection
	if proc.Conn != nil {
		proc.Conn.Close()
	}

	// Remove from managed plugins
	delete(m.plugins, name)

	proc.logger.Info("Plugin stopped")
	return nil
}

// RestartPlugin restarts a plugin
func (m *Manager) RestartPlugin(ctx context.Context, name string) error {
	m.pluginsMutex.Lock()
	defer m.pluginsMutex.Unlock()

	proc, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	logger := proc.logger.WithField("operation", "restart")
	logger.Info("Restarting plugin")

	// Store plugin info for restart
	plugin := proc.Plugin

	// Stop the current instance
	if err := m.stopPluginUnsafe(proc); err != nil {
		logger.WithError(err).Warn("Error stopping plugin for restart")
	}

	// Remove from managed plugins
	delete(m.plugins, name)

	// Start new instance
	return m.StartPlugin(plugin)
}

// stopPluginUnsafe stops a plugin without acquiring locks (caller must hold lock)
func (m *Manager) stopPluginUnsafe(proc *PluginProcess) error {
	proc.logger.Info("Stopping plugin")

	// Send shutdown request
	shutdownCtx, cancel := context.WithTimeout(context.Background(), m.config.ShutdownTimeout)
	defer cancel()

	if proc.Client != nil {
		shutdownReq := &proto.ShutdownRequest{
			TimeoutSeconds: int32(m.config.ShutdownTimeout.Seconds()),
			Reason:         "Manager restart",
		}

		proc.Client.Shutdown(shutdownCtx, shutdownReq)
	}

	// Kill tomb
	proc.tomb.Kill(nil)

	// Wait for graceful shutdown
	done := make(chan struct{})
	go func() {
		proc.Cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Graceful shutdown
	case <-time.After(m.config.ShutdownTimeout):
		// Force kill
		proc.Cmd.Process.Kill()
	}

	// Close gRPC connection
	if proc.Conn != nil {
		proc.Conn.Close()
	}

	proc.logger.Info("Plugin stopped")
	return nil
}

// StopAll stops all running plugins
func (m *Manager) StopAll() {
	m.pluginsMutex.RLock()
	names := make([]string, 0, len(m.plugins))
	for name := range m.plugins {
		names = append(names, name)
	}
	m.pluginsMutex.RUnlock()

	for _, name := range names {
		if err := m.StopPlugin(name); err != nil {
			m.logger.WithError(err).WithField("plugin", name).Error("Failed to stop plugin")
		}
	}
}

// GetPlugin returns plugin information
func (m *Manager) GetPlugin(name string) (*PluginProcess, bool) {
	m.pluginsMutex.RLock()
	defer m.pluginsMutex.RUnlock()

	proc, exists := m.plugins[name]
	return proc, exists
}

// ListPlugins returns all running plugins
func (m *Manager) ListPlugins() []string {
	m.pluginsMutex.RLock()
	defer m.pluginsMutex.RUnlock()

	names := make([]string, 0, len(m.plugins))
	for name := range m.plugins {
		names = append(names, name)
	}
	return names
}

// monitorProcess monitors a plugin process
func (m *Manager) monitorProcess(proc *PluginProcess) error {
	// Wait for process to exit
	err := proc.Cmd.Wait()

	proc.logger.WithError(err).Warn("Plugin process exited")

	// Remove from managed plugins
	m.pluginsMutex.Lock()
	delete(m.plugins, proc.Plugin.Info.Name)
	m.pluginsMutex.Unlock()

	// TODO: Implement restart logic

	return nil
}

// healthCheckLoop performs periodic health checks
func (m *Manager) healthCheckLoop() error {
	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.tomb.Dying():
			return nil
		case <-ticker.C:
			m.performHealthChecks()
		}
	}
}

// performHealthChecks checks all plugins
func (m *Manager) performHealthChecks() {
	m.pluginsMutex.RLock()
	plugins := make([]*PluginProcess, 0, len(m.plugins))
	for _, proc := range m.plugins {
		plugins = append(plugins, proc)
	}
	m.pluginsMutex.RUnlock()

	for _, proc := range plugins {
		if err := m.checkPluginHealth(proc); err != nil {
			proc.logger.WithError(err).Warn("Health check failed")
			// TODO: Handle unhealthy plugins
		}
	}
}

// checkPluginHealth checks a single plugin's health
func (m *Manager) checkPluginHealth(proc *PluginProcess) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := proc.Client.HealthCheck(ctx, &proto.Empty{})
	if err != nil {
		return err
	}

	proc.LastHealth = time.Now()

	if resp.Status != proto.HealthStatus_HEALTHY {
		return fmt.Errorf("plugin unhealthy: %s", resp.Message)
	}

	return nil
}

// Helper types

type logWriter struct {
	logger *logrus.Entry
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	w.logger.Info(string(p))
	return len(p), nil
}

// findFreePort finds an available port
func findFreePort() int {
	// Simple implementation - in production, use a proper port allocator
	return 50000 + (time.Now().Nanosecond() % 10000)
}
