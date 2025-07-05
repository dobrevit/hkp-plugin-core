package plugin_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/config"
	"github.com/dobrevit/hkp-plugin-core/pkg/events"
	"github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
	"github.com/dobrevit/hkp-plugin-core/pkg/metrics"
	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	log "github.com/sirupsen/logrus"
)

// MockPlugin implements the Plugin interface for testing
type MockPlugin struct {
	plugin.BasePlugin
	initError     error
	initCalls     int
	shutdownCalls int
	deps          []plugin.PluginDependency
}

func NewMockPlugin(name, version, description string) *MockPlugin {
	p := &MockPlugin{}
	p.SetInfo(name, version, description)
	return p
}

func (p *MockPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
	p.initCalls++
	if p.initError != nil {
		return p.initError
	}
	p.SetInitialized(true)
	return nil
}

func (p *MockPlugin) Dependencies() []plugin.PluginDependency {
	return p.deps
}

func (p *MockPlugin) Shutdown(ctx context.Context) error {
	p.shutdownCalls++
	p.SetInitialized(false)
	return nil
}

// MockPluginHost implements the PluginHost interface for testing
type MockPluginHost struct {
	middlewares map[string]func(http.Handler) http.Handler
	handlers    map[string]http.HandlerFunc
	tasks       map[string]func(context.Context) error
	events      []events.PluginEvent
	subscribers map[string][]events.PluginEventHandler
	mu          sync.RWMutex
}

func NewMockPluginHost() *MockPluginHost {
	return &MockPluginHost{
		middlewares: make(map[string]func(http.Handler) http.Handler),
		handlers:    make(map[string]http.HandlerFunc),
		tasks:       make(map[string]func(context.Context) error),
		events:      make([]events.PluginEvent, 0),
		subscribers: make(map[string][]events.PluginEventHandler),
	}
}

func (h *MockPluginHost) RegisterMiddleware(path string, middleware func(http.Handler) http.Handler) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.middlewares[path] = middleware
	return nil
}

func (h *MockPluginHost) RegisterHandler(pattern string, handler http.HandlerFunc) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handlers[pattern] = handler
	return nil
}

func (h *MockPluginHost) Storage() hkpstorage.Storage {
	return nil
}

func (h *MockPluginHost) Config() *config.Settings {
	return &config.Settings{
		DataDir: "/tmp/data",
		Plugins: config.PluginConfig{
			Enabled: true,
		},
	}
}
func (h *MockPluginHost) Metrics() *metrics.Metrics { return nil }
func (h *MockPluginHost) Logger() *log.Logger       { return log.StandardLogger() }

func (h *MockPluginHost) RegisterTask(name string, interval time.Duration, task func(context.Context) error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tasks[name] = task
	return nil
}

func (h *MockPluginHost) PublishEvent(event events.PluginEvent) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, event)

	if handlers, exists := h.subscribers[event.Type]; exists {
		for _, handler := range handlers {
			go handler(event)
		}
	}
	return nil
}

func (h *MockPluginHost) SubscribeEvent(eventType string, handler events.PluginEventHandler) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subscribers[eventType] = append(h.subscribers[eventType], handler)
	return nil
}

func (h *MockPluginHost) SubscribeKeyChanges(callback func(hkpstorage.KeyChange) error) error {
	// Mock implementation for testing
	return nil
}

func (h *MockPluginHost) PublishThreatDetected(threat events.ThreatInfo) error {
	return h.PublishEvent(events.PluginEvent{
		Type:   events.EventSecurityThreatDetected,
		Source: threat.Source,
		Data:   map[string]interface{}{"threat": threat},
	})
}

func (h *MockPluginHost) PublishRateLimitViolation(violation events.RateLimitViolation) error {
	return h.PublishEvent(events.PluginEvent{
		Type:   events.EventRateLimitViolation,
		Source: violation.Source,
		Data:   map[string]interface{}{"violation": violation},
	})
}

func (h *MockPluginHost) PublishZTNAEvent(eventType string, ztnaEvent events.ZTNAEvent) error {
	return h.PublishEvent(events.PluginEvent{
		Type:   eventType,
		Source: "ztna",
		Data:   map[string]interface{}{"ztna": ztnaEvent},
	})
}

// MockLogger implements the Logger interface for testing
type MockLogger struct {
	logs []LogEntry
	mu   sync.RWMutex
}

type LogEntry struct {
	Level string
	Msg   string
	Args  []interface{}
}

func NewMockLogger() *MockLogger {
	return &MockLogger{}
}

func (l *MockLogger) Info(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, LogEntry{Level: "info", Msg: msg, Args: args})
}

func (l *MockLogger) Warn(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, LogEntry{Level: "warn", Msg: msg, Args: args})
}

func (l *MockLogger) Error(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, LogEntry{Level: "error", Msg: msg, Args: args})
}

func (l *MockLogger) Debug(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, LogEntry{Level: "debug", Msg: msg, Args: args})
}

func (l *MockLogger) GetLogs() []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return append([]LogEntry{}, l.logs...)
}

// TestBasePlugin tests the BasePlugin implementation
func TestBasePlugin(t *testing.T) {
	p := &plugin.BasePlugin{}

	// Test initial state
	if p.Name() != "" {
		t.Error("Expected empty name initially")
	}
	if p.Version() != "" {
		t.Error("Expected empty version initially")
	}
	if p.Description() != "" {
		t.Error("Expected empty description initially")
	}
	if p.IsInitialized() {
		t.Error("Expected not initialized initially")
	}

	// Test SetInfo
	p.SetInfo("test-plugin", "1.0.0", "Test plugin description")
	if p.Name() != "test-plugin" {
		t.Errorf("Expected name 'test-plugin', got '%s'", p.Name())
	}
	if p.Version() != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", p.Version())
	}
	if p.Description() != "Test plugin description" {
		t.Errorf("Expected description 'Test plugin description', got '%s'", p.Description())
	}

	// Test SetInitialized
	p.SetInitialized(true)
	if !p.IsInitialized() {
		t.Error("Expected initialized to be true")
	}

	// Test Dependencies (should return empty by default)
	deps := p.Dependencies()
	if len(deps) != 0 {
		t.Errorf("Expected no dependencies, got %d", len(deps))
	}

	// Test Shutdown
	err := p.Shutdown(context.Background())
	if err != nil {
		t.Errorf("Expected no error from Shutdown, got %v", err)
	}
	if p.IsInitialized() {
		t.Error("Expected initialized to be false after shutdown")
	}
}

// TestPluginRegistry tests the PluginRegistry functionality
func TestPluginRegistry(t *testing.T) {
	host := NewMockPluginHost()
	registry := plugin.NewPluginRegistry(host)

	// Test empty registry
	plugins := registry.List()
	if len(plugins) != 0 {
		t.Errorf("Expected empty registry, got %d plugins", len(plugins))
	}

	// Test registering a plugin
	mockPlugin := NewMockPlugin("test-plugin", "1.0.0", "Test plugin")
	err := registry.Register(mockPlugin)
	if err != nil {
		t.Errorf("Failed to register plugin: %v", err)
	}

	// Test retrieving the plugin
	retrievedPlugin, exists := registry.Get("test-plugin")
	if !exists {
		t.Error("Plugin should exist in registry")
	}
	if retrievedPlugin.Name() != "test-plugin" {
		t.Errorf("Expected plugin name 'test-plugin', got '%s'", retrievedPlugin.Name())
	}

	// Test listing plugins
	plugins = registry.List()
	if len(plugins) != 1 {
		t.Errorf("Expected 1 plugin, got %d", len(plugins))
	}

	// Test registering duplicate plugin
	duplicatePlugin := NewMockPlugin("test-plugin", "2.0.0", "Duplicate")
	err = registry.Register(duplicatePlugin)
	if err == nil {
		t.Error("Expected error when registering duplicate plugin")
	}

	// Test registering plugin with empty name
	emptyNamePlugin := NewMockPlugin("", "1.0.0", "No name")
	err = registry.Register(emptyNamePlugin)
	if err == nil {
		t.Error("Expected error when registering plugin with empty name")
	}
}

// TestPluginLifecycle tests the plugin lifecycle management
func TestPluginLifecycle(t *testing.T) {
	host := NewMockPluginHost()
	registry := plugin.NewPluginRegistry(host)

	// Create plugins with dependencies
	pluginA := NewMockPlugin("plugin-a", "1.0.0", "Plugin A")
	pluginB := NewMockPlugin("plugin-b", "1.0.0", "Plugin B")
	pluginC := NewMockPlugin("plugin-c", "1.0.0", "Plugin C")

	// Set dependencies: C depends on B, B depends on A
	pluginB.deps = []plugin.PluginDependency{
		{Name: "plugin-a", Version: "1.0.0", Type: plugin.DependencyRequired},
	}
	pluginC.deps = []plugin.PluginDependency{
		{Name: "plugin-b", Version: "1.0.0", Type: plugin.DependencyRequired},
	}

	// Register plugins in reverse order
	registry.Register(pluginC)
	registry.Register(pluginB)
	registry.Register(pluginA)

	// Initialize plugins
	configs := map[string]map[string]interface{}{
		"plugin-a": {"setting": "value-a"},
		"plugin-b": {"setting": "value-b"},
		"plugin-c": {"setting": "value-c"},
	}

	err := registry.Initialize(context.Background(), configs)
	if err != nil {
		t.Errorf("Failed to initialize plugins: %v", err)
	}

	// Verify initialization order (A should be initialized before B, B before C)
	if pluginA.initCalls != 1 {
		t.Errorf("Expected plugin A to be initialized once, got %d", pluginA.initCalls)
	}
	if pluginB.initCalls != 1 {
		t.Errorf("Expected plugin B to be initialized once, got %d", pluginB.initCalls)
	}
	if pluginC.initCalls != 1 {
		t.Errorf("Expected plugin C to be initialized once, got %d", pluginC.initCalls)
	}

	// Test shutdown
	err = registry.Shutdown(context.Background())
	if err != nil {
		t.Errorf("Failed to shutdown plugins: %v", err)
	}

	// Verify all plugins were shut down
	if pluginA.shutdownCalls != 1 {
		t.Errorf("Expected plugin A to be shut down once, got %d", pluginA.shutdownCalls)
	}
	if pluginB.shutdownCalls != 1 {
		t.Errorf("Expected plugin B to be shut down once, got %d", pluginB.shutdownCalls)
	}
	if pluginC.shutdownCalls != 1 {
		t.Errorf("Expected plugin C to be shut down once, got %d", pluginC.shutdownCalls)
	}
}

// TestDependencyGraph tests the dependency graph functionality
func TestDependencyGraph(t *testing.T) {
	graph := plugin.NewDependencyGraph()

	// Add nodes
	graph.AddNode("A")
	graph.AddNode("B")
	graph.AddNode("C")

	// Add edges: A -> B -> C
	graph.AddEdge("A", "B")
	graph.AddEdge("B", "C")

	// Test topological sort
	sorted, err := graph.TopologicalSort()
	if err != nil {
		t.Errorf("Failed to sort graph: %v", err)
	}

	if len(sorted) != 3 {
		t.Errorf("Expected 3 nodes in sorted result, got %d", len(sorted))
	}

	// Verify order: A should come before B, B should come before C
	aIndex := -1
	bIndex := -1
	cIndex := -1
	for i, node := range sorted {
		switch node {
		case "A":
			aIndex = i
		case "B":
			bIndex = i
		case "C":
			cIndex = i
		}
	}

	if aIndex > bIndex || bIndex > cIndex {
		t.Errorf("Invalid topological order: %v", sorted)
	}
}

// TestCircularDependency tests circular dependency detection
func TestCircularDependency(t *testing.T) {
	graph := plugin.NewDependencyGraph()

	// Add nodes
	graph.AddNode("A")
	graph.AddNode("B")
	graph.AddNode("C")

	// Create circular dependency: A -> B -> C -> A
	graph.AddEdge("A", "B")
	graph.AddEdge("B", "C")
	graph.AddEdge("C", "A")

	// Test topological sort should fail
	_, err := graph.TopologicalSort()
	if err == nil {
		t.Error("Expected error for circular dependency")
	}
}

// TestPluginManager tests the PluginManager functionality
func TestPluginManager(t *testing.T) {
	host := NewMockPluginHost()
	logger := NewMockLogger()
	manager := plugin.NewPluginManager(host, logger)

	// Test registering plugins
	pluginA := NewMockPlugin("manager-test-a", "1.0.0", "Manager Test A")
	pluginB := NewMockPlugin("manager-test-b", "1.0.0", "Manager Test B")

	err := manager.Register(pluginA)
	if err != nil {
		t.Errorf("Failed to register plugin A: %v", err)
	}

	err = manager.Register(pluginB)
	if err != nil {
		t.Errorf("Failed to register plugin B: %v", err)
	}

	// Test listing plugins
	plugins := manager.ListPlugins()
	if len(plugins) != 2 {
		t.Errorf("Expected 2 plugins, got %d", len(plugins))
	}

	// Test getting plugin
	retrievedPlugin, exists := manager.GetPlugin("manager-test-a")
	if !exists {
		t.Error("Plugin A should exist")
	}
	if retrievedPlugin.Name() != "manager-test-a" {
		t.Errorf("Expected plugin name 'manager-test-a', got '%s'", retrievedPlugin.Name())
	}

	// Test initializing plugins
	configs := map[string]map[string]interface{}{
		"manager-test-a": {"key": "value"},
		"manager-test-b": {"key": "value"},
	}

	err = manager.Initialize(context.Background(), configs)
	if err != nil {
		t.Errorf("Failed to initialize plugins: %v", err)
	}

	// Test shutdown
	err = manager.Shutdown(context.Background())
	if err != nil {
		t.Errorf("Failed to shutdown plugins: %v", err)
	}
}

// TestLoadPlugin tests the LoadPlugin functionality
func TestLoadPlugin(t *testing.T) {
	host := NewMockPluginHost()
	logger := NewMockLogger()
	manager := plugin.NewPluginManager(host, logger)

	// Test loading a plugin
	plugin := NewMockPlugin("load-test", "1.0.0", "Load Test Plugin")
	config := map[string]interface{}{"test": "config"}

	err := manager.LoadPlugin(context.Background(), plugin, config)
	if err != nil {
		t.Errorf("Failed to load plugin: %v", err)
	}

	// Verify plugin was registered and initialized
	retrievedPlugin, exists := manager.GetPlugin("load-test")
	if !exists {
		t.Error("Plugin should exist after loading")
	}

	if !retrievedPlugin.(*MockPlugin).IsInitialized() {
		t.Error("Plugin should be initialized after loading")
	}

	if plugin.initCalls != 1 {
		t.Errorf("Expected plugin to be initialized once, got %d", plugin.initCalls)
	}
}

// TestPluginInitializationError tests error handling during plugin initialization
func TestPluginInitializationError(t *testing.T) {
	host := NewMockPluginHost()
	registry := plugin.NewPluginRegistry(host)

	// Create a plugin that fails to initialize
	failingPlugin := NewMockPlugin("failing-plugin", "1.0.0", "Failing Plugin")
	failingPlugin.initError = fmt.Errorf("initialization failed")

	registry.Register(failingPlugin)

	// Try to initialize
	configs := map[string]map[string]interface{}{
		"failing-plugin": {},
	}

	err := registry.Initialize(context.Background(), configs)
	if err == nil {
		t.Error("Expected error during initialization")
	}

	errorStr := fmt.Sprintf("%v", err)
	if !strings.Contains(errorStr, "failed to initialize plugin failing-plugin") {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}

// TestPluginEvents tests the plugin event system
func TestPluginEvents(t *testing.T) {
	host := NewMockPluginHost()

	// Subscribe to events
	var receivedEvents []plugin.PluginEvent
	handler := func(event plugin.PluginEvent) error {
		receivedEvents = append(receivedEvents, event)
		return nil
	}

	err := host.SubscribeEvent(plugin.EventSecurityThreatDetected, handler)
	if err != nil {
		t.Errorf("Failed to subscribe to event: %v", err)
	}

	// Publish an event
	event := plugin.PluginEvent{
		Type:      plugin.EventSecurityThreatDetected,
		Source:    "test-plugin",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"threat_type": "test_threat",
			"severity":    "high",
		},
	}

	err = host.PublishEvent(event)
	if err != nil {
		t.Errorf("Failed to publish event: %v", err)
	}

	// Wait a bit for async event handling
	time.Sleep(10 * time.Millisecond)

	// Verify event was received
	if len(receivedEvents) != 1 {
		t.Errorf("Expected 1 received event, got %d", len(receivedEvents))
	}

	if receivedEvents[0].Type != plugin.EventSecurityThreatDetected {
		t.Errorf("Expected event type %s, got %s", plugin.EventSecurityThreatDetected, receivedEvents[0].Type)
	}
}

// TestGlobalRegistry tests the global plugin registry functions
func TestGlobalRegistry(t *testing.T) {
	// Note: This test may interfere with other tests if they use the global registry
	// In a real-world scenario, you'd want to reset the global state or use dependency injection

	// Test registering a plugin globally
	globalPlugin := NewMockPlugin("global-test", "1.0.0", "Global Test Plugin")

	// This should not panic
	plugin.Register(globalPlugin)

	// Test getting the global registry
	registry := plugin.GetRegistry()
	if registry == nil {
		t.Error("Expected global registry to exist")
	}

	// Test setting host
	host := NewMockPluginHost()
	plugin.SetHost(host)

	// Verify the plugin was registered
	retrievedPlugin, exists := registry.Get("global-test")
	if !exists {
		t.Error("Global plugin should exist in registry")
	}
	if retrievedPlugin.Name() != "global-test" {
		t.Errorf("Expected global plugin name 'global-test', got '%s'", retrievedPlugin.Name())
	}
}

// TestConcurrentPluginOperations tests concurrent access to plugin operations
func TestConcurrentPluginOperations(t *testing.T) {
	host := NewMockPluginHost()
	registry := plugin.NewPluginRegistry(host)

	// Test concurrent plugin registration
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			plugin := NewMockPlugin(fmt.Sprintf("concurrent-plugin-%d", id), "1.0.0", "Concurrent Test")
			err := registry.Register(plugin)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent registration error: %v", err)
	}

	// Verify all plugins were registered
	plugins := registry.List()
	if len(plugins) != 10 {
		t.Errorf("Expected 10 plugins after concurrent registration, got %d", len(plugins))
	}

	// Test concurrent plugin retrieval
	wg = sync.WaitGroup{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pluginName := fmt.Sprintf("concurrent-plugin-%d", id)
			plugin, exists := registry.Get(pluginName)
			if !exists {
				t.Errorf("Plugin %s should exist", pluginName)
			}
			if plugin != nil && plugin.Name() != pluginName {
				t.Errorf("Expected plugin name %s, got %s", pluginName, plugin.Name())
			}
		}(i)
	}

	wg.Wait()
}
