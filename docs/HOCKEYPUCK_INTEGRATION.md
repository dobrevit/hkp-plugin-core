# Hockeypuck Plugin System Integration Guide

This guide shows how to integrate the plugin system into Hockeypuck with the latest adaptations including httprouter support.

## Overview

The integration involves:
1. Adding plugin support to Hockeypuck's server struct
2. Implementing the PluginHost interface
3. Initializing plugins during server startup
4. Handling plugin lifecycle during shutdown
5. Exposing plugin management endpoints

## 1. Server Structure Updates

Add plugin-related fields to the Hockeypuck Server struct:

```go
// In hockeypuck/server/server.go
type Server struct {
    settings        *Settings
    st              storage.Storage
    middle          *interpose.Middleware
    r               *httprouter.Router  // Hockeypuck uses httprouter
    sksPeer         *sks.Peer
    pksSender       *pks.Sender
    logWriter       io.WriteCloser
    metricsListener *metrics.Metrics

    t                 tomb.Tomb
    hkpAddr, hkpsAddr string

    // Plugin system integration
    pluginHost      pluginapi.PluginHost      // Host for plugins
    pluginManager   *pluginapi.PluginManager  // Manager for loading plugins
    pluginRegistry  *pluginapi.PluginRegistry // Registry for managing plugins
    pluginSystem    *integration.PluginSystem // Plugin system integration
    pluginLifecycle *management.PluginManager // Plugin lifecycle management
}
```

## 2. Plugin Host Implementation

Create a ServerPluginHost that implements the PluginHost interface:

```go
// In hockeypuck/server/plugin_host.go
package server

import (
    "context"
    "net/http"
    "time"

    "github.com/julienschmidt/httprouter"
    log "github.com/sirupsen/logrus"

    "github.com/dobrevit/hkp-plugin-core/pkg/config"
    "github.com/dobrevit/hkp-plugin-core/pkg/events"
    "github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
    "github.com/dobrevit/hkp-plugin-core/pkg/metrics"
)

type ServerPluginHost struct {
    server   *Server
    eventBus *events.EventBus
    tasks    map[string]TaskInfo
}

func NewServerPluginHost(server *Server) *ServerPluginHost {
    return &ServerPluginHost{
        server: server,
        tasks:  make(map[string]TaskInfo),
    }
}

// RegisterHandler registers API endpoints using httprouter
func (ph *ServerPluginHost) RegisterHandler(pattern string, handler httprouter.Handle) error {
    // Register with the actual Hockeypuck router
    if ph.server != nil && ph.server.r != nil {
        // Register for all HTTP methods that make sense
        ph.server.r.GET(pattern, handler)
        ph.server.r.POST(pattern, handler)
        ph.server.r.PUT(pattern, handler)
        ph.server.r.DELETE(pattern, handler)
    }

    log.WithFields(log.Fields{
        "pattern": pattern,
    }).Debug("Plugin handler registered")
    return nil
}

// RegisterMiddleware for interpose compatibility
func (ph *ServerPluginHost) RegisterMiddleware(path string, middleware func(http.Handler) http.Handler) error {
    // Integrate with Hockeypuck's interpose middleware chain
    if ph.server != nil && ph.server.middle != nil {
        ph.server.middle.Use(middleware)
    }
    
    log.WithFields(log.Fields{
        "path": path,
    }).Debug("Plugin middleware registered")
    return nil
}

// Storage returns the actual Hockeypuck storage
func (ph *ServerPluginHost) Storage() hkpstorage.Storage {
    if ph.server != nil {
        return ph.server.st
    }
    return nil
}

// Config returns plugin configuration
func (ph *ServerPluginHost) Config() *config.Settings {
    if ph.server != nil && ph.server.settings != nil {
        return &config.Settings{
            DataDir: ph.server.settings.IndexPath,
            HKP: config.HKPConfig{
                Bind: ph.server.settings.HKP.Bind,
            },
            Plugins: config.PluginConfig{
                Enabled:   true,
                Directory: "./plugins",
                LoadOrder: []string{}, // Loaded from config
            },
        }
    }
    return &config.Settings{}
}

// Metrics returns the metrics system
func (ph *ServerPluginHost) Metrics() *metrics.Metrics {
    if ph.server != nil && ph.server.metricsListener != nil {
        return ph.server.metricsListener
    }
    return metrics.NewMetrics()
}

// Logger returns the logger
func (ph *ServerPluginHost) Logger() *log.Logger {
    return log.StandardLogger()
}

// RegisterTask registers periodic tasks
func (ph *ServerPluginHost) RegisterTask(name string, interval time.Duration, task func(context.Context) error) error {
    ctx, cancel := context.WithCancel(context.Background())
    ph.tasks[name] = TaskInfo{
        Name:     name,
        Interval: interval,
        Task:     task,
        Cancel:   cancel,
    }

    // Start the task
    go ph.runTask(ctx, name, interval, task)
    return nil
}

// Event system integration...
// (PublishEvent, SubscribeEvent, etc. implementations)
```

## 3. Server Initialization

Update the NewServer function to initialize the plugin system:

```go
func NewServer(settings *Settings) (*Server, error) {
    // ... existing initialization ...

    s := &Server{
        settings: settings,
        r:        httprouter.New(),
        // ... other fields ...
    }

    // Create plugin host
    s.pluginHost = NewServerPluginHost(s)

    // ... rest of initialization ...

    // Initialize plugin system after core components are ready
    if err := s.initPlugins(context.Background()); err != nil {
        log.WithError(err).Warn("Failed to initialize plugins")
        // Continue startup even if plugins fail
    }

    return s, nil
}

// initPlugins initializes the plugin system
func (s *Server) initPlugins(ctx context.Context) error {
    host := s.pluginHost
    settings := s.convertToPluginSettings()

    pluginSystem, err := integration.InitializePlugins(ctx, host, settings)
    if err != nil {
        return err
    }

    s.pluginSystem = pluginSystem

    // Initialize plugin lifecycle management
    if pluginSystem != nil {
        pluginManager, err := management.NewPluginManager(pluginSystem, log.StandardLogger())
        if err != nil {
            return fmt.Errorf("failed to create plugin lifecycle manager: %w", err)
        }
        s.pluginLifecycle = pluginManager

        // Register plugin management endpoints
        if err := s.registerPluginManagementEndpoints(); err != nil {
            return fmt.Errorf("failed to register plugin management endpoints: %w", err)
        }
    }

    return nil
}
```

## 4. Plugin Management Endpoints

Register management endpoints for plugin control:

```go
func (s *Server) registerPluginManagementEndpoints() error {
    if s.pluginLifecycle == nil {
        return nil
    }

    // Register plugin management endpoints
    s.r.GET("/plugins/status", s.pluginLifecycle.HandleStatus)
    s.r.GET("/plugins/health", s.pluginLifecycle.HandleHealth)
    s.r.GET("/plugins/list", s.pluginLifecycle.HandleList)
    s.r.POST("/plugins/reload", s.pluginLifecycle.HandleReload)
    s.r.GET("/plugins/config", s.pluginLifecycle.HandleConfig)
    s.r.PUT("/plugins/config", s.pluginLifecycle.HandleConfigUpdate)

    log.Info("Plugin management endpoints registered")
    return nil
}
```

## 5. Server Lifecycle Integration

### Starting the Server

```go
func (s *Server) Start() error {
    s.openLog()

    // Start HTTP servers
    s.t.Go(s.listenAndServeHKP)
    if s.settings.HKPS != nil {
        s.t.Go(s.listenAndServeHKPS)
    }

    // Start SKS peer
    if s.sksPeer != nil {
        s.sksPeer.Start()
    }

    // Start plugin tasks (already started during initialization)
    
    // ... rest of startup ...
    
    return nil
}
```

### Stopping the Server

```go
func (s *Server) Stop() {
    defer s.closeLog()

    // Shutdown plugins first (graceful draining)
    if s.pluginSystem != nil {
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        if err := s.pluginSystem.Shutdown(ctx); err != nil {
            log.WithError(err).Error("Error shutting down plugins")
        }
    }

    // Then shutdown core components
    if s.sksPeer != nil {
        s.sksPeer.Stop()
    }
    if s.metricsListener != nil {
        s.metricsListener.Stop()
    }
    
    s.t.Kill(ErrStopping)
    s.t.Wait()
}
```

## 6. Configuration

Add plugin configuration to Hockeypuck's settings:

```toml
# In hockeypuck.conf

[hockeypuck.plugins]
enabled = true
directory = "/usr/lib/hockeypuck/plugins"

# Plugin load order (if not using .so files)
load_order = [
    "ratelimit",
    "ratelimit-threat-intel",
    "ratelimit-geo",
    "ml-abuse-detector",
    "zero-trust-security",
]

# Plugin-specific configuration
[hockeypuck.plugins.config.ratelimit]
max_requests_per_minute = 60
burst_size = 100

[hockeypuck.plugins.config.zero-trust-security]
enabled = true
session_timeout = "30m"
max_devices_per_user = 5
```

## 7. Plugin Example

Here's how a plugin would integrate with Hockeypuck:

```go
package myplugin

import (
    "context"
    "net/http"
    
    "github.com/dobrevit/hkp-plugin-core/pkg/plugin"
    "github.com/julienschmidt/httprouter"
)

type MyPlugin struct {
    plugin.BasePlugin
}

func (p *MyPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
    p.SetInfo("my-plugin", "1.0.0", "My Hockeypuck plugin")
    
    // Register handlers - can use standard handlers with adapter
    host.RegisterHandler("/pks/my-endpoint", plugin.WrapStandardHandler(p.handleRequest))
    
    // Or use httprouter handlers directly for better performance
    host.RegisterHandler("/pks/user/:id", p.handleUserRequest)
    
    // Register middleware for authentication
    host.RegisterMiddleware("/pks", p.authMiddleware)
    
    // Subscribe to key change events
    host.SubscribeKeyChanges(p.onKeyChange)
    
    return nil
}

// Standard handler
func (p *MyPlugin) handleRequest(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello from plugin"))
}

// Httprouter handler with params
func (p *MyPlugin) handleUserRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    userID := ps.ByName("id")
    w.Write([]byte("User: " + userID))
}

// Middleware
func (p *MyPlugin) authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Add authentication
        next.ServeHTTP(w, r)
    })
}

// Key change handler
func (p *MyPlugin) onKeyChange(change hkpstorage.KeyChange) error {
    // React to key changes in the database
    return nil
}

// Export the plugin
func GetPlugin() plugin.Plugin {
    return &MyPlugin{}
}
```

## 8. Building and Deploying Plugins

### Building a Plugin

```bash
# Build as a shared object
go build -buildmode=plugin -o myplugin.so ./cmd/myplugin

# Copy to plugin directory
sudo cp myplugin.so /usr/lib/hockeypuck/plugins/
```

### Plugin Discovery

Hockeypuck will:
1. Scan the plugin directory for .so files
2. Load each plugin using Go's plugin package
3. Call GetPlugin() to get the plugin instance
4. Initialize plugins in dependency order
5. Start plugin services

## 9. Monitoring and Management

### Check Plugin Status
```bash
curl http://localhost:11371/plugins/status
```

### List Loaded Plugins
```bash
curl http://localhost:11371/plugins/list
```

### Check Plugin Health
```bash
curl http://localhost:11371/plugins/health
```

### Reload a Plugin
```bash
curl -X POST http://localhost:11371/plugins/reload?plugin=my-plugin
```

## 10. Best Practices

1. **Error Handling**: Plugins should not crash the server
2. **Resource Management**: Clean up resources in Shutdown()
3. **Logging**: Use structured logging with appropriate levels
4. **Configuration**: Validate configuration in Initialize()
5. **Dependencies**: Declare dependencies explicitly
6. **Performance**: Use httprouter handlers for high-traffic endpoints
7. **Security**: Validate all inputs and implement proper access controls

## Summary

This integration provides:
- Full plugin lifecycle management
- HTTP endpoint registration with httprouter
- Middleware support via interpose
- Event system integration
- Configuration management
- Hot reload capabilities
- Health monitoring
- Graceful shutdown with request draining

The plugin system is designed to be non-intrusive - Hockeypuck continues to function even if plugins fail to load or crash.