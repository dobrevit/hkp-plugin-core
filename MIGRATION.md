# Migration Guide: Go Plugins to gRPC Plugins

This document provides guidance for migrating from the deprecated Go plugin system (`.so` files) to the new gRPC plugin architecture.

## Overview

The HKP Plugin System has migrated from Go's native plugin system to a gRPC-based architecture to solve several critical issues:

### Issues with Go Plugin System
- **Binary Compatibility**: Go plugins require exact Go version and dependency matching
- **AGPL License Constraints**: Shared address space meant proprietary plugins inherited AGPL license
- **Debugging Difficulties**: Crashes in plugins could bring down the entire server
- **Hot Reload Limitations**: Plugin updates required server restarts

### Benefits of gRPC Architecture
- ✅ **Process Isolation**: Plugins run as separate processes
- ✅ **License Boundary**: Clear separation allows proprietary plugins
- ✅ **Hot Reload**: Plugin updates without server restart
- ✅ **Better Debugging**: Plugin crashes don't affect the server
- ✅ **Language Agnostic**: Plugins can be written in any language supporting gRPC

## Migration Steps

### 1. Update Plugin Structure

**Old Structure (Go Plugin):**
```
src/plugins/myplugin/
├── main.go           # Plugin wrapper
└── myplugin/
    └── plugin.go     # Plugin implementation
```

**New Structure (gRPC Plugin):**
```
plugins/myplugin-grpc/
├── main.go           # gRPC server implementation
├── components.go     # Supporting components
└── plugin.toml       # Plugin manifest
```

### 2. Convert Plugin Interface

**Old Interface:**
```go
type Plugin interface {
    Initialize(ctx context.Context, host PluginHost, config map[string]interface{}) error
    Name() string
    Version() string
    Description() string
    Dependencies() []PluginDependency
    Shutdown(ctx context.Context) error
}
```

**New Interface (gRPC):**
```go
// Implement proto.HKPPluginServer
type MyPlugin struct {
    proto.UnimplementedHKPPluginServer
    // ... fields
}

func (p *MyPlugin) Initialize(ctx context.Context, req *proto.InitRequest) (*proto.InitResponse, error)
func (p *MyPlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error)
func (p *MyPlugin) CheckRateLimit(ctx context.Context, req *proto.RateLimitCheck) (*proto.RateLimitResponse, error)
// ... other gRPC methods
```

### 3. Update Configuration

**Old Configuration:**
```go
// Loaded from TOML via map[string]interface{}
config := map[string]interface{}{
    "enabled": true,
    "threshold": 0.8,
}
```

**New Configuration:**
```go
// Structured configuration with JSON tags
type MyPluginConfig struct {
    Enabled   bool    `json:"enabled"`
    Threshold float64 `json:"threshold"`
}

// Parse from InitRequest
if req.ConfigJson != "" {
    json.Unmarshal([]byte(req.ConfigJson), &p.config)
}
```

### 4. Update HTTP Handling

**Old HTTP Middleware:**
```go
func (p *MyPlugin) CreateMiddleware() (func(http.Handler) http.Handler, error) {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Process request
            next.ServeHTTP(w, r)
        })
    }, nil
}
```

**New gRPC HTTP Handling:**
```go
func (p *MyPlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
    // Extract client IP
    clientIP := req.RemoteAddr
    
    // Process request
    // ...
    
    return &proto.HTTPResponse{
        StatusCode:    200,
        Headers:       map[string]string{"X-Plugin": "processed"},
        ContinueChain: true,
    }, nil
}
```

### 5. Update Event System

**Old Event Handling:**
```go
host.SubscribeEvent("security.threat.detected", p.handleThreatEvent)

func (p *MyPlugin) handleThreatEvent(event plugin.PluginEvent) error {
    // Handle event
    return nil
}
```

**New gRPC Event Handling:**
```go
func (p *MyPlugin) PublishEvent(ctx context.Context, req *proto.Event) (*proto.Empty, error) {
    if req.Type == "security.threat.detected" {
        // Handle event
    }
    return &proto.Empty{}, nil
}
```

## Plugin Manifest (plugin.toml)

Create a `plugin.toml` file for plugin discovery:

```toml
[plugin]
name = "my-plugin"
version = "1.0.0"
description = "My awesome plugin"
executable = "my-plugin-grpc"
capabilities = ["rate_limiting", "security"]
priority = 50

[config]
enabled = true
threshold = 0.8

[health]
check_interval = "30s"
timeout = "10s"
restart_threshold = 3

[grpc]
address = "localhost:50100"
max_connections = 100
timeout = "30s"
```

## Using the Plugin SDK

Generate a new plugin template:

```bash
cd sdk
go run generator.go my-new-plugin
cd ../plugins/my-new-plugin-grpc
make build
make run
```

## Testing Migration

1. **Build New Plugin:**
   ```bash
   cd plugins/myplugin-grpc
   go build -o myplugin-grpc .
   ```

2. **Run Plugin:**
   ```bash
   PLUGIN_GRPC_ADDRESS=localhost:50100 ./myplugin-grpc
   ```

3. **Test with Hockeypuck:**
   ```bash
   # Update hockeypuck config to use gRPC plugins
   # Start hockeypuck and verify plugin loading
   ```

## Deprecated Components

The following components are deprecated and should not be used for new plugins:

### Deprecated Files
- `src/plugins/*/main.go` (Go plugin wrappers)
- `pkg/plugin/plugin.go` (Legacy plugin interface)
- `pkg/plugin/host.go` (Legacy plugin host)
- Build configurations for `.so` files

### Deprecated Patterns
- `plugin.Plugin` interface
- `plugin.PluginHost` interface
- `gopkg.in/tomb.v2` for lifecycle management (use context.Context)
- Direct HTTP middleware registration
- Direct event subscription

## Migration Checklist

- [ ] Convert plugin interface to gRPC
- [ ] Create plugin.toml manifest
- [ ] Update configuration handling
- [ ] Convert HTTP middleware to HandleHTTPRequest
- [ ] Update event handling
- [ ] Add health checks
- [ ] Test plugin independently
- [ ] Test integration with Hockeypuck
- [ ] Remove old plugin files
- [ ] Update documentation

## Troubleshooting

### Common Issues

1. **Plugin Not Loading:**
   - Check plugin.toml syntax
   - Verify executable path
   - Check gRPC address conflicts

2. **Configuration Not Working:**
   - Verify JSON tags on config struct
   - Check TOML to JSON conversion
   - Validate configuration schema

3. **gRPC Connection Errors:**
   - Check port availability
   - Verify network configuration
   - Check firewall settings

4. **Plugin Crashes:**
   - Check logs in plugin process
   - Verify all gRPC methods are implemented
   - Check for nil pointer dereferences

### Getting Help

- Check plugin logs for specific error messages
- Use gRPC debugging tools to inspect communication
- Refer to working examples in `plugins/` directory
- Review the plugin SDK documentation

## Future Considerations

- **Multi-language Support**: Plugins can now be written in Python, Rust, etc.
- **Plugin Marketplace**: Consider distributing plugins as container images
- **Service Mesh Integration**: Plugins could integrate with service mesh solutions
- **Advanced Health Monitoring**: Rich health checks and metrics
- **Plugin Dependency Management**: Plugins can depend on other plugins more safely