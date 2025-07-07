# gRPC Plugin System Design

## Overview

This document outlines the design for migrating the HKP Plugin System from Go's native plugin architecture to a gRPC-based process model, similar to HashiCorp's Terraform provider architecture.

## Goals

1. **License Boundary**: Maintain clear separation between AGPL Hockeypuck and plugins
2. **Binary Independence**: Eliminate Go plugin binary compatibility issues
3. **Language Flexibility**: Allow plugins in any language supporting gRPC
4. **Process Isolation**: Improve stability through process-level isolation
5. **Version Compatibility**: Support multiple protocol versions

## Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│                     │         │                     │
│  Hockeypuck (AGPL)  │         │   Plugin Process    │
│                     │         │   (Any License)     │
│  ┌───────────────┐  │  gRPC   │  ┌──────────────┐   │
│  │ Plugin Host   │◄─┼─────────┼─►│ gRPC Server  │   │
│  │   Manager     │  │         │  │              │   │
│  └───────────────┘  │         │  └──────────────┘   │
│                     │         │                     │
└─────────────────────┘         └─────────────────────┘
```

## Core Components

### 1. Protocol Definition (`proto/hkp_plugin.proto`)

```protobuf
syntax = "proto3";
package hkpplugin;

service HKPPlugin {
  // Lifecycle
  rpc Initialize(InitRequest) returns (InitResponse);
  rpc Shutdown(ShutdownRequest) returns (ShutdownResponse);
  
  // Metadata
  rpc GetInfo(Empty) returns (PluginInfo);
  
  // Events
  rpc HandleRequest(HandleRequestEvent) returns (HandleResponse);
  rpc SubscribeEvents(EventFilter) returns (stream Event);
  
  // Storage proxy
  rpc QueryStorage(StorageQuery) returns (StorageResponse);
  
  // Health
  rpc HealthCheck(Empty) returns (HealthStatus);
}

message PluginInfo {
  string name = 1;
  string version = 2;
  string description = 3;
  repeated string capabilities = 4;
}

message HandleRequestEvent {
  string request_id = 1;
  string method = 2;
  string path = 3;
  map<string, string> headers = 4;
  bytes body = 5;
}
```

### 2. Plugin Discovery

Plugins will be discovered through:
- **Directory scanning**: `/var/lib/hockeypuck/plugins/`
- **Manifest files**: `plugin.toml` describing the plugin
- **Binary naming**: `hkp-plugin-<name>`

Example `plugin.toml`:
```toml
[plugin]
name = "antiabuse"
version = "1.0.0"
executable = "hkp-plugin-antiabuse"
protocol_version = "1.0"

[plugin.config]
# Plugin-specific configuration
threshold = 100
```

### 3. Process Management

The Plugin Host Manager handles:
- **Launch**: Start plugin processes with proper environment
- **Monitor**: Health checks and restart on failure
- **Communication**: Manage gRPC connections
- **Shutdown**: Graceful termination

### 4. Version Negotiation

```go
type ProtocolVersion struct {
    Major int
    Minor int
    Patch int
}

// During handshake
func NegotiateVersion(client, server ProtocolVersion) (ProtocolVersion, error) {
    // Find compatible version
}
```

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)
- [ ] Define protobuf schema
- [ ] Implement basic plugin host manager
- [ ] Create plugin discovery mechanism
- [ ] Implement health monitoring

### Phase 2: gRPC Framework (Week 3-4)
- [ ] Build gRPC server framework for plugins
- [ ] Implement client-side integration in host
- [ ] Add version negotiation
- [ ] Create logging/debugging infrastructure

### Phase 3: Storage & Events (Week 5-6)
- [ ] Implement storage proxy over gRPC
- [ ] Build event streaming system
- [ ] Add request handling pipeline
- [ ] Implement middleware chain over gRPC

### Phase 4: Plugin Migration (Week 7-8)
- [ ] Convert antiabuse plugin as proof of concept
- [ ] Create plugin SDK/template
- [ ] Document plugin development
- [ ] Migrate remaining plugins

### Phase 5: Production Readiness (Week 9-10)
- [ ] Performance optimization
- [ ] Security hardening
- [ ] Monitoring and metrics
- [ ] Documentation and examples

## Security Considerations

1. **Authentication**: Plugins authenticate with shared secret or mTLS
2. **Authorization**: Capabilities-based access control
3. **Isolation**: Plugins run with minimal privileges
4. **Communication**: Optional TLS for gRPC connections

## Performance Considerations

1. **Connection Pooling**: Reuse gRPC connections
2. **Streaming**: Use streaming for events and bulk operations
3. **Caching**: Cache frequent storage queries
4. **Buffering**: Buffer events to reduce RPC calls

## Migration Guide

For existing plugin developers:

1. **Replace Plugin Interface**: Implement gRPC server instead of Go interface
2. **Update Dependencies**: Remove direct Hockeypuck dependencies
3. **Change Build**: Build standalone binary instead of `.so`
4. **Update Configuration**: Use new plugin manifest format
5. **Test**: Verify functionality with new architecture

## Example Plugin Structure

```
hkp-plugin-antiabuse/
├── cmd/
│   └── main.go          # Main entry point
├── internal/
│   ├── server.go        # gRPC server implementation
│   ├── handler.go       # Request handling logic
│   └── config.go        # Configuration
├── proto/
│   └── plugin.proto     # Plugin-specific extensions
├── plugin.toml          # Plugin manifest
└── Dockerfile           # Container build (optional)
```

## Benefits Summary

1. **License Freedom**: Plugins can be proprietary, MIT, Apache, etc.
2. **Language Choice**: Python, Rust, Go, Java - any gRPC language
3. **Deployment Flexibility**: Plugins can run remotely
4. **Version Independence**: No binary compatibility issues
5. **Better Testing**: Easier to mock and test in isolation
6. **Process Isolation**: Plugin crashes don't affect Hockeypuck

## References

- [HashiCorp go-plugin](https://github.com/hashicorp/go-plugin)
- [gRPC Go Tutorial](https://grpc.io/docs/languages/go/)
- [Protocol Buffers](https://developers.google.com/protocol-buffers)
