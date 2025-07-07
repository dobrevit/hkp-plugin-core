# gRPC Plugin System MVP

## Overview

This MVP demonstrates the new gRPC-based plugin architecture that solves the critical issues with Go's native plugin system (`.so` files) and provides clear licensing boundaries.

## What's Been Built

### 1. Core Infrastructure ✅

- **gRPC Protocol**: Complete protobuf definition with all necessary services
- **Plugin Discovery**: Automatic discovery via TOML manifests  
- **Process Lifecycle**: Full process management with health checks and restart logic
- **Server Framework**: Easy-to-use gRPC server framework for plugin developers

### 2. MVP Implementation ✅

- **Refactored Server** (`cmd/interpose/main_grpc.go`): New server using gRPC plugin architecture
- **Converted Plugin** (`plugins/antiabuse-grpc/`): AntiAbuse plugin rewritten for gRPC
- **Build System**: Makefile targets for building gRPC plugins
- **Configuration**: TOML-based configuration for server and plugins

### 3. Key Benefits Achieved ✅

- **License Freedom**: Plugins run as separate processes, avoiding AGPL contamination
- **Binary Independence**: No more Go plugin compatibility issues
- **Process Isolation**: Better stability and security
- **Language Flexibility**: Future plugins can be written in any gRPC-supported language

## Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│  Hockeypuck (AGPL)  │  gRPC   │   Plugin Process    │
│                     │◄───────►│   (Any License)     │
│  ┌───────────────┐  │         │  ┌──────────────┐  │
│  │ Lifecycle     │  │         │  │ gRPC Server  │  │
│  │ Manager       │  │         │  │              │  │
│  └───────────────┘  │         │  └──────────────┘  │
└─────────────────────┘         └─────────────────────┘
```

## Files Created/Modified

### Core Framework
- `proto/hkp_plugin.proto` - gRPC protocol definition
- `pkg/grpc/proto/` - Generated Go code from protobuf
- `pkg/discovery/` - Plugin discovery and registration
- `pkg/lifecycle/` - Process lifecycle management  
- `pkg/grpc/server/` - Plugin server framework

### MVP Implementation
- `cmd/interpose/main_grpc.go` - Refactored server
- `cmd/interpose/grpc-server.toml` - Configuration
- `plugins/antiabuse-grpc/` - Converted plugin
- `test-grpc-mvp.sh` - Test script

### Build System
- Updated `Makefile` with gRPC targets:
  - `make proto` - Generate protobuf code
  - `make grpc-plugins` - Build gRPC plugins  
  - `make mvp-grpc` - Build complete MVP

## How to Test the MVP

1. **Build the MVP**:
   ```bash
   make mvp-grpc
   ```

2. **Run the test script**:
   ```bash
   ./test-grpc-mvp.sh
   ```

3. **Manual testing**:
   ```bash
   cd cmd/interpose
   ./interpose-grpc -config grpc-server.toml
   ```

## Plugin Development Example

The antiabuse plugin demonstrates how easy it is to create plugins:

```go
type AntiAbusePlugin struct {
    server.BasePlugin
    // Plugin-specific fields
}

func (p *AntiAbusePlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
    // Rate limiting logic
    // Return response or allow continuation
}
```

## API Endpoints

The MVP exposes these endpoints:

- **Core HKP**: `/pks/lookup`, `/pks/add`, `/pks/stats`
- **Plugin Management**: 
  - `/plugins/status` - System status
  - `/plugins/list` - List all plugins
  - `/plugins/health` - Health checks
  - `/plugins/restart` - Restart specific plugins

## Next Steps

With the MVP complete, the next high-priority task is implementing the gRPC client integration in Hockeypuck itself, which will complete the full architecture.

## Key Achievements

1. **Solved License Issue**: Clear separation between AGPL Hockeypuck and plugins
2. **Eliminated Binary Compatibility**: No more Go plugin version matching requirements  
3. **Improved Stability**: Process isolation prevents plugin crashes from affecting main server
4. **Enhanced Debugging**: gRPC reflection and separate logs per plugin
5. **Future-Proofed**: Can support plugins in Python, Rust, Java, etc.

This MVP proves the gRPC plugin architecture is viable and provides a solid foundation for the complete plugin system.