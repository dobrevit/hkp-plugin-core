# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Architecture

This is the HKP Plugin System - a comprehensive, modular security and operational framework for Hockeypuck OpenPGP key servers. The system implements a gRPC-based plugin architecture with clear licensing boundaries, allowing plugins to be developed under any license while Hockeypuck remains AGPL.

### Core Components

- **Plugin Framework**: Process-based architecture using gRPC for inter-process communication (similar to Terraform providers)
- **gRPC Protocol**: Well-defined protobuf-based API ensuring clean separation between AGPL Hockeypuck and plugins
- **Process Management**: Plugin lifecycle management (discovery, launch, monitoring, restart)
- **Event System**: Event-driven communication via gRPC streams
- **Storage Interface**: Plugin access to storage through gRPC API without direct AGPL code dependency
- **Configuration**: TOML-based configuration for both Hockeypuck and plugins
- **Version Negotiation**: Protocol versioning for backward compatibility

### Plugin Categories

1. **Security Plugins**: Zero Trust, ML Abuse Detection
2. **Rate Limiting Plugins**: Geographic Analysis, Threat Intelligence, ML Extension, Tarpit
3. **Operational Plugins**: Anti-Abuse, Basic Rate Limiting

### Key Architecture Files

- `proto/`: gRPC protocol definitions (protobuf files)
- `pkg/plugin/`: Core plugin interfaces and process management
- `pkg/grpc/client/`: gRPC client implementation for Hockeypuck
- `pkg/grpc/server/`: gRPC server framework for plugins
- `pkg/discovery/`: Plugin discovery and registration
- `pkg/lifecycle/`: Plugin process lifecycle management
- `pkg/config/`: Configuration structures for plugins
- `src/plugins/`: Individual plugin implementations (standalone binaries)
- `cmd/plugin-host/`: Plugin host process that manages plugin lifecycle

## Development Commands

### Building
```bash
# Build all plugins and application
make all

# Build only plugins
make plugins

# Build specific plugin
make plugin-antiabuse

# Build main application
make app
```

### Testing
```bash
# Run all tests (unit + integration)
make test

# Run with coverage
make test-coverage

# Run verbose tests
make test-verbose

# Run only unit tests
make test-unit

# Direct test script usage
./scripts/test-all.sh
./scripts/test-all.sh --coverage
./scripts/test-all.sh --verbose
```

### Code Quality
```bash
# Format code
make fmt

# Run linter (requires golangci-lint)
make lint
```

### Development Workflow
```bash
# Development mode (build and run)
make dev

# Run application with config
make run
```

## Plugin Development

### gRPC-Based Plugin Architecture

Plugins are standalone executables that communicate with Hockeypuck via gRPC:

1. **Plugin Binary**: Standalone executable (any language supporting gRPC)
2. **gRPC Server**: Plugin implements gRPC server based on protobuf definitions
3. **Protocol Buffer**: Defines the contract between Hockeypuck and plugins
4. **Process Isolation**: Plugins run in separate processes with clear boundaries

### Plugin gRPC Service Interface
```protobuf
service HKPPlugin {
  // Lifecycle methods
  rpc Initialize(InitRequest) returns (InitResponse);
  rpc Shutdown(ShutdownRequest) returns (ShutdownResponse);
  
  // Plugin information
  rpc GetInfo(Empty) returns (PluginInfo);
  
  // Event handling
  rpc HandleKeyChange(KeyChangeEvent) returns (HandleResponse);
  rpc SubscribeEvents(EventSubscription) returns (stream Event);
  
  // Storage access (proxied through gRPC)
  rpc QueryKeys(QueryRequest) returns (QueryResponse);
  
  // Health monitoring
  rpc HealthCheck(Empty) returns (HealthStatus);
}
```

### Licensing Boundaries

**IMPORTANT**: The gRPC architecture creates a clear licensing boundary:
- **Hockeypuck (AGPL)**: Remains under AGPL license
- **gRPC Protocol**: Interface definitions are separate from implementation
- **Plugins (Any License)**: Can be licensed under any terms (MIT, Apache, proprietary, etc.)
- **Communication**: Via well-defined RPC protocol, not direct linking

This separation allows commercial plugins while respecting Hockeypuck's AGPL license.

### Architectural Shift from Go Plugins to gRPC

**Why the Change**: 
- Go's native plugin system (`.so` files) requires exact binary compatibility
- All dependencies must match exactly between host and plugins
- Plugins inherit the host's license (AGPL contamination)

**Benefits of gRPC Architecture**:
- **License Freedom**: Plugins can use any license
- **Language Agnostic**: Plugins can be written in any language with gRPC support
- **Version Independence**: No binary compatibility issues
- **Better Isolation**: Process-level isolation improves stability
- **Remote Plugins**: Possibility to run plugins on different machines

### Migration Strategy

1. **Phase 1**: Define gRPC protocol in protobuf
2. **Phase 2**: Implement plugin host with process management
3. **Phase 3**: Create gRPC server framework for Go plugins
4. **Phase 4**: Convert existing plugins to gRPC architecture
5. **Phase 5**: Deprecate Go plugin (`.so`) support

### Plugin Loading Order
Critical: Plugins must be loaded in dependency order:
1. Threat Intelligence (priority 15)
2. Geographic Analysis (priority 20)
3. ML Rate Limiting (priority 25)
4. ML Abuse Detection (priority 30)
5. Zero Trust (priority 40)
6. Tarpit (priority 50)

### Event System
Plugins communicate via events:
```go
// Subscribe to events
host.SubscribeEvent("threat.detected", handler)

// Publish events
host.PublishEvent(plugin.PluginEvent{
    Type: "abuse.detected",
    Source: pluginName,
    Data: eventData,
})
```

### Plugin Health Monitoring & Restart Logic 🔥

The `/pkg/health/` package provides comprehensive health monitoring and automatic restart capabilities:

**Key Features:**
- **Automatic Health Checks**: Continuous monitoring with configurable intervals (default: 30s)
- **Failure Detection**: Configurable failure thresholds and state tracking
- **Smart Restart Logic**: Exponential backoff with maximum restart limits
- **HTTP Health Endpoints**: REST API for health status and management
- **Kubernetes Integration**: Liveness and readiness probe support
- **Real-time Monitoring**: Detailed health metrics and status tracking

**HTTP Health Endpoints:**
- `GET /health` - Overall system health with plugin summary
- `GET /health/liveness` - Kubernetes liveness probe endpoint
- `GET /health/readiness` - Kubernetes readiness probe endpoint
- `GET /health/{plugin}` - Specific plugin health details
- `POST /health/{plugin}/restart` - Manual plugin restart trigger

**Health States:** Unknown → Healthy → Unhealthy → Restarting → Failed
**Restart Logic:** Automatic restart with exponential backoff (5s → 10s → 20s → ... → 5m max)
**Integration:** Seamlessly integrated with HockeypuckPluginHost

**Usage Example:**
```go
// Health monitoring is automatically included in SimplePluginAdapter
pluginAdapter := client.NewSimplePluginAdapter("/etc/hockeypuck/plugins", logger)
pluginAdapter.Start(ctx) // Starts health monitoring automatically

// Add health endpoints to HTTP server
mux.HandleFunc("/health", pluginAdapter.HandleManagement)
mux.HandleFunc("/plugins/", pluginAdapter.HandleManagement)
```

**Demo Application:** `cmd/health-monitoring/` provides a complete interactive demo
showing health monitoring, failure simulation, and automatic recovery!

### Plugin Lifecycle Management

The `/pkg/management/` package provides production-ready plugin lifecycle management:

**Key Features:**
- **Hot Reload**: Graceful plugin reloading with request draining
- **Health Monitoring**: Real-time plugin health checks
- **Configuration Management**: Dynamic config updates
- **HTTP Endpoints**: Ready-to-use management API
- **Request Draining**: Zero-downtime plugin transitions
- **Rollback Support**: Automatic rollback on failures

**HTTP Endpoints for Hockeypuck:**
- `GET /plugins/status` - System status and plugin states
- `GET /plugins/list` - Detailed plugin information
- `GET /plugins/health` - Health checks for all plugins
- `POST /plugins/reload?plugin=<name>` - Hot reload specific plugin
- `GET/PUT /plugins/config?plugin=<name>` - Config management

**Integration Example:**
```go
// In Hockeypuck's server initialization
pluginManager := management.NewPluginManager(host, settings, logger)
pluginSystem, _ := integration.InitializePlugins(ctx, host, settings)
pluginManager.SetPluginSystem(pluginSystem)

// Register HTTP endpoints
mux.HandleFunc("/plugins/status", pluginManager.StatusHandler)
mux.HandleFunc("/plugins/reload", pluginManager.ReloadHandler)
// ... other endpoints
```

This enables zero-downtime plugin updates and comprehensive monitoring for production Hockeypuck deployments!

## Project Structure

```
├── cmd/interpose/          # Main application
├── pkg/                    # Core packages
│   ├── config/             # AGPL-compliant configuration
│   ├── events/             # Event system (Hockeypuck bridge)
│   ├── hkpstorage/         # Clean-room storage interfaces
│   ├── integration/        # Simple Hockeypuck integration
│   ├── management/         # Plugin lifecycle management ⭐
│   ├── metrics/            # Prometheus metrics
│   ├── middleware/         # Interpose-compatible middleware
│   ├── plugin/             # Plugin management core
│   ├── ratelimit/          # Rate limiting backends
│   ├── recovery/           # Circuit breakers and recovery
│   ├── resources/          # Resource monitoring
│   ├── security/           # Security verification
│   ├── storage/            # Storage interfaces
│   └── versioning/         # Version management
├── src/plugins/            # Plugin implementations
│   ├── antiabuse/          # Basic anti-abuse
│   ├── mlabuse/            # ML abuse detection
│   ├── ratelimit-geo/      # Geographic analysis
│   ├── ratelimit-ml/       # ML rate limiting
│   ├── ratelimit-tarpit/   # Tarpit defense
│   ├── ratelimit-threat/   # Threat intelligence
│   └── zerotrust/          # Zero trust security
├── tests/                  # Integration tests
└── scripts/                # Build and test scripts
```

## Configuration

### Build Configuration
- Go version: 1.24
- Build mode: Plugin (for `.so` files)
- Main dependencies: interpose, mux, redis, geoip2, prometheus, tomb

### Plugin Configuration
Each plugin has its own TOML configuration section. The main application loads configuration from `cmd/interpose/config.toml`.

## Testing Strategy

The project uses a comprehensive testing approach:
- Unit tests for individual plugins and packages
- Integration tests that build and test plugin interactions
- Coverage reporting via `go tool cover`
- Test timeout: 10 minutes default

## Security Considerations

This is a security-focused project implementing:
- Zero Trust Network Access (ZTNA)
- ML-based abuse detection
- Threat intelligence integration
- Geographic anomaly detection
- Tarpit and honeypot systems

All plugins handle sensitive security data and must follow secure coding practices.

## Development Notes

- Plugins are compiled as shared libraries (`.so` files)
- The system uses tomb.Tomb for graceful goroutine management
- Event-driven architecture enables loose coupling between plugins
- Hot-reload capabilities allow plugin updates without server restart
- Resource monitoring and circuit breakers ensure system stability
