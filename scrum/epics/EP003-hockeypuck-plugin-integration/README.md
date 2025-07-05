# Epic 003: Hockeypuck Plugin Integration & Licensing Refactor

## Epic Overview

**Epic ID**: EP003  
**Epic Name**: Hockeypuck Plugin Integration & Licensing Refactor  
**Priority**: Critical  
**Business Value**: Enable plugin ecosystem for Hockeypuck while maintaining licensing compliance  
**Story Points**: 55  
**Planned Duration**: 3 Sprints (6 weeks)  
**Team Lead**: Senior Go Developer + Legal Counsel  

## Epic Goal

Refactor and integrate the existing plugin API system with the upstream Hockeypuck project while ensuring proper licensing separation between AGPL core and MIT plugin API. Create the foundation for a sustainable plugin ecosystem that respects both legal requirements and architectural best practices.

## Business Value

- **Legal Compliance**: Ensure AGPL compliance while enabling diverse plugin licensing
- **Upstream Integration**: Prepare for integration with Hockeypuck project
- **Plugin Ecosystem**: Enable third-party plugin development
- **Architecture Foundation**: Clean separation of concerns for long-term maintainability
- **Community Growth**: Foster broader Hockeypuck adoption through extensibility

## Epic Hypothesis

**We believe** that creating a legally compliant plugin integration with Hockeypuck  
**Will achieve** seamless plugin ecosystem without licensing conflicts  
**We will know this is true when** plugins can be developed under any OSI license and Hockeypuck maintains AGPL compliance.

## User Personas

### Primary Users
- **Hockeypuck Maintainers**: Need clean integration path
- **Plugin Developers**: Require clear licensing and API boundaries
- **Enterprise Users**: Need legally compliant extensibility

### Secondary Users
- **Legal Compliance Officers**: Need licensing clarity
- **Open Source Community**: Want contribution opportunities
- **System Administrators**: Need seamless deployment

## Features Included

### 1. Licensing Architecture Refactor
- Separate plugin API as independent MIT-licensed project
- Create abstraction layer for AGPL/MIT boundary
- Implement wrapper pattern for type conversion
- Establish legal documentation and guidelines

### 2. Hockeypuck Integration Layer
- Minimal changes to Hockeypuck core
- Plugin loader and registry integration
- Storage operation hooks and wrappers
- HTTP middleware registration

### 3. OpenPGP Library Analysis
- Audit all OpenPGP dependencies for licensing
- Create safe re-exports of permissive libraries
- Implement type-safe conversion layers
- Document approved dependencies

### 4. Plugin API Foundation
- Create standalone plugin API repository
- Implement plugin lifecycle management
- Define storage, protocol, and application hooks
- Establish plugin development guidelines

## User Stories

### US015: Plugin API Project Creation
**As a** Plugin Developer  
**I want** a standalone MIT-licensed plugin API  
**So that** I can develop plugins under any compatible license

**Story Points**: 8  
**Sprint**: 6  

### US016: Licensing Boundary Implementation
**As a** Legal Compliance Officer  
**I want** clear separation between AGPL and MIT code  
**So that** licensing obligations are well-defined and enforceable

**Story Points**: 13  
**Sprint**: 6  

### US017: Hockeypuck Integration Wrapper
**As a** Hockeypuck Maintainer  
**I want** minimal changes to core for plugin support  
**So that** the codebase remains stable and maintainable

**Story Points**: 13  
**Sprint**: 6-7  

### US018: OpenPGP Library Compatibility
**As a** Plugin Developer  
**I want** to use standard OpenPGP types safely  
**So that** I can work with familiar APIs without licensing issues

**Story Points**: 8  
**Sprint**: 7  

### US019: Plugin Loading Infrastructure
**As a** System Administrator  
**I want** dynamic plugin loading from directories  
**So that** I can manage plugins without recompiling Hockeypuck

**Story Points**: 8  
**Sprint**: 7  

### US020: Documentation and Guidelines
**As a** Plugin Developer  
**I want** comprehensive documentation on plugin development  
**So that** I understand both technical and legal requirements

**Story Points**: 5  
**Sprint**: 8  

## Technical Architecture

### Licensing Separation Model
```
┌─────────────────────────────────────────────────────────────────┐
│                     Plugin Ecosystem                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  Federation     │  │   Monitoring    │  │    Custom       │  │
│  │   Plugin        │  │    Plugin       │  │   Business      │  │
│  │ (Any License)   │  │ (Any License)   │  │   Plugin        │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                   Plugin API (MIT Licensed)                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ • Abstract interfaces (StorageInterface, ProtocolInterface)│ │
│  │ • Safe OpenPGP re-exports (golang.org/x/crypto/openpgp)    │ │
│  │ • Event system and lifecycle management                    │ │
│  │ • No AGPL dependencies                                     │ │
│  └────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│              Translation/Wrapper Layer (AGPL)                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ • Type conversion between MIT interfaces and AGPL types    │ │
│  │ • Plugin registry and loader                               │ │
│  │ • Storage operation wrappers                               │ │
│  │ • HTTP middleware integration                              │ │
│  └────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                  Hockeypuck Core (AGPL)                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ • Storage implementations (PostgreSQL, LevelDB)            │ │
│  │ • HKP protocol handlers                                    │ │
│  │ • Reconciliation protocol (conflux)                        │ │
│  │ • Core business logic                                      │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Plugin API Structure
```
hockeypuck-plugin-api/
├── LICENSE                    # MIT License
├── README.md                  # Plugin development guide
├── go.mod                     # No AGPL dependencies
├── pkg/
│   ├── plugin/
│   │   ├── interface.go       # Core plugin interfaces
│   │   ├── registry.go        # Plugin registry
│   │   ├── loader.go          # .so file loading
│   │   └── lifecycle.go       # Plugin lifecycle
│   ├── storage/
│   │   ├── interface.go       # Storage plugin interface
│   │   └── hooks.go           # Storage operation hooks
│   ├── protocol/
│   │   ├── interface.go       # Protocol plugin interface
│   │   └── middleware.go      # HTTP middleware types
│   ├── openpgp/
│   │   ├── types.go           # Safe OpenPGP re-exports
│   │   └── utils.go           # Utility functions
│   └── event/
│       ├── bus.go             # Event bus implementation
│       └── types.go           # Event definitions
├── examples/
│   ├── federation/            # Federation plugin example
│   ├── monitoring/            # Monitoring plugin example
│   └── simple/                # Basic plugin template
└── docs/
    ├── plugin-development.md  # Development guide
    ├── licensing.md           # Legal guidelines
    └── api-reference.md       # API documentation
```

### Hockeypuck Integration Points

#### Minimal Core Changes
```go
// cmd/hockeypuck/main.go
import (
    "github.com/hockeypuck/plugin-api/pkg/plugin"
    "github.com/hockeypuck/hockeypuck/internal/pluginwrapper"
)

func main() {
    // Existing initialization...
    
    // Plugin system initialization (optional)
    if config.PluginDir != "" {
        pluginMgr, err := pluginwrapper.Initialize(config.PluginDir, server)
        if err != nil {
            log.Warnf("Plugin initialization failed: %v", err)
        } else {
            defer pluginMgr.Shutdown()
        }
    }
    
    // Rest of existing code unchanged...
}
```

#### Storage Wrapper Implementation
```go
// internal/pluginwrapper/storage.go
package pluginwrapper

import (
    "github.com/hockeypuck/plugin-api/pkg/storage"
    "github.com/hockeypuck/hockeypuck/storage"
)

type StorageWrapper struct {
    backend storage.Storage
    hooks   []pluginapi.StorageHook
}

func (w *StorageWrapper) Insert(keys []*openpgp.Entity) error {
    // Convert to plugin API types
    pluginKeys := convertToPluginKeys(keys)
    
    // Pre-hooks
    for _, hook := range w.hooks {
        if err := hook.BeforeInsert(pluginKeys); err != nil {
            return err
        }
    }
    
    // Original operation
    err := w.backend.Insert(keys)
    
    // Post-hooks
    for _, hook := range w.hooks {
        hook.AfterInsert(pluginKeys)
    }
    
    return err
}
```

## API Endpoints to Implement

### Plugin Management
- `GET /plugins` - List loaded plugins
- `GET /plugins/{name}` - Get plugin details
- `POST /plugins/reload` - Reload plugins (admin only)
- `GET /plugins/health` - Plugin health status

### Plugin Development Support
- `GET /api/plugin/interfaces` - Available plugin interfaces
- `GET /api/plugin/events` - Available event types
- `POST /api/plugin/validate` - Validate plugin before loading

## Implementation Steps

### Phase 1: Foundation (Sprint 6)
1. **Create Plugin API Repository**
   - Set up separate GitHub repository
   - MIT license and legal documentation
   - Basic plugin interfaces
   - OpenPGP dependency analysis

2. **Legal Framework**
   - Document licensing boundaries
   - Create contribution guidelines
   - Establish legal review process
   - Plugin developer agreement template

### Phase 2: Integration Layer (Sprint 7)
1. **Hockeypuck Wrapper Layer**
   - Create internal/pluginwrapper package
   - Implement storage operation hooks
   - Add HTTP middleware support
   - Plugin registry integration

2. **Safe OpenPGP Integration**
   - Audit all OpenPGP dependencies
   - Create safe re-exports
   - Type conversion utilities
   - Performance optimization

### Phase 3: Deployment (Sprint 8)
1. **Plugin Loading Infrastructure**
   - .so file loading and validation
   - Plugin lifecycle management
   - Configuration integration
   - Error handling and recovery

2. **Documentation and Testing**
   - Comprehensive plugin development guide
   - Legal compliance documentation
   - Example plugins and templates
   - Integration test suite

## Acceptance Criteria

### Epic-Level Acceptance Criteria
- [ ] Plugin API repository created with MIT license
- [ ] Clear licensing separation between AGPL and MIT code
- [ ] Hockeypuck integration with minimal core changes
- [ ] OpenPGP libraries safely re-exported
- [ ] Plugin loading infrastructure functional
- [ ] Comprehensive legal and technical documentation
- [ ] Example plugins demonstrating capabilities
- [ ] Legal review completed and approved

## Definition of Done

### Legal Compliance
- [ ] All licensing boundaries clearly documented
- [ ] Legal review completed by qualified counsel
- [ ] Contribution guidelines established
- [ ] Plugin developer agreement template created

### Technical Implementation
- [ ] Plugin API compiles with no AGPL dependencies
- [ ] Hockeypuck integration working with existing functionality
- [ ] Plugin loading and lifecycle management operational
- [ ] Storage and protocol hooks functional
- [ ] Example plugins working end-to-end

### Documentation
- [ ] Plugin development guide complete
- [ ] Legal compliance documentation
- [ ] API reference documentation
- [ ] Integration guide for Hockeypuck
- [ ] Contribution guidelines

## Dependencies

### Legal Dependencies
- Legal counsel review for licensing approach
- Open source license compatibility analysis
- Contributor agreement templates

### Technical Dependencies
- Analysis of Hockeypuck codebase and architecture
- OpenPGP library licensing audit
- Go plugin system compatibility testing

## Risks and Mitigation

### High Risks
1. **Legal Complexity**: AGPL/MIT boundary confusion
   - *Mitigation*: Clear documentation, legal review, automated checks
2. **Hockeypuck Integration**: Breaking existing functionality
   - *Mitigation*: Minimal changes, extensive testing, optional plugin system

### Medium Risks
1. **Performance Overhead**: Plugin wrapper layer impact
   - *Mitigation*: Performance testing, optimization, benchmarking
2. **Maintenance Burden**: Two-repository maintenance
   - *Mitigation*: Automated synchronization, clear ownership model

## Success Metrics

### Legal Compliance
- **Zero licensing violations** in plugin API
- **Legal review approval** from qualified counsel
- **Clear guidelines** for plugin developers

### Technical Success
- **<5% performance overhead** from plugin layer
- **100% backward compatibility** with existing Hockeypuck
- **Plugin loading success rate** >95%

### Community Adoption
- **Example plugins** demonstrating capabilities
- **Clear documentation** for plugin development
- **Community contributions** within 3 months

## Sprint Breakdown

### Sprint 6 (Weeks 11-12)
- **Focus**: Plugin API foundation and licensing framework
- **Stories**: US015, US016
- **Deliverables**: Plugin API repository, legal documentation

### Sprint 7 (Weeks 13-14)
- **Focus**: Hockeypuck integration and OpenPGP compatibility
- **Stories**: US017, US018, US019
- **Deliverables**: Integration layer, OpenPGP re-exports, plugin loading

### Sprint 8 (Weeks 15-16)
- **Focus**: Documentation and testing
- **Stories**: US020, testing and validation
- **Deliverables**: Complete documentation, example plugins, test suite

## Cost Estimation

### Development Costs
- **Senior Go Developer**: 6 weeks × $12,000/month × 0.25 = $18,000
- **Legal Counsel**: 10 hours × $400/hour = $4,000
- **Technical Writer**: 2 weeks × $8,000/month × 0.25 = $4,000

**Total Development**: $26,000

### Infrastructure Costs
- **Additional repository hosting**: $0 (GitHub)
- **Legal review documentation**: $500
- **Testing infrastructure**: $300

**Total Infrastructure**: $800

**Epic Total**: $26,800

This epic is critical for establishing the foundation that all future plugin development will build upon, ensuring both legal compliance and technical excellence from the start.