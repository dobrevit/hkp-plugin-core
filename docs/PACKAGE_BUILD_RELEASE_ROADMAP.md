# Binary Package Build and Release Automation Roadmap
## Comprehensive CI/CD Strategy for Hockeypuck Package Distribution

**Document Version**: 1.0  
**Date**: July 1, 2025  
**Status**: Implementation Roadmap  

---

## Executive Summary

This document outlines a comprehensive strategy for implementing automated binary package builds and releases for Hockeypuck, focusing on .deb and .rpm packages alongside statically compiled binaries. The goal is to create a robust, automated CI/CD pipeline that produces production-ready packages for multiple Linux distributions.

## Current State Assessment

### Existing Infrastructure ✅
- **Debian Packaging**: Basic debian/ directory structure with control files
- **Docker CI/CD**: Multi-architecture Docker builds (linux/amd64, linux/arm64)
- **Snap Packaging**: Snapcraft configuration for snap store distribution
- **GitHub Actions**: Basic CI with Go testing and Docker publishing
- **Release Automation**: Basic release script with Git tagging
- **Makefile Build System**: Go build targets with version injection

### Gap Analysis 🔍
- **Missing RPM Packaging**: No .spec files or RPM build configuration
- **Limited Binary Distribution**: No standalone binary releases
- **Manual Package Building**: No automated package building in CI
- **Limited Architecture Support**: Only amd64 for .deb packages
- **No Package Repository**: No APT/YUM repository hosting
- **Limited Testing**: No package installation testing
- **No Dependency Management**: Limited control over runtime dependencies

---

## Implementation Roadmap

### Phase 1: Foundation Setup (Q3 2025)

#### 1.1 Enhanced Build Infrastructure
**Objective**: Establish robust multi-platform build foundation

```yaml
# Enhanced GitHub Actions matrix strategy
strategy:
  matrix:
    os: [ubuntu-20.04, ubuntu-22.04, ubuntu-24.04]
    arch: [amd64, arm64, armv7]
    go-version: ['1.23']
    package-format: [deb, rpm, binary]
```

**Deliverables**:
- Multi-architecture Go cross-compilation setup
- Enhanced Makefile with cross-platform targets
- Version management and build metadata injection
- Artifact naming and versioning standards

#### 1.2 Debian Package Enhancement
**Objective**: Improve existing Debian packaging for production use

**Tasks**:
- Update debian/control for modern dependencies
- Add multi-architecture support (amd64, arm64)
- Enhance systemd service configuration
- Add package testing and validation
- Implement dbgsym packages for debugging

```bash
# Enhanced debian/rules targets
override_dh_auto_build:
	$(MAKE) build VERSION=$(DEB_VERSION) GOARCH=$(DEB_HOST_ARCH)

override_dh_auto_test:
	$(MAKE) test-go test-postgresql

override_dh_systemd_enable:
	dh_systemd_enable --name=hockeypuck hockeypuck.service
```

#### 1.3 RPM Package Creation
**Objective**: Create comprehensive RPM packaging for RHEL/CentOS/Fedora

**New Files**:
- `hockeypuck.spec` - RPM package specification
- `rpm/` directory structure for RPM-specific files
- RHEL/CentOS systemd service files
- RPM build scripts and automation

```spec
# hockeypuck.spec template
Name:           hockeypuck
Version:        %{version}
Release:        1%{?dist}
Summary:        OpenPGP Key Server
License:        AGPL-3.0
URL:            https://hockeypuck.github.io/
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.23
BuildRequires:  systemd-rpm-macros
Requires:       shadow-utils

%description
Hockeypuck is an OpenPGP Key Server implementing the HTTP Keyserver Protocol.
```

### Phase 2: Automated Package Building (Q4 2025)

#### 2.1 GitHub Actions Package Workflow
**Objective**: Implement comprehensive automated package building

```yaml
name: Package Build and Release

on:
  push:
    tags: ['v*']
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to build'
        required: true

jobs:
  build-packages:
    strategy:
      matrix:
        include:
          - os: ubuntu-22.04
            package: deb
            arch: amd64
          - os: ubuntu-22.04
            package: deb
            arch: arm64
          - os: ubuntu-22.04
            package: rpm
            arch: amd64
          - os: ubuntu-22.04
            package: rpm
            arch: arm64
          - os: ubuntu-22.04
            package: binary
            arch: amd64
          - os: ubuntu-22.04
            package: binary
            arch: arm64
```

#### 2.2 Package Testing and Validation
**Objective**: Automated testing of built packages

**Testing Strategy**:
- Package installation testing in clean containers
- Service startup and functionality verification
- Configuration file validation
- Dependency resolution testing
- Package removal and upgrade testing

```yaml
  test-packages:
    needs: build-packages
    strategy:
      matrix:
        distro: [ubuntu:20.04, ubuntu:22.04, ubuntu:24.04, 
                 debian:11, debian:12, 
                 centos:8, centos:9, 
                 fedora:38, fedora:39]
    steps:
      - name: Test package installation
        run: |
          # Test .deb installation on Debian/Ubuntu
          # Test .rpm installation on RHEL/CentOS/Fedora
          # Verify service functionality
```

#### 2.3 Static Binary Distribution
**Objective**: Create standalone, statically-linked binaries

**Features**:
- CGO disabled for full static linking
- Multiple architecture support
- Compressed binary releases
- Checksum generation and verification
- Digital signature for security

```makefile
# Static binary targets
build-static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-w -s -X main.version=$(VERSION)" \
		-a -installsuffix cgo \
		-o bin/hockeypuck-linux-amd64 \
		./cmd/hockeypuck
```

### Phase 3: Distribution Infrastructure (Q1 2026)

#### 3.1 Package Repository Setup
**Objective**: Host APT and YUM repositories for easy installation

**APT Repository**:
- GitHub Pages or dedicated hosting for APT repository
- GPG signing for package integrity
- Multiple distribution support (Ubuntu, Debian)
- Automated repository metadata generation

**YUM Repository**:
- RPM repository hosting with createrepo
- GPG signing for RPM packages
- Support for RHEL, CentOS, Fedora
- Automated repository metadata updates

```bash
# APT repository structure
dists/
  focal/
    main/
      binary-amd64/
      binary-arm64/
  jammy/
    main/
      binary-amd64/
      binary-arm64/
pool/
  main/
    h/hockeypuck/
```

#### 3.2 Installation Scripts and Documentation
**Objective**: Simplify installation process for end users

**Deliverables**:
- One-line installation scripts for major distributions
- Comprehensive installation documentation
- Package manager integration
- Configuration templates and examples

```bash
# install.sh - Universal installation script
#!/bin/bash
# Auto-detect distribution and install appropriate package
if command -v apt-get >/dev/null 2>&1; then
    # Debian/Ubuntu installation
    curl -fsSL https://packages.hockeypuck.io/apt/gpg | sudo apt-key add -
    echo "deb https://packages.hockeypuck.io/apt $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hockeypuck.list
    sudo apt-get update && sudo apt-get install hockeypuck
elif command -v yum >/dev/null 2>&1; then
    # RHEL/CentOS/Fedora installation
    sudo yum-config-manager --add-repo https://packages.hockeypuck.io/rpm/hockeypuck.repo
    sudo yum install hockeypuck
fi
```

### Phase 4: Advanced Features (Q2 2026)

#### 4.1 Multi-Distribution Support
**Objective**: Support for additional Linux distributions

**Target Distributions**:
- **Debian**: 11, 12, Testing
- **Ubuntu**: 20.04 LTS, 22.04 LTS, 24.04 LTS, Latest
- **RHEL/CentOS**: 8, 9
- **Fedora**: 38, 39, 40
- **openSUSE**: Leap, Tumbleweed
- **Alpine**: Latest (musl-based static binaries)

#### 4.2 Package Signing and Security
**Objective**: Implement comprehensive package security

**Security Features**:
- GPG signing for all packages
- Checksums (SHA256, SHA512) for integrity verification
- SLSA attestations for supply chain security
- Vulnerability scanning for built packages
- Reproducible builds for verification

```yaml
  security-scan:
    needs: build-packages
    steps:
      - name: Scan packages for vulnerabilities
        uses: anchore/scan-action@v3
        with:
          path: "./packages/"
          
      - name: Generate SLSA attestation
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.4.0
```

#### 4.3 Advanced CI/CD Features
**Objective**: Implement sophisticated release automation

**Features**:
- Automated changelog generation
- Release notes from Git commits and PR descriptions
- Staged releases (alpha, beta, stable)
- Rollback capabilities
- Performance benchmarking
- Package size optimization

### Phase 5: Maintenance and Optimization (Q3 2026)

#### 5.1 Monitoring and Analytics
**Objective**: Track package distribution and usage

**Metrics**:
- Download statistics by package type and architecture
- Distribution usage analytics
- Installation success rates
- Error reporting and diagnostics
- Performance metrics

#### 5.2 Automated Maintenance
**Objective**: Reduce manual maintenance overhead

**Automation**:
- Dependency update notifications
- Security patch automation
- Repository cleanup and maintenance
- Package retention policies
- Build optimization and caching

---

## Technical Implementation Details

### Build Matrix Configuration
```yaml
# Complete build matrix for all targets
strategy:
  fail-fast: false
  matrix:
    include:
      # Debian packages
      - os: ubuntu-22.04
        package_type: deb
        arch: amd64
        go_arch: amd64
        distro: ubuntu
        version: "22.04"
      - os: ubuntu-22.04
        package_type: deb
        arch: arm64
        go_arch: arm64
        distro: ubuntu
        version: "22.04"
      
      # RPM packages
      - os: ubuntu-22.04
        package_type: rpm
        arch: x86_64
        go_arch: amd64
        distro: centos
        version: "9"
      - os: ubuntu-22.04
        package_type: rpm
        arch: aarch64
        go_arch: arm64
        distro: centos
        version: "9"
      
      # Static binaries
      - os: ubuntu-22.04
        package_type: binary
        arch: amd64
        go_arch: amd64
        static: true
      - os: ubuntu-22.04
        package_type: binary
        arch: arm64
        go_arch: arm64
        static: true
```

### Package Naming Convention
```bash
# Debian packages
hockeypuck_${VERSION}-1_amd64.deb
hockeypuck_${VERSION}-1_arm64.deb
hockeypuck-dbgsym_${VERSION}-1_amd64.deb

# RPM packages
hockeypuck-${VERSION}-1.el9.x86_64.rpm
hockeypuck-${VERSION}-1.el9.aarch64.rpm
hockeypuck-debuginfo-${VERSION}-1.el9.x86_64.rpm

# Static binaries
hockeypuck-${VERSION}-linux-amd64.tar.gz
hockeypuck-${VERSION}-linux-arm64.tar.gz
hockeypuck-${VERSION}-linux-armv7.tar.gz

# Checksums
hockeypuck-${VERSION}-checksums.txt
hockeypuck-${VERSION}-checksums.txt.sig
```

### Repository Structure
```
packages.hockeypuck.io/
├── apt/
│   ├── dists/
│   │   ├── focal/
│   │   ├── jammy/
│   │   └── noble/
│   ├── pool/
│   └── gpg
├── rpm/
│   ├── el8/
│   ├── el9/
│   ├── fedora38/
│   └── fedora39/
├── binaries/
│   ├── latest/
│   └── archive/
└── install.sh
```

---

## Resource Requirements

### Infrastructure Costs
- **GitHub Actions**: ~$50-100/month for build minutes
- **Package Hosting**: ~$20-50/month for repository hosting
- **CDN**: ~$10-30/month for global distribution
- **Monitoring**: ~$20-40/month for analytics and monitoring

### Development Time Estimates
- **Phase 1**: 3-4 weeks (1 developer)
- **Phase 2**: 4-6 weeks (1 developer)
- **Phase 3**: 3-4 weeks (1 developer + DevOps)
- **Phase 4**: 4-6 weeks (1 developer + security review)
- **Phase 5**: 2-3 weeks (ongoing maintenance setup)

### Maintenance Overhead
- **Weekly**: Repository maintenance, dependency updates
- **Monthly**: Security patch reviews, analytics review
- **Quarterly**: Distribution support updates, optimization

---

## Success Metrics

### Technical Metrics
- **Build Success Rate**: >98% for all package types
- **Build Time**: <15 minutes for complete matrix
- **Package Size**: <50MB for binaries, <20MB for packages
- **Installation Success**: >99% on supported distributions

### Distribution Metrics
- **Download Growth**: Track adoption across package types
- **Distribution Coverage**: Support 95% of target use cases
- **User Satisfaction**: <5% installation issues reported
- **Security**: Zero package integrity issues

### Operational Metrics
- **Release Frequency**: Support weekly releases if needed
- **Time to Release**: <2 hours from tag to availability
- **Rollback Time**: <30 minutes for critical issues
- **Support Overhead**: <10% developer time for maintenance

---

## Risk Mitigation

### Technical Risks
- **Build Failures**: Comprehensive testing and rollback procedures
- **Dependency Issues**: Pinned dependencies and compatibility testing
- **Security Vulnerabilities**: Automated scanning and rapid patching
- **Performance Regression**: Benchmarking and performance testing

### Operational Risks
- **Infrastructure Outages**: Multiple hosting providers and CDN
- **Maintainer Availability**: Documentation and automation
- **Cost Overruns**: Usage monitoring and alerts
- **Legal/Compliance**: License compliance and security attestations

---

## Migration Strategy

### Phase 1: Parallel Development
- Develop package building alongside existing processes
- Test with internal releases and staging environments
- Gradually expand distribution support

### Phase 2: Soft Launch
- Release packages for limited distributions
- Gather feedback from early adopters
- Refine processes based on real-world usage

### Phase 3: Full Deployment
- Complete rollout across all supported distributions
- Deprecate manual packaging processes
- Establish monitoring and maintenance procedures

### Phase 4: Optimization
- Performance tuning and cost optimization
- Advanced features and automation
- Community feedback integration

---

## Conclusion

This roadmap provides a comprehensive strategy for implementing world-class package distribution for Hockeypuck. The phased approach ensures manageable implementation while delivering immediate value to users.

**Key Benefits**:
- **Easy Installation**: One-command installation across major Linux distributions
- **Security**: Signed packages with integrity verification
- **Automation**: Minimal manual intervention for releases
- **Scalability**: Support for growing user base and new distributions
- **Maintainability**: Automated processes reduce ongoing overhead

**Immediate Actions**:
1. Review and approve roadmap
2. Set up GitHub Actions enhancement for Phase 1
3. Create RPM packaging specifications
4. Establish package signing infrastructure
5. Begin implementation of enhanced Debian packaging

**Success Criteria**: By Q3 2026, Hockeypuck should have a fully automated, secure, and comprehensive package distribution system supporting all major Linux distributions with minimal maintenance overhead.

---

**Document Status**: Ready for technical review and implementation planning
