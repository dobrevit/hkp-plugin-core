// Package version provides version negotiation and compatibility checking for gRPC plugins
package version

import (
	"fmt"
	"strconv"
	"strings"
)

// ProtocolVersion represents the gRPC plugin protocol version
type ProtocolVersion struct {
	Major int
	Minor int
	Patch int
}

// Current protocol version - update when making breaking changes
var CurrentProtocolVersion = ProtocolVersion{
	Major: 1,
	Minor: 0,
	Patch: 0,
}

// MinimumSupportedVersion defines the oldest supported protocol version
var MinimumSupportedVersion = ProtocolVersion{
	Major: 1,
	Minor: 0,
	Patch: 0,
}

// String returns the version as a string (e.g., "1.0.0")
func (v ProtocolVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ParseVersion parses a version string into a ProtocolVersion
func ParseVersion(versionStr string) (ProtocolVersion, error) {
	parts := strings.Split(versionStr, ".")
	if len(parts) != 3 {
		return ProtocolVersion{}, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", versionStr)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return ProtocolVersion{}, fmt.Errorf("invalid major version: %s", parts[0])
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return ProtocolVersion{}, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return ProtocolVersion{}, fmt.Errorf("invalid patch version: %s", parts[2])
	}

	return ProtocolVersion{
		Major: major,
		Minor: minor,
		Patch: patch,
	}, nil
}

// IsCompatible checks if the given version is compatible with the current protocol
func (v ProtocolVersion) IsCompatible(other ProtocolVersion) bool {
	// Major version must match exactly
	if v.Major != other.Major {
		return false
	}

	// Minor version compatibility: current version must be >= plugin version
	if v.Minor < other.Minor {
		return false
	}

	// Patch version is always compatible within the same major.minor
	return true
}

// IsSupported checks if the version is still supported
func (v ProtocolVersion) IsSupported() bool {
	return v.IsCompatible(MinimumSupportedVersion) && 
		   CurrentProtocolVersion.IsCompatible(v)
}

// Compare returns:
// -1 if v < other
//  0 if v == other
//  1 if v > other
func (v ProtocolVersion) Compare(other ProtocolVersion) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}

	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}

	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}

	return 0
}

// CompatibilityResult represents the result of a compatibility check
type CompatibilityResult struct {
	Compatible     bool
	ServerVersion  ProtocolVersion
	PluginVersion  ProtocolVersion
	Reason         string
	Recommendation string
}

// CheckCompatibility performs a comprehensive compatibility check
func CheckCompatibility(serverVersion, pluginVersion ProtocolVersion) CompatibilityResult {
	result := CompatibilityResult{
		ServerVersion: serverVersion,
		PluginVersion: pluginVersion,
	}

	// Check if plugin version is supported
	if !pluginVersion.IsSupported() {
		result.Compatible = false
		result.Reason = fmt.Sprintf("Plugin version %s is no longer supported (minimum: %s)", 
			pluginVersion, MinimumSupportedVersion)
		result.Recommendation = fmt.Sprintf("Update plugin to use protocol version %s or later", 
			MinimumSupportedVersion)
		return result
	}

	// Check basic compatibility
	if !serverVersion.IsCompatible(pluginVersion) {
		result.Compatible = false
		
		if serverVersion.Major != pluginVersion.Major {
			result.Reason = fmt.Sprintf("Major version mismatch: server %d, plugin %d", 
				serverVersion.Major, pluginVersion.Major)
			result.Recommendation = "Plugin must be updated to match server's major version"
		} else if serverVersion.Minor < pluginVersion.Minor {
			result.Reason = fmt.Sprintf("Plugin requires newer protocol: server %s, plugin %s", 
				serverVersion, pluginVersion)
			result.Recommendation = "Update server to support newer protocol version"
		}
		return result
	}

	// Compatible!
	result.Compatible = true
	result.Reason = "Versions are compatible"
	
	// Provide recommendations for optimization
	comparison := serverVersion.Compare(pluginVersion)
	if comparison > 0 {
		result.Recommendation = fmt.Sprintf("Plugin can be updated to use newer protocol features (current: %s, latest: %s)", 
			pluginVersion, serverVersion)
	} else if comparison == 0 {
		result.Recommendation = "Plugin is using the latest protocol version"
	}

	return result
}

// NegotiateVersion negotiates the best compatible version between server and plugin
func NegotiateVersion(serverVersions []ProtocolVersion, pluginVersions []ProtocolVersion) (ProtocolVersion, error) {
	// Find the highest version that both sides support
	var bestVersion *ProtocolVersion
	
	for _, serverVer := range serverVersions {
		for _, pluginVer := range pluginVersions {
			if serverVer.IsCompatible(pluginVer) {
				if bestVersion == nil || serverVer.Compare(*bestVersion) > 0 {
					bestVersion = &serverVer
				}
			}
		}
	}

	if bestVersion == nil {
		return ProtocolVersion{}, fmt.Errorf("no compatible version found between server versions %v and plugin versions %v", 
			serverVersions, pluginVersions)
	}

	return *bestVersion, nil
}

// GetSupportedVersions returns the list of protocol versions supported by this implementation
func GetSupportedVersions() []ProtocolVersion {
	var versions []ProtocolVersion
	
	// Add all versions from minimum to current
	for major := MinimumSupportedVersion.Major; major <= CurrentProtocolVersion.Major; major++ {
		startMinor := 0
		endMinor := CurrentProtocolVersion.Minor
		
		if major == MinimumSupportedVersion.Major {
			startMinor = MinimumSupportedVersion.Minor
		}
		if major < CurrentProtocolVersion.Major {
			endMinor = 999 // Future-proof for when we have multiple major versions
		}
		
		for minor := startMinor; minor <= endMinor; minor++ {
			startPatch := 0
			endPatch := CurrentProtocolVersion.Patch
			
			if major == MinimumSupportedVersion.Major && minor == MinimumSupportedVersion.Minor {
				startPatch = MinimumSupportedVersion.Patch
			}
			if major < CurrentProtocolVersion.Major || minor < CurrentProtocolVersion.Minor {
				endPatch = 999 // Future-proof
			}
			
			for patch := startPatch; patch <= endPatch; patch++ {
				version := ProtocolVersion{Major: major, Minor: minor, Patch: patch}
				if version.Compare(CurrentProtocolVersion) <= 0 {
					versions = append(versions, version)
				}
			}
		}
	}
	
	return versions
}