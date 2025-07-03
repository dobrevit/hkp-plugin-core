package main

import (
	"hkp-plugin-core/pkg/plugin"
	"hkp-plugin-core/src/plugins/ratelimit-threat/ratelimitthreat"
)

// Plugin entry point
func CreatePlugin() plugin.Plugin {
	return &ratelimitthreat.ThreatIntelPlugin{}
}
