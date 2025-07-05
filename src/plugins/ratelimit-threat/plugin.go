package main

import (
	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/ratelimit-threat/ratelimitthreat"
)

// Plugin entry point
func CreatePlugin() plugin.Plugin {
	return &ratelimitthreat.ThreatIntelPlugin{}
}
