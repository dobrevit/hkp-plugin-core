package main

import (
	"hkp-plugin-core/pkg/plugin"
	"hkp-plugin-core/src/plugins/ratelimit-tarpit/ratelimittarpit"
)

// Plugin entry point
func CreatePlugin() plugin.Plugin {
	return &ratelimittarpit.TarpitPlugin{}
}
