package main

import (
	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/ratelimit-tarpit/ratelimittarpit"
)

// Plugin entry point
func CreatePlugin() plugin.Plugin {
	return &ratelimittarpit.TarpitPlugin{}
}
