package main

import (
	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/antiabuse/antiabuse"
)

// GetPlugin returns the plugin instance for dynamic loading
func GetPlugin() plugin.Plugin {
	return antiabuse.GetPlugin()
}

func main() {}
