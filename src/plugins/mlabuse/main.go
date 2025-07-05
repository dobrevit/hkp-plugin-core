package main

import (
	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/mlabuse/mlabuse"
)

// GetPlugin returns the plugin instance for dynamic loading
func GetPlugin() plugin.Plugin {
	return mlabuse.GetPlugin()
}

func main() {}
