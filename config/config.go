package config

import (
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Config represents the main application configuration
type Config struct {
	Server    ServerConfig              `toml:"server"`
	Plugins   PluginsConfig             `toml:"plugins"`
	RateLimit RateLimitConfig           `toml:"rateLimit"`
	Logging   LoggingConfig             `toml:"logging"`
}

// ServerConfig contains server-specific configuration
type ServerConfig struct {
	Bind    string `toml:"bind"`
	DataDir string `toml:"dataDir"`
}

// PluginsConfig contains plugin system configuration
type PluginsConfig struct {
	Enabled   bool                            `toml:"enabled"`
	Directory string                          `toml:"directory"`
	Config    map[string]map[string]any `toml:"config"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	Enabled                   bool          `toml:"enabled"`
	MaxConcurrentConnections  int           `toml:"maxConcurrentConnections"`
	ConnectionRate            int           `toml:"connectionRate"`
	HTTPRequestRate           int           `toml:"httpRequestRate"`
	HTTPErrorRate             int           `toml:"httpErrorRate"`
	CrawlerBlockDuration      time.Duration `toml:"crawlerBlockDuration"`
	Backend                   BackendConfig `toml:"backend"`
	Tor                       TorConfig     `toml:"tor"`
	Headers                   HeadersConfig `toml:"headers"`
	Whitelist                 WhitelistConfig `toml:"whitelist"`
}

// BackendConfig contains backend storage configuration
type BackendConfig struct {
	Type string `toml:"type"`
}

// TorConfig contains Tor-specific rate limiting configuration
type TorConfig struct {
	Enabled                     bool          `toml:"enabled"`
	MaxRequestsPerConnection    int           `toml:"maxRequestsPerConnection"`
	MaxConcurrentConnections    int           `toml:"maxConcurrentConnections"`
	ConnectionRate              int           `toml:"connectionRate"`
	ConnectionRateWindow        time.Duration `toml:"connectionRateWindow"`
	BanDuration                 time.Duration `toml:"banDuration"`
	RepeatOffenderBanDuration   time.Duration `toml:"repeatOffenderBanDuration"`
	ExitNodeListURL             string        `toml:"exitNodeListURL"`
	UpdateInterval              time.Duration `toml:"updateInterval"`
	CacheFilePath               string        `toml:"cacheFilePath"`
	GlobalRateLimit             bool          `toml:"globalRateLimit"`
	GlobalRequestRate           int           `toml:"globalRequestRate"`
	GlobalRateWindow            time.Duration `toml:"globalRateWindow"`
	GlobalBanDuration           time.Duration `toml:"globalBanDuration"`
}

// HeadersConfig contains HTTP headers configuration
type HeadersConfig struct {
	Enabled   bool   `toml:"enabled"`
	TorHeader string `toml:"torHeader"`
	BanHeader string `toml:"banHeader"`
}

// WhitelistConfig contains IP whitelist configuration
type WhitelistConfig struct {
	IPs []string `toml:"ips"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Bind:    ":11371",
			DataDir: "/var/lib/hockeypuck",
		},
		Plugins: PluginsConfig{
			Enabled:   true,
			Directory: "./plugins",
			Config: map[string]map[string]any{
				"zero-trust-security": {
					"enabled":                   true,
					"requireAuthentication":     true,
					"maxRiskScore":              0.7,
					"sessionTimeout":            "30m",
					"reevaluationInterval":      "5m",
					"deviceFingerprintingLevel": "standard",
					"auditLevel":                "basic",
					"auditLogPath":              "./logs",
					"publicPaths": []string{
						"/pks/lookup",
						"/pks/stats",
						"/health",
						"/metrics",
						"/ratelimit/tarpit/status",
						"/ratelimit/ml/status",
						"/ratelimit/threatintel/status",
					},
				},
				"ratelimit-geo": {
					"enabled":                   true,
					"geoip_database_path":       "/usr/share/GeoIP/GeoLite2-City.mmdb",
					"impossible_travel_enabled": true,
					"max_travel_speed_kmh":      1000.0,
					"clustering_enabled":        true,
					"cluster_radius_km":         50.0,
					"cluster_size_threshold":    5,
					"asn_analysis_enabled":      true,
					"max_asns_per_ip":           3,
					"ban_duration":              "1h",
					"impossible_travel_ban":     "6h",
					"clustering_ban":            "2h",
					"asn_jumping_ban":           "30m",
				},
				"ratelimit-threat": {
					"enabled":             true,
					"updateInterval":      "1h",
					"cacheSize":           100000,
					"blockDuration":       "24h",
					"reputationThreshold": 0.3,
					"autoBlock":           true,
					"shareThreatData":     false,
					"threatFeeds": []map[string]any{
						{
							"name":       "AlienVault OTX",
							"url":        "https://reputation.alienvault.com/reputation.data",
							"type":       "ip",
							"format":     "json",
							"updateFreq": "1h",
							"enabled":    true,
						},
						{
							"name":       "Abuse.ch Feodo Tracker",
							"url":        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
							"type":       "ip",
							"format":     "txt",
							"updateFreq": "2h",
							"enabled":    true,
						},
					},
				},
			},
		},
		RateLimit: RateLimitConfig{
			Enabled:                   true,
			MaxConcurrentConnections:  80,
			ConnectionRate:            40,
			HTTPRequestRate:           100,
			HTTPErrorRate:             20,
			CrawlerBlockDuration:      24 * time.Hour,
			Backend: BackendConfig{
				Type: "memory",
			},
			Tor: TorConfig{
				Enabled:                     true,
				MaxRequestsPerConnection:    2,
				MaxConcurrentConnections:    1,
				ConnectionRate:              1,
				ConnectionRateWindow:        10 * time.Second,
				BanDuration:                 24 * time.Hour,
				RepeatOffenderBanDuration:   576 * time.Hour,
				ExitNodeListURL:             "https://www.dan.me.uk/torlist/?exit",
				UpdateInterval:              1 * time.Hour,
				CacheFilePath:               "tor_exit_nodes.cache",
				GlobalRateLimit:             true,
				GlobalRequestRate:           1,
				GlobalRateWindow:            10 * time.Second,
				GlobalBanDuration:           1 * time.Hour,
			},
			Headers: HeadersConfig{
				Enabled:   true,
				TorHeader: "X-Tor-Exit",
				BanHeader: "X-RateLimit-Ban",
			},
			Whitelist: WhitelistConfig{
				IPs: []string{
					"127.0.0.1",
					"::1",
					"10.0.0.0/8",
					"172.16.0.0/12",
					"192.168.0.0/16",
				},
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// LoadConfig loads configuration from a TOML file
func LoadConfig(filename string) (*Config, error) {
	config := DefaultConfig()
	
	if filename == "" {
		return config, nil
	}
	
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return config, nil
	}
	
	if _, err := toml.DecodeFile(filename, config); err != nil {
		return nil, err
	}
	
	return config, nil
}

// SaveConfig saves configuration to a TOML file
func SaveConfig(config *Config, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	return toml.NewEncoder(file).Encode(config)
}