package config

import "time"

// Config is the root configuration structure loaded from YAML.
type Config struct {
	Logging LoggingConfig `yaml:"logging"`
	Log     LogConfig     `yaml:"log"`
	Rules   []Rule        `yaml:"rules"`
	Backend BackendConfig `yaml:"backend"`
}

// LoggingConfig controls log verbosity and format.
type LoggingConfig struct {
	Level string `yaml:"level"` // e.g. "info", "debug"
	JSON  bool   `yaml:"json"`
}

// LogConfig describes the webserver log we are tailing.
type LogConfig struct {
	Path   string `yaml:"path"`   // e.g. /var/log/nginx/access.log
	Parser string `yaml:"parser"` // e.g. "nginx_combined"
}

// Rule defines expected request properties and thresholds.
type Rule struct {
	ID          string        `yaml:"id"`
	Description string        `yaml:"description,omitempty"`
	Method      string        `yaml:"method"`       // e.g. GET, POST
	Path        string        `yaml:"path"`         // exact path for MVP
	MaxErrors   int           `yaml:"max_errors"`   // number of 4xx/5xx from same IP
	Window      time.Duration `yaml:"window"`       // rolling window (e.g. "1m")
	BanDuration time.Duration `yaml:"ban_duration"` // how long to ban IP
}

// BackendConfig selects and configures the firewall backend.
type BackendConfig struct {
	Type string `yaml:"type"` // "iptables", "http_api", "vultr", "proxmox"`

	IPTables *IPTablesConfig `yaml:"iptables,omitempty"`
	HTTP     *HTTPAPIConfig  `yaml:"http_api,omitempty"`
	Vultr    *VultrConfig    `yaml:"vultr,omitempty"`
	Proxmox  *ProxmoxConfig  `yaml:"proxmox,omitempty"`

	// Global behavior flags.
	DryRun    bool     `yaml:"dry_run,omitempty"`   // if true, do not actually ban/unban, just log
	Whitelist []string `yaml:"whitelist,omitempty"` // CIDR or IPs never to ban
}

// IPTablesConfig controls iptables backend behavior.
type IPTablesConfig struct {
	Table string `yaml:"table"` // e.g. "filter"
	Chain string `yaml:"chain"` // e.g. "INPUT"
}

// HTTPAPIConfig controls the generic HTTP firewall API backend.
type HTTPAPIConfig struct {
	URL       string            `yaml:"url"`
	AuthToken string            `yaml:"auth_token,omitempty"`
	Headers   map[string]string `yaml:"headers,omitempty"`
}

// VultrConfig configures the Vultr firewall backend.
type VultrConfig struct {
	APIKey     string `yaml:"api_key"`
	FirewallID string `yaml:"firewall_id"` // firewall group ID
}

// ProxmoxConfig configures the Proxmox firewall backend.
type ProxmoxConfig struct {
	APIURL      string `yaml:"api_url"` // e.g. https://proxmox.local:8006/api2/json
	TokenID     string `yaml:"token_id"`
	TokenSecret string `yaml:"token_secret"`
	Node        string `yaml:"node"`
	VMID        string `yaml:"vmid"` // optional; if empty, apply at node level
}
