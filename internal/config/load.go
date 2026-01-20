package config

import (
	"fmt"
	"os"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Load reads, parses, and validates configuration from the provided path.
// Warns if the config file has insecure permissions (world-readable).
func Load(path string) (*Config, error) {
	// Check file permissions (Unix only).
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err == nil {
			mode := info.Mode().Perm()
			// Warn if file is world-readable (contains API keys).
			if mode&0o004 != 0 {
				fmt.Fprintf(os.Stderr, "WARNING: config file %s is world-readable (mode %o). Consider: chmod 600 %s\n", path, mode, path)
			}
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

func validate(c *Config) error {
	if c.Log.Path == "" {
		return fmt.Errorf("log.path is required")
	}

	if c.Log.Parser == "" {
		c.Log.Parser = "nginx_combined"
	}

	if c.Backend.Type == "" {
		return fmt.Errorf("backend.type is required")
	}

	switch c.Backend.Type {
	case "iptables":
		if c.Backend.IPTables == nil {
			return fmt.Errorf("backend.iptables must be set when backend.type=iptables")
		}
		if c.Backend.IPTables.Table == "" || c.Backend.IPTables.Chain == "" {
			return fmt.Errorf("backend.iptables.table and backend.iptables.chain are required")
		}
	case "http_api":
		if c.Backend.HTTP == nil {
			return fmt.Errorf("backend.http_api must be set when backend.type=http_api")
		}
		if c.Backend.HTTP.URL == "" {
			return fmt.Errorf("backend.http_api.url is required")
		}
	case "vultr":
		if c.Backend.Vultr == nil {
			return fmt.Errorf("backend.vultr must be set when backend.type=vultr")
		}
		if c.Backend.Vultr.APIKey == "" || c.Backend.Vultr.FirewallID == "" {
			return fmt.Errorf("backend.vultr.api_key and backend.vultr.firewall_id are required")
		}
	case "proxmox":
		if c.Backend.Proxmox == nil {
			return fmt.Errorf("backend.proxmox must be set when backend.type=proxmox")
		}
		if c.Backend.Proxmox.APIURL == "" || c.Backend.Proxmox.Node == "" {
			return fmt.Errorf("backend.proxmox.api_url and backend.proxmox.node are required")
		}
	default:
		return fmt.Errorf("unsupported backend.type %q", c.Backend.Type)
	}

	if len(c.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}

	for i := range c.Rules {
		r := &c.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("rule at index %d is missing id", i)
		}
		if r.Method == "" {
			return fmt.Errorf("rule %q: method is required", r.ID)
		}
		if r.Path == "" {
			return fmt.Errorf("rule %q: path is required", r.ID)
		}
		if r.MaxErrors <= 0 {
			return fmt.Errorf("rule %q: max_errors must be > 0", r.ID)
		}
		if r.Window <= 0 {
			return fmt.Errorf("rule %q: window must be > 0", r.ID)
		}
		if r.BanDuration <= 0 {
			return fmt.Errorf("rule %q: ban_duration must be > 0", r.ID)
		}
	}

	// Default logging level if not provided.
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}

	return nil
}
