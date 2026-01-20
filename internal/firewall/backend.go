package firewall

import (
	"context"
	"fmt"
	"time"

	"github.com/cyra/foxhole-fw/internal/config"
	"github.com/cyra/foxhole-fw/internal/logging"
)

// Backend is the interface implemented by firewall backends.
type Backend interface {
	// Ban should install a rule that blocks the given IP.
	Ban(ctx context.Context, ip string, duration time.Duration, reason, ruleID string) error
	// Unban should remove any rule previously created for the given IP, if supported.
	Unban(ctx context.Context, ip string) error
	// Name returns a short identifier for logging.
	Name() string
}

// NewBackend constructs a Backend from configuration.
func NewBackend(cfg *config.Config, logger *logging.Logger) (Backend, error) {
	switch cfg.Backend.Type {
	case "iptables":
		return NewIPTablesBackend(cfg.Backend.IPTables, logger), nil
	case "http_api":
		return NewHTTPAPIBackend(cfg.Backend.HTTP, logger), nil
	case "vultr":
		return NewVultrBackend(cfg.Backend.Vultr, logger), nil
	case "proxmox":
		return NewProxmoxBackend(cfg.Backend.Proxmox, logger), nil
	default:
		return nil, fmt.Errorf("unsupported backend.type %q", cfg.Backend.Type)
	}
}
