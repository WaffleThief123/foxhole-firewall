package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/cyra/foxhole-fw/internal/config"
	"github.com/cyra/foxhole-fw/internal/logging"
)

// iptablesBackend implements Backend using the local iptables binary.
type iptablesBackend struct {
	table  string
	chain  string
	logger *logging.Logger
}

func NewIPTablesBackend(cfg *config.IPTablesConfig, logger *logging.Logger) Backend {
	return &iptablesBackend{
		table:  cfg.Table,
		chain:  cfg.Chain,
		logger: logger,
	}
}

func (b *iptablesBackend) Name() string {
	return "iptables"
}

func (b *iptablesBackend) Ban(ctx context.Context, ip string, duration time.Duration, reason, ruleID string) error {
	if err := ValidateIP(ip); err != nil {
		return fmt.Errorf("iptables ban: %w", err)
	}

	// Use ip6tables for IPv6 addresses.
	iptablesCmd := "iptables"
	if IsIPv6(ip) {
		iptablesCmd = "ip6tables"
	}

	args := []string{"-t", b.table, "-I", b.chain, "1", "-s", ip, "-j", "DROP"}
	b.logger.Infof("%s ban: ip=%s table=%s chain=%s rule=%s reason=%s for=%s", iptablesCmd, ip, b.table, b.chain, ruleID, reason, duration)
	cmd := exec.CommandContext(ctx, iptablesCmd, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s ban failed: %w (output=%s)", iptablesCmd, err, string(output))
	}
	return nil
}

func (b *iptablesBackend) Unban(ctx context.Context, ip string) error {
	if err := ValidateIP(ip); err != nil {
		return fmt.Errorf("iptables unban: %w", err)
	}

	// Use ip6tables for IPv6 addresses.
	iptablesCmd := "iptables"
	if IsIPv6(ip) {
		iptablesCmd = "ip6tables"
	}

	args := []string{"-t", b.table, "-D", b.chain, "-s", ip, "-j", "DROP"}
	b.logger.Infof("%s unban: ip=%s table=%s chain=%s", iptablesCmd, ip, b.table, b.chain)
	cmd := exec.CommandContext(ctx, iptablesCmd, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s unban failed: %w (output=%s)", iptablesCmd, err, string(output))
	}
	return nil
}
