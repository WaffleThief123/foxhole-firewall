package firewall

import (
	"fmt"
	"net"

	"github.com/cyra/foxhole-fw/internal/config"
)

// ValidateIP checks if the given string is a valid IPv4 or IPv6 address.
// Returns an error if the IP is invalid or empty.
func ValidateIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("empty IP address")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}
	return nil
}

// IsIPv6 returns true if the given IP string is a valid IPv6 address.
func IsIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() == nil
}

// whitelistMatcher checks if an IP is in a configured whitelist.
type whitelistMatcher struct {
	nets []*net.IPNet
	ips  map[string]struct{}
}

func newWhitelistMatcher(cfg *config.BackendConfig) *whitelistMatcher {
	m := &whitelistMatcher{
		ips: make(map[string]struct{}),
	}
	for _, entry := range cfg.Whitelist {
		if ip := net.ParseIP(entry); ip != nil {
			m.ips[ip.String()] = struct{}{}
			continue
		}
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			m.nets = append(m.nets, cidr)
		}
	}
	return m
}

func (m *whitelistMatcher) Contains(ipStr string) bool {
	if m == nil {
		return false
	}
	if _, ok := m.ips[ipStr]; ok {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range m.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
