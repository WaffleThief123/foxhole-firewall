package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cyra/foxhole-fw/internal/config"
	"github.com/cyra/foxhole-fw/internal/logging"
)

// vultrBackend integrates with the Vultr firewall API.
// It creates per-IP rules that block all TCP and UDP ports.
type vultrBackend struct {
	cfg    *config.VultrConfig
	client *http.Client
	logger *logging.Logger

	mu    sync.Mutex
	rules map[string][]string // ip -> []ruleID
}

func NewVultrBackend(cfg *config.VultrConfig, logger *logging.Logger) Backend {
	return &vultrBackend{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		logger: logger,
		rules:  make(map[string][]string),
	}
}

func (b *vultrBackend) Name() string {
	return "vultr"
}

func (b *vultrBackend) Ban(ctx context.Context, ip string, duration time.Duration, reason, ruleID string) error {
	if err := ValidateIP(ip); err != nil {
		return fmt.Errorf("vultr ban: %w", err)
	}

	b.logger.Infof("Vultr backend ban: ip=%s rule=%s for=%s reason=%s (firewall_id=%s)", ip, ruleID, duration, reason, b.cfg.FirewallID)

	ipType, subnetSize := "v4", 32
	if IsIPv6(ip) {
		ipType, subnetSize = "v6", 128
	}

	protocols := []string{"tcp", "udp"}
	var createdIDs []string

	for _, proto := range protocols {
		id, err := b.createRule(ctx, ip, ipType, subnetSize, proto, ruleID)
		if err != nil {
			return err
		}
		if id != "" {
			createdIDs = append(createdIDs, id)
		}
	}

	if len(createdIDs) == 0 {
		return fmt.Errorf("vultr: no rule IDs returned for ip=%s", ip)
	}

	b.mu.Lock()
	b.rules[ip] = append(b.rules[ip], createdIDs...)
	b.mu.Unlock()

	return nil
}

// createRule creates a single firewall rule and returns its ID.
// Response body is properly closed before returning.
func (b *vultrBackend) createRule(ctx context.Context, ip, ipType string, subnetSize int, proto, fwRuleID string) (string, error) {
	type ruleReq struct {
		Direction  string `json:"direction"`
		IPType     string `json:"ip_type"`
		Protocol   string `json:"protocol"`
		Subnet     string `json:"subnet"`
		SubnetSize int    `json:"subnet_size"`
		Port       string `json:"port"`
		Notes      string `json:"notes,omitempty"`
	}

	type ruleResp struct {
		FirewallRule struct {
			ID string `json:"id"`
		} `json:"firewall_rule"`
	}

	body, err := json.Marshal(ruleReq{
		Direction:  "in",
		IPType:     ipType,
		Protocol:   proto,
		Subnet:     ip,
		SubnetSize: subnetSize,
		Port:       "1-65535",
		Notes:      fmt.Sprintf("foxhole-fw:%s", fwRuleID),
	})
	if err != nil {
		return "", fmt.Errorf("vultr: marshal request: %w", err)
	}

	url := fmt.Sprintf("https://api.vultr.com/v2/firewalls/%s/rules", b.cfg.FirewallID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("vultr: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.cfg.APIKey)

	resp, err := b.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vultr: http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("vultr: non-success status %s", resp.Status)
	}

	var rr ruleResp
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return "", fmt.Errorf("vultr: decode response: %w", err)
	}

	return rr.FirewallRule.ID, nil
}

func (b *vultrBackend) Unban(ctx context.Context, ip string) error {
	if err := ValidateIP(ip); err != nil {
		return fmt.Errorf("vultr unban: %w", err)
	}

	b.mu.Lock()
	ids := b.rules[ip]
	delete(b.rules, ip)
	b.mu.Unlock()

	if len(ids) == 0 {
		b.logger.Infof("Vultr backend unban: no rules recorded for ip=%s", ip)
		return nil
	}

	for _, id := range ids {
		url := fmt.Sprintf("https://api.vultr.com/v2/firewalls/%s/rules/%s", b.cfg.FirewallID, id)
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, http.NoBody)
		if err != nil {
			b.logger.Errorf("vultr: build delete request failed for ip=%s id=%s: %v", ip, id, err)
			continue
		}
		req.Header.Set("Authorization", "Bearer "+b.cfg.APIKey)

		resp, err := b.client.Do(req)
		if err != nil {
			b.logger.Errorf("vultr: http delete failed for ip=%s id=%s: %v", ip, id, err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 300 {
			b.logger.Errorf("vultr: delete rule failed for ip=%s id=%s status=%s", ip, id, resp.Status)
			continue
		}
	}

	return nil
}
