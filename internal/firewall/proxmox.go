package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cyra/foxhole-fw/internal/config"
	"github.com/cyra/foxhole-fw/internal/logging"
)

// proxmoxBackend integrates with the Proxmox firewall HTTP API.
// It creates per-IP drop rules on all ports at node or VM level.
type proxmoxBackend struct {
	cfg    *config.ProxmoxConfig
	client *http.Client
	logger *logging.Logger

	mu    sync.Mutex
	rules map[string][]int // ip -> []position
}

func NewProxmoxBackend(cfg *config.ProxmoxConfig, logger *logging.Logger) Backend {
	return &proxmoxBackend{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		logger: logger,
		rules:  make(map[string][]int),
	}
}

func (b *proxmoxBackend) Name() string {
	return "proxmox"
}

func (b *proxmoxBackend) Ban(ctx context.Context, ip string, duration time.Duration, reason, ruleID string) error {
	if err := ValidateIP(ip); err != nil {
		return fmt.Errorf("proxmox ban: %w", err)
	}

	u, err := url.Parse(b.cfg.APIURL)
	if err != nil {
		return fmt.Errorf("proxmox: invalid api_url: %w", err)
	}

	scope := "node"
	if b.cfg.VMID != "" {
		scope = "vm:" + b.cfg.VMID
	}
	b.logger.Infof("Proxmox backend ban: ip=%s rule=%s for=%s reason=%s (scope=%s node=%s)", ip, ruleID, duration, reason, scope, b.cfg.Node)

	var rulesPath string
	if b.cfg.VMID != "" {
		rulesPath = path.Join("nodes", b.cfg.Node, "qemu", b.cfg.VMID, "firewall", "rules")
	} else {
		rulesPath = path.Join("nodes", b.cfg.Node, "firewall", "rules")
	}
	u.Path = path.Join(u.Path, rulesPath)

	// Use /128 for IPv6 addresses, /32 for IPv4.
	subnetSize := "32"
	if IsIPv6(ip) {
		subnetSize = "128"
	}

	form := url.Values{}
	form.Set("type", "in")
	form.Set("action", "drop")
	form.Set("enable", "1")
	form.Set("source", ip+"/"+subnetSize)
	form.Set("comment", fmt.Sprintf("foxhole-fw:%s", ruleID))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("proxmox: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "PVEAPIToken="+b.cfg.TokenID+"="+b.cfg.TokenSecret)

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("proxmox: http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("proxmox: non-success status %s", resp.Status)
	}

	var body struct {
		Data struct {
			Pos int `json:"pos"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		b.logger.Errorf("proxmox: decode response failed (ip=%s): %v", ip, err)
	} else if body.Data.Pos > 0 {
		b.mu.Lock()
		b.rules[ip] = append(b.rules[ip], body.Data.Pos)
		b.mu.Unlock()
	}

	return nil
}

func (b *proxmoxBackend) Unban(ctx context.Context, ip string) error {
	if err := ValidateIP(ip); err != nil {
		return fmt.Errorf("proxmox unban: %w", err)
	}

	uBase, err := url.Parse(b.cfg.APIURL)
	if err != nil {
		return fmt.Errorf("proxmox: invalid api_url: %w", err)
	}

	scope := "node"
	if b.cfg.VMID != "" {
		scope = "vm:" + b.cfg.VMID
	}
	b.logger.Infof("Proxmox backend unban: ip=%s (scope=%s node=%s)", ip, scope, b.cfg.Node)

	b.mu.Lock()
	positions := b.rules[ip]
	delete(b.rules, ip)
	b.mu.Unlock()

	if len(positions) == 0 {
		b.logger.Infof("Proxmox backend unban: no recorded rules for ip=%s", ip)
		return nil
	}

	for _, pos := range positions {
		u := *uBase
		var rulesPath string
		if b.cfg.VMID != "" {
			rulesPath = path.Join("nodes", b.cfg.Node, "qemu", b.cfg.VMID, "firewall", "rules", fmt.Sprintf("%d", pos))
		} else {
			rulesPath = path.Join("nodes", b.cfg.Node, "firewall", "rules", fmt.Sprintf("%d", pos))
		}
		u.Path = path.Join(u.Path, rulesPath)

		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), http.NoBody)
		if err != nil {
			b.logger.Errorf("proxmox: build delete request failed for ip=%s pos=%d: %v", ip, pos, err)
			continue
		}
		req.Header.Set("Authorization", "PVEAPIToken="+b.cfg.TokenID+"="+b.cfg.TokenSecret)

		resp, err := b.client.Do(req)
		if err != nil {
			b.logger.Errorf("proxmox: http delete failed for ip=%s pos=%d: %v", ip, pos, err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 300 {
			b.logger.Errorf("proxmox: delete rule failed for ip=%s pos=%d status=%s", ip, pos, resp.Status)
			continue
		}
	}

	return nil
}
