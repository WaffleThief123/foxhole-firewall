package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cyra/foxhole-fw/internal/config"
	"github.com/cyra/foxhole-fw/internal/logging"
)

// httpAPIBackend implements Backend by calling a remote HTTP API.
type httpAPIBackend struct {
	url     string
	token   string
	headers map[string]string
	client  *http.Client
	logger  *logging.Logger
}

func NewHTTPAPIBackend(cfg *config.HTTPAPIConfig, logger *logging.Logger) Backend {
	return &httpAPIBackend{
		url:     cfg.URL,
		token:   cfg.AuthToken,
		headers: cfg.Headers,
		client:  &http.Client{Timeout: 10 * time.Second},
		logger:  logger,
	}
}

func (b *httpAPIBackend) Name() string {
	return "http_api"
}

type apiRequest struct {
	Action          string `json:"action"` // "ban" or "unban"
	IP              string `json:"ip"`
	DurationSeconds int64  `json:"duration_seconds,omitempty"`
	Reason          string `json:"reason,omitempty"`
	RuleID          string `json:"rule_id,omitempty"`
}

func (b *httpAPIBackend) Ban(ctx context.Context, ip string, duration time.Duration, reason, ruleID string) error {
	if err := ValidateIP(ip); err != nil {
		return fmt.Errorf("http_api ban: %w", err)
	}
	b.logger.Infof("http_api ban: ip=%s rule=%s reason=%s for=%s", ip, ruleID, reason, duration)
	body := apiRequest{
		Action:          "ban",
		IP:              ip,
		DurationSeconds: int64(duration.Seconds()),
		Reason:          reason,
		RuleID:          ruleID,
	}
	return b.send(ctx, body)
}

func (b *httpAPIBackend) Unban(ctx context.Context, ip string) error {
	if err := ValidateIP(ip); err != nil {
		return fmt.Errorf("http_api unban: %w", err)
	}
	b.logger.Infof("http_api unban: ip=%s", ip)
	body := apiRequest{
		Action: "unban",
		IP:     ip,
	}
	return b.send(ctx, body)
}

func (b *httpAPIBackend) send(ctx context.Context, payload apiRequest) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("http request failed: status=%s", resp.Status)
	}

	return nil
}
