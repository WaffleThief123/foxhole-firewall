package firewall

import (
	"context"
	"sync"
	"time"

	"github.com/cyra/foxhole-fw/internal/config"
	"github.com/cyra/foxhole-fw/internal/logging"
	"github.com/cyra/foxhole-fw/internal/rules"
)

// banInfo tracks a single active ban.
type banInfo struct {
	ExpiresAt time.Time
	RuleID    string
}

// BanManager consumes decisions and applies bans/unbans via a Backend.
type BanManager struct {
	backend   Backend
	logger    *logging.Logger
	dryRun    bool
	whitelist *whitelistMatcher

	mu   sync.Mutex
	bans map[string]banInfo // ip -> banInfo
}

// NewBanManager creates a new BanManager.
func NewBanManager(backend Backend, backendCfg *config.BackendConfig, logger *logging.Logger) *BanManager {
	return &BanManager{
		backend:   backend,
		logger:    logger,
		dryRun:    backendCfg.DryRun,
		whitelist: newWhitelistMatcher(backendCfg),
		bans:      make(map[string]banInfo),
	}
}

// Run starts processing decisions until ctx is done.
func (m *BanManager) Run(ctx context.Context, decisions <-chan *rules.Decision) {
	for {
		select {
		case <-ctx.Done():
			m.logger.Infof("ban manager shutting down (backend=%s)", m.backend.Name())
			return
		case d := <-decisions:
			if d == nil {
				continue
			}
			if !d.Ban || !d.Violation {
				continue
			}
			m.handleDecision(ctx, d)
		}
	}
}

func (m *BanManager) handleDecision(ctx context.Context, d *rules.Decision) {
	if m.whitelist.Contains(d.IP) {
		m.logger.Infof("ban skipped (whitelisted ip): ip=%s rule=%s backend=%s", d.IP, d.RuleID, m.backend.Name())
		return
	}

	m.mu.Lock()
	existing, ok := m.bans[d.IP]
	if ok && existing.ExpiresAt.After(time.Now()) {
		// Already banned and not yet expired; skip duplicate.
		m.logger.Infof("ban skipped (already active): ip=%s rule=%s backend=%s", d.IP, existing.RuleID, m.backend.Name())
		m.mu.Unlock()
		return
	}
	expiry := time.Now().Add(d.BanFor)
	m.bans[d.IP] = banInfo{
		ExpiresAt: expiry,
		RuleID:    d.RuleID,
	}
	m.mu.Unlock()

	if m.dryRun {
		m.logger.Infof("DRY-RUN ban: ip=%s rule=%s backend=%s until=%s", d.IP, d.RuleID, m.backend.Name(), expiry.Format(time.RFC3339))
		return
	}

	// Apply ban via backend.
	if err := m.backend.Ban(ctx, d.IP, d.BanFor, d.Reason, d.RuleID); err != nil {
		m.logger.Errorf("failed to apply ban: ip=%s rule=%s backend=%s err=%v", d.IP, d.RuleID, m.backend.Name(), err)
		return
	}

	m.logger.Infof("ban applied: ip=%s rule=%s backend=%s until=%s", d.IP, d.RuleID, m.backend.Name(), expiry.Format(time.RFC3339))

	// Schedule unban if duration is positive.
	if d.BanFor > 0 {
		go m.scheduleUnban(ctx, d.IP, expiry)
	}
}

func (m *BanManager) scheduleUnban(ctx context.Context, ip string, expiry time.Time) {
	delay := time.Until(expiry)
	if delay <= 0 {
		delay = time.Second
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	if err := m.backend.Unban(ctx, ip); err != nil {
		m.logger.Errorf("failed to unban ip=%s backend=%s err=%v", ip, m.backend.Name(), err)
		return
	}

	m.mu.Lock()
	delete(m.bans, ip)
	m.mu.Unlock()

	m.logger.Infof("unbanned ip=%s backend=%s", ip, m.backend.Name())
}
