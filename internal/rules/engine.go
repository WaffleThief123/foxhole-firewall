package rules

import (
	"context"
	"time"

	"github.com/cyra/foxhole-fw/internal/config"
	"github.com/cyra/foxhole-fw/internal/logging"
	"github.com/cyra/foxhole-fw/internal/parser"
)

// Engine evaluates events against configured rules and emits decisions.
type Engine struct {
	cfgStore *config.Store
	store    *Store
	logger   *logging.Logger
}

// NewEngine creates a new Engine backed by a config.Store.
func NewEngine(cfgStore *config.Store, logger *logging.Logger) *Engine {
	cfg := cfgStore.Current()
	// TTL for the store: max window across rules, or 5m by default.
	var maxWindow time.Duration
	for _, r := range cfg.Rules {
		if r.Window > maxWindow {
			maxWindow = r.Window
		}
	}
	if maxWindow == 0 {
		maxWindow = 5 * time.Minute
	}
	store := NewStore(maxWindow, time.Minute)
	return &Engine{
		cfgStore: cfgStore,
		store:    store,
		logger:   logger,
	}
}

// Run starts consuming events and emitting decisions until ctx is canceled or events channel closes.
func (e *Engine) Run(ctx context.Context, events <-chan *parser.Event, decisions chan<- *Decision) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			e.processEvent(ev, decisions)
		}
	}
}

func (e *Engine) processEvent(ev *parser.Event, decisions chan<- *Decision) {
	cfg := e.cfgStore.Current()
	evalTime := ev.Timestamp
	if evalTime.IsZero() {
		evalTime = time.Now()
	}

	// For MVP: treat 4xx/5xx as errors and count them per-IP.
	if ev.Status >= 400 {
		_ = e.store.RecordError(ev.RemoteAddr, evalTime)
	}

	for _, r := range cfg.Rules {
		if !matchRule(&r, ev) {
			continue
		}

		count := e.store.ApplyWindow(ev.RemoteAddr, evalTime, r.Window)
		if count >= r.MaxErrors {
			dec := &Decision{
				IP:        ev.RemoteAddr,
				RuleID:    r.ID,
				Violation: true,
				Reason:    "max_errors exceeded",
				Ban:       true,
				BanFor:    r.BanDuration,
				Event:     ev,
				Timestamp: evalTime,
			}
			decisions <- dec
			e.logger.Infof("violation: ip=%s rule=%s count=%d", dec.IP, dec.RuleID, count)
		}
	}
}

// Close stops the engine's internal store GC goroutine.
func (e *Engine) Close() {
	e.store.Close()
}

func matchRule(r *config.Rule, ev *parser.Event) bool {
	if r.Method != "" && ev.Method != r.Method {
		return false
	}
	if r.Path != "" && ev.Path != r.Path {
		return false
	}
	return true
}
