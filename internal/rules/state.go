package rules

import (
	"sync"
	"time"

	"github.com/cyra/foxhole-fw/internal/parser"
)

const (
	// DefaultMaxIPs is the default maximum number of unique IPs to track.
	DefaultMaxIPs = 100000

	// DefaultMaxErrorsPerIP is the default maximum errors to track per IP.
	DefaultMaxErrorsPerIP = 1000
)

// ipStats holds per-IP counters over time.
type ipStats struct {
	Errors []time.Time
}

// Store tracks per-IP state with basic GC and memory limits.
type Store struct {
	mu             sync.Mutex
	byIP           map[string]*ipStats
	ttl            time.Duration
	ticker         *time.Ticker
	done           chan struct{}
	maxIPs         int
	maxErrorsPerIP int
}

// NewStore creates a new Store with the given TTL and GC interval.
// Uses default memory limits which can be changed with SetLimits.
func NewStore(ttl, gcInterval time.Duration) *Store {
	s := &Store{
		byIP:           make(map[string]*ipStats),
		ttl:            ttl,
		ticker:         time.NewTicker(gcInterval),
		done:           make(chan struct{}),
		maxIPs:         DefaultMaxIPs,
		maxErrorsPerIP: DefaultMaxErrorsPerIP,
	}
	go s.gcLoop()
	return s
}

// SetLimits configures memory limits. Must be called before use or with mutex held.
func (s *Store) SetLimits(maxIPs, maxErrorsPerIP int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxIPs > 0 {
		s.maxIPs = maxIPs
	}
	if maxErrorsPerIP > 0 {
		s.maxErrorsPerIP = maxErrorsPerIP
	}
}

// Close stops the GC goroutine and releases resources.
func (s *Store) Close() {
	s.ticker.Stop()
	close(s.done)
}

// RecordError records an error-like event (4xx/5xx) for an IP at time t.
// Returns the current error count for the IP, or -1 if the IP limit was reached.
func (s *Store) RecordError(ip string, t time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := t
	stats, ok := s.byIP[ip]
	if !ok {
		// Check if we've hit the max IPs limit.
		if len(s.byIP) >= s.maxIPs {
			// At capacity - don't track new IPs to prevent memory exhaustion.
			return -1
		}
		stats = &ipStats{}
		s.byIP[ip] = stats
	}

	// Drop old entries outside of ttl window.
	cutoff := now.Add(-s.ttl)
	filtered := stats.Errors[:0]
	for _, ts := range stats.Errors {
		if ts.After(cutoff) {
			filtered = append(filtered, ts)
		}
	}
	stats.Errors = filtered

	// Enforce max errors per IP limit.
	if len(stats.Errors) >= s.maxErrorsPerIP {
		// Drop oldest entries to make room.
		excess := len(stats.Errors) - s.maxErrorsPerIP + 1
		stats.Errors = stats.Errors[excess:]
	}

	stats.Errors = append(stats.Errors, now)
	return len(stats.Errors)
}

// ApplyWindow trims old entries for a specific IP based on the given window.
func (s *Store) ApplyWindow(ip string, t time.Time, window time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats, ok := s.byIP[ip]
	if !ok {
		return 0
	}
	cutoff := t.Add(-window)
	filtered := stats.Errors[:0]
	for _, ts := range stats.Errors {
		if ts.After(cutoff) {
			filtered = append(filtered, ts)
		}
	}
	stats.Errors = filtered
	return len(stats.Errors)
}

// gcLoop periodically removes stale IP entries.
func (s *Store) gcLoop() {
	for {
		select {
		case <-s.done:
			return
		case <-s.ticker.C:
			s.gc()
		}
	}
}

func (s *Store) gc() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-s.ttl)

	for ip, stats := range s.byIP {
		filtered := stats.Errors[:0]
		for _, ts := range stats.Errors {
			if ts.After(cutoff) {
				filtered = append(filtered, ts)
			}
		}
		if len(filtered) == 0 {
			delete(s.byIP, ip)
		} else {
			stats.Errors = filtered
		}
	}
}

// Decision represents the outcome of evaluating an event.
type Decision struct {
	IP        string
	RuleID    string
	Violation bool
	Reason    string
	Ban       bool
	BanFor    time.Duration
	Event     *parser.Event
	Timestamp time.Time
}
