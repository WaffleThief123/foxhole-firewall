package config

import "sync/atomic"

// Store holds the current configuration and supports atomic swaps.
type Store struct {
	v atomic.Value // *Config
}

// NewStore creates a Store with the initial configuration.
func NewStore(cfg *Config) *Store {
	s := &Store{}
	s.v.Store(cfg)
	return s
}

// Current returns the current configuration.
func (s *Store) Current() *Config {
	v := s.v.Load()
	if v == nil {
		return nil
	}
	cfg, ok := v.(*Config)
	if !ok {
		return nil
	}
	return cfg
}

// Update replaces the current configuration.
func (s *Store) Update(cfg *Config) {
	s.v.Store(cfg)
}
