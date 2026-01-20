package config

import (
	"fmt"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Logger defines the logging interface needed by the config watcher.
type Logger interface {
	Infof(string, ...any)
	Errorf(string, ...any)
}

// WatchFile watches a single config file for changes and reloads it into the Store.
// On successful reload, the store is updated; on error, the old config is kept.
// Returns a stop function to cleanly shut down the watcher, or an error if setup fails.
func WatchFile(path string, store *Store, logger Logger) (stop func(), err error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create watcher: %w", err)
	}

	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("watch file: %w", err)
	}

	done := make(chan struct{})

	go func() {
		defer watcher.Close()

		var lastEvent time.Time
		for {
			select {
			case <-done:
				return
			case ev, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Debounce rapid successive events.
				now := time.Now()
				if now.Sub(lastEvent) < 500*time.Millisecond {
					continue
				}
				lastEvent = now

				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
					logger.Infof("config file change detected: %s", ev.Name)
					cfg, err := Load(path)
					if err != nil {
						logger.Errorf("failed to reload config: %v", err)
						continue
					}
					store.Update(cfg)
					logger.Infof("config reloaded successfully")
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Errorf("config watcher error: %v", err)
			}
		}
	}()

	return func() { close(done) }, nil
}
