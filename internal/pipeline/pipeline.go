package pipeline

import (
	"context"

	"github.com/cyra/foxhole-fw/internal/config"
	"github.com/cyra/foxhole-fw/internal/logging"
	"github.com/cyra/foxhole-fw/internal/logtail"
	"github.com/cyra/foxhole-fw/internal/parser"
)

// StartLogPipeline wires together the log tailer and parser and emits parsed events on the channel.
// The caller is responsible for closing the events channel when context is canceled.
func StartLogPipeline(ctx context.Context, cfg *config.Config, logger *logging.Logger, events chan<- *parser.Event) error {
	p, err := parser.New(cfg.Log.Parser)
	if err != nil {
		return err
	}

	t := logtail.New(cfg.Log.Path, logger)
	lines := make(chan string, 100)

	go func() {
		// Tail will exit when ctx is canceled.
		_ = t.Tail(ctx, lines)
		close(lines)
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case line, ok := <-lines:
				if !ok {
					return
				}
				ev, err := p.Parse(line)
				if err != nil {
					logger.Errorf("parse error: %v", err)
					continue
				}
				events <- ev
			}
		}
	}()

	return nil
}
