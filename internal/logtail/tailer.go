package logtail

import (
	"context"

	"github.com/cyra/foxhole-fw/internal/logging"
	"github.com/hpcloud/tail"
)

// Tailer streams lines from a log file as they are written.
type Tailer struct {
	path   string
	logger *logging.Logger
}

// New creates a new Tailer for the given file path.
func New(path string, logger *logging.Logger) *Tailer {
	return &Tailer{
		path:   path,
		logger: logger,
	}
}

// Tail follows the file and sends each line to the provided channel until ctx is done.
func (t *Tailer) Tail(ctx context.Context, out chan<- string) error {
	cfg := tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: true,
		Poll:      true,
		Logger:    tail.DiscardingLogger,
	}

	tf, err := tail.TailFile(t.path, cfg)
	if err != nil {
		return err
	}

	t.logger.Infof("tailing log file %s", t.path)

	for {
		select {
		case <-ctx.Done():
			_ = tf.Stop()
			tf.Cleanup()
			return ctx.Err()
		case line, ok := <-tf.Lines:
			if !ok {
				return nil
			}
			if line.Err != nil {
				t.logger.Errorf("tail error: %v", line.Err)
				continue
			}
			out <- line.Text
		}
	}
}
