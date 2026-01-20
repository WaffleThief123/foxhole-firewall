package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cyra/foxhole-fw/internal/config"
	"github.com/cyra/foxhole-fw/internal/firewall"
	"github.com/cyra/foxhole-fw/internal/logging"
	"github.com/cyra/foxhole-fw/internal/parser"
	"github.com/cyra/foxhole-fw/internal/pipeline"
	"github.com/cyra/foxhole-fw/internal/rules"
)

var (
	configPath  = flag.String("config", "/etc/foxhole-fw/config.yaml", "Path to configuration file")
	showVersion = flag.Bool("version", false, "Print version and exit")
	version     = "dev" // Set via ldflags: -X main.version=v1.0.0
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Println("fwld version", version)
		os.Exit(0)
	}

	logger := logging.NewLogger()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger.Infof("foxhole-fw starting (version=%s)", version)
	logger.Infof("config loaded from %s (backend=%s)", *configPath, cfg.Backend.Type)

	// Set up root context with cancellation on SIGINT/SIGTERM.
	ctx, cancel := signalContext()

	store := config.NewStore(cfg)

	watcherStop, err := config.WatchFile(*configPath, store, logger)
	if err != nil {
		logger.Errorf("config watcher disabled: %v", err)
	}

	events := make(chan *parser.Event, 100)
	decisions := make(chan *rules.Decision, 100)

	if pipelineErr := pipeline.StartLogPipeline(ctx, cfg, logger, events); pipelineErr != nil {
		fmt.Fprintf(os.Stderr, "failed to start log pipeline: %v\n", pipelineErr)
		cancel()
		os.Exit(1)
	}

	engine := rules.NewEngine(store, logger)

	backend, backendErr := firewall.NewBackend(cfg, logger)
	if backendErr != nil {
		fmt.Fprintf(os.Stderr, "failed to create firewall backend: %v\n", backendErr)
		cancel()
		os.Exit(1)
	}
	logger.Infof("firewall backend initialized: %s", backend.Name())

	banManager := firewall.NewBanManager(backend, &cfg.Backend, logger)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		engine.Run(ctx, events, decisions)
		close(decisions)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		banManager.Run(ctx, decisions)
	}()

	// Block until shutdown signal.
	<-ctx.Done()
	logger.Info("shutting down...")

	// Close events channel to signal pipeline shutdown.
	close(events)

	// Stop config watcher if running.
	if watcherStop != nil {
		watcherStop()
	}

	// Close rules store to stop GC goroutine.
	engine.Close()

	// Wait for goroutines to finish.
	wg.Wait()
	cancel()
	logger.Info("shutdown complete")
}

// signalContext returns a context that is canceled on SIGINT or SIGTERM.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}
