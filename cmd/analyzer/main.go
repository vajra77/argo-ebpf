package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"argo-ebpf/internal/infrastructure/ebpf"
	"argo-ebpf/internal/infrastructure/repository"
	"argo-ebpf/internal/presentation"
	"argo-ebpf/internal/service/alert"
	"argo-ebpf/internal/service/collector"
)

func main() {
	// command line flags
	iface := flag.String("iface", "eth0", "Interfaccia di rete da monitorare (es. eth0, bond0)")
	apiAddr := flag.String("api-addr", ":8080", "Indirizzo di ascolto per le API REST Retool")
	logLevel := flag.String("log-level", "info", "Livello di log (debug, info, warn, error)")
	flag.Parse()

	// Logger init
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	logger.Info("👁️ Starting argo-ebpf Sentinel...",
		"interface", *iface,
		"api_address", *apiAddr,
	)

	// Context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// In-Memory Repository init
	memStore := repository.NewInMemoryStore()

	// Event Processor init
	processor := collector.NewEventProcessor(memStore, logger)

	// eBPF/XDP loader initialization
	bpfLoader, err := ebpf.NewLoader(*iface, processor, logger)
	if err != nil {
		logger.Error("Failed to initialize eBPF loader", "error", err)
		os.Exit(1)
	}
	defer bpfLoader.Close()

	if err := bpfLoader.Start(ctx); err != nil {
		logger.Error("Failed to start eBPF XDP hook", "error", err)
		os.Exit(1)
	}
	logger.Info("eBPF XDP hook attached successfully", "interface", *iface)

	// Anomaly Detector Engine (Background Worker)
	anomalyDetector := alert.NewAnomalyDetector(memStore, alert.DefaultConfig(), logger)
	go anomalyDetector.Start(ctx)

	// API router and server init
	router := presentation.NewRouter(memStore)
	server := &http.Server{
		Addr:         *apiAddr,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		logger.Info("REST API Server running", "address", *apiAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP API Server failure", "error", err)
			stop()
		}
	}()

	// Waiting for SIGINT/SIGTERM
	<-ctx.Done()
	logger.Info("Shutdown signal received, starting graceful teardown...")

	// Context with timeout to gracefully shutdown HTTP server and eBPF
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP Server forced shutdown error", "error", err)
	}

	logger.Info("argo-ebpf stopped cleanly. Goodbye!")
}
