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
	// 1. Parsing dei flag da linea di comando
	iface := flag.String("iface", "eth0", "Interfaccia di rete da monitorare (es. eth0, bond0)")
	apiAddr := flag.String("api-addr", ":8080", "Indirizzo di ascolto per le API REST Retool")
	logLevel := flag.String("log-level", "info", "Livello di log (debug, info, warn, error)")
	flag.Parse()

	// 2. Inizializzazione Logger Strutturato (slog)
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

	// 3. Gestione del Context per lo Shutdown Pulito
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 4. Inizializzazione Repository In-Memory (Domain Storage)
	memStore := repository.NewInMemoryStore()

	// 5. Inizializzazione Event Processor (Service Layer)
	processor := collector.NewEventProcessor(memStore, logger)

	// 6. Inizializzazione e Avvio Loader eBPF / XDP (Infrastructure Layer)
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

	// 7. Avvio Anomaly Detector Engine (Background Worker)
	anomalyDetector := alert.NewAnomalyDetector(memStore, alert.DefaultConfig(), logger)
	go anomalyDetector.Start(ctx)

	// 8. Inizializzazione Router e Server HTTP REST per Retool (Presentation Layer)
	router := presentation.NewRouter(memStore)
	server := &http.Server{
		Addr:         *apiAddr,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		logger.Info("REST API Server running for Retool integration", "address", *apiAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP API Server failure", "error", err)
			stop()
		}
	}()

	// 9. Attesa del segnale di terminazione (SIGINT / SIGTERM)
	<-ctx.Done()
	logger.Info("Shutdown signal received, starting graceful teardown...")

	// Context con timeout per chiudere il server HTTP ed staccare eBPF pulitamente
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP Server forced shutdown error", "error", err)
	}

	logger.Info("argo-ebpf stopped cleanly. Goodbye!")
}
