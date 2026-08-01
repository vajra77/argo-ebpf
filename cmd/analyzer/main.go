// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Namex IXP - https://www.namex.it
//
// Author: Francesco Ferreri <f.ferreri@namex.it>
// GitHub: @vajra77
//
// File: main.go
// Description: eBPF tool for IXP broadcast analysis
package main

import (
	"argo-ebpf/internal/models"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"argo-ebpf/internal/api"
	"argo-ebpf/internal/infrastructure/ebpf"
	"argo-ebpf/internal/infrastructure/repository"
	"argo-ebpf/internal/services/alert"
	"argo-ebpf/internal/services/collector"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		slog.Warn("No .env file found, using system environment variables")
	}

	// Recupero configurazioni da Environment Variables
	iface := getEnv("IFACE", "eth0")
	apiAddr := getEnv("API_ADDR", "127.0.0.1:8080")
	logLevel := getEnv("LOG_LEVEL", "info")
	redisAddr := getEnv("REDIS_ADDR", "localhost:6379")

	// Logger init
	var level slog.Level
	switch logLevel {
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
		"interface", iface,
		"api_address", apiAddr,
	)

	// Context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// In-Memory Repository init
	var store models.MetricsRepository
	if redisAddr != "" {
		store = repository.NewRedisStore(redisAddr, "", 0)
	} else {
		store = repository.NewInMemoryStore()
	}

	// Event Processor init
	processor := collector.NewEventProcessor(store, logger)

	// eBPF/XDP loader initialization
	bpfPoller, err := ebpf.NewPoller(iface, processor, logger)
	if err != nil {
		logger.Error("Failed to initialize eBPF loader", "error", err)
		os.Exit(1)
	}
	defer bpfPoller.Close()

	if err := bpfPoller.Start(ctx); err != nil {
		logger.Error("Failed to start eBPF XDP hook", "error", err)
		os.Exit(1)
	}
	logger.Info("eBPF XDP hook attached successfully", "interface", iface)

	// Anomaly Detector Engine (Background Worker)
	anomalyDetector := alert.NewAnomalyDetector(store, alert.DefaultConfig(), logger)
	go anomalyDetector.Start(ctx)

	// API router and server init
	router := api.NewRouter(store)
	server := &http.Server{
		Addr:         apiAddr,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		logger.Info("REST API Server running", "address", apiAddr)
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

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
