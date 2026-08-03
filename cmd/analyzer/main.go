/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */
package main

import (
	"argo-ebpf/internal/api"
	"argo-ebpf/internal/domain/peer"
	"argo-ebpf/internal/domain/stats"
	"argo-ebpf/internal/services/ixf"
	"argo-ebpf/internal/services/queries"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"argo-ebpf/internal/infrastructure/ebpf"
	"argo-ebpf/internal/infrastructure/repository"
	"argo-ebpf/internal/services/collector"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		slog.Warn("No .env file found, using system environment variables")
	}

	// Recupero configurazioni da Environment Variables
	iface := getEnv("IFACE", "eth0")
	srvAddr := getEnv("SERVER_ADDR", "localhost:8080")
	logLevel := getEnv("LOG_LEVEL", "info")
	redisAddr := getEnv("REDIS_ADDR", "localhost:6379")
	ixfURL := getEnv("IXF_PROVIDER_URL", "")
	apiKey := getEnv("API_KEY", "")

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
		"api_address", srvAddr,
	)

	// Context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	peerStore := repository.NewRedisPeerStore(ctx, redisAddr, 24*time.Hour)
	statsStore := repository.NewRedisStatsStore(ctx, redisAddr, 15*time.Minute)

	// Mapper control
	mapper := ixf.NewMapper(ixfURL)

	// Cache control
	peerCache := collector.NewPeerCache(mapper, peerStore, logger)
	go func() {
		ticker := time.NewTicker(peer.DefaultTTL)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				logger.Info("Stopping peer cache flusher")
				peerCache.Flush()
				return
			case <-ticker.C:
				// flush cache to redis store
				peerCache.Flush()
			}
		}
	}()

	statsCache := collector.NewStatsCache(statsStore, logger)
	go func() {
		ticker := time.NewTicker(stats.DefaultTimeSlot)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				logger.Info("Stopping stats cache flusher")
				statsCache.Flush()
				return
			case <-ticker.C:
				// flush cache to redis store
				statsCache.Flush()
			}
		}
	}()

	// Event Processor init
	processor := collector.NewEventProcessor(peerCache, statsCache, logger)

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

	// API router and server init
	mux := http.NewServeMux()
	peerQueries := queries.NewPeerQueryService(peerStore)
	peerApi := api.NewPeerAPI(peerQueries, []string{apiKey})
	peerApi.RegisterRoutes(mux, "/api/v1")

	server := new(http.Server{
		Addr:         srvAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	})

	go func() {
		logger.Info("REST API Server running", "address", srvAddr)
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
