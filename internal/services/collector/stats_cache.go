/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package collector

import (
	"argo-ebpf/internal/domain/stats"
	"log/slog"
	"sync"
)

type StatsCache struct {
	stats  *stats.Stats
	repo   stats.Repository
	storeC chan *stats.Stats

	logger *slog.Logger
	mu     sync.Mutex
}

func NewStatsCache(repo stats.Repository, logger *slog.Logger) *StatsCache {
	c := new(StatsCache{
		stats:  stats.New(),
		repo:   repo,
		logger: logger,
		storeC: make(chan *stats.Stats, 100),
	})

	go func() {
		for snapshot := range c.storeC {
			if err := c.repo.Upsert(snapshot); err != nil {
				c.logger.Warn("unable to store stats", "error", err)
			}
			snapshot.Release()
		}
	}()

	return c
}

func (c *StatsCache) Close() {
	close(c.storeC)
}

func (c *StatsCache) Set(srcMac string, protoType uint16, packets uint64, bytes uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.Update(srcMac, protoType, packets, bytes)
}

func (c *StatsCache) Flush() {
	c.mu.Lock()
	snapshot := stats.AcquireSnapshot()
	c.stats.DrainTo(snapshot)
	c.storeC <- snapshot
	c.mu.Unlock()
}
