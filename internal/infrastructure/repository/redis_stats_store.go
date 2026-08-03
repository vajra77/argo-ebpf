/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package repository

import (
	"argo-ebpf/internal/domain/stats"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const statsKey = "stats:all"

type RedisStatsStore struct {
	ctx    context.Context
	client *redis.Client
	ttl    time.Duration
}

func NewRedisStatsStore(ctx context.Context, addr string, ttl time.Duration) *RedisStatsStore {
	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	return new(RedisStatsStore{
		ctx:    ctx,
		client: client,
		ttl:    ttl,
	})
}

func (s *RedisStatsStore) Upsert(st *stats.Stats) error {

	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("failed to marshal stats: %w", err)
	}

	pipe := s.client.Pipeline()
	pipe.Set(s.ctx, statsKey, data, s.ttl)

	_, err = pipe.Exec(s.ctx)
	if err != nil {
		return fmt.Errorf("failed to upsert stats in redis: %w", err)
	}
	return nil
}

func (s *RedisStatsStore) Retrieve() (*stats.Stats, error) {
	data, err := s.client.Get(s.ctx, statsKey).Bytes()
	if err != nil {
		return nil, err
	}

	var jStats stats.Stats
	if err := json.Unmarshal(data, &jStats); err != nil {
		return nil, err
	}

	return new(jStats), nil
}
