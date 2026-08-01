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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"argo-ebpf/internal/models"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	ctx    context.Context
	client *redis.Client
	ttl    time.Duration
}

func NewRedisStore(ctx context.Context, addr string, ttl time.Duration) *RedisStore {
	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	return new(RedisStore{
		ctx:    ctx,
		client: client,
		ttl:    ttl,
	})
}

func (s *RedisStore) Save(peer *models.Peer) error {
	peerKey := fmt.Sprintf("peer:asn:%d", peer.ASN)

	data, err := json.Marshal(peer)
	if err != nil {
		return err
	}

	// Usiamo una Pipeline per garantire l'atomicità delle operazioni di mapping
	pipe := s.client.Pipeline()
	pipe.Set(s.ctx, peerKey, data, s.ttl)

	for _, mac := range peer.MACs {
		macKey := fmt.Sprintf("peer:mac:%s", mac)
		pipe.Set(s.ctx, macKey, peer.ASN, s.ttl)
	}

	_, err = pipe.Exec(s.ctx)
	return err
}

func (s *RedisStore) RetrieveByMAC(mac string) (*models.Peer, error) {
	macKey := fmt.Sprintf("peer:mac:%s", mac)

	asn, err := s.client.Get(s.ctx, macKey).Int()
	if errors.Is(err, redis.Nil) {
		// Logica UnknownMACs
		s.client.SAdd(s.ctx, "peers:unknown_macs", mac)
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return s.RetrieveByASN(asn)
}

func (s *RedisStore) RetrieveByASN(asn int) (*models.Peer, error) {
	peerKey := fmt.Sprintf("peer:asn:%d", asn)

	data, err := s.client.Get(s.ctx, peerKey).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	var peer models.Peer
	if err := json.Unmarshal(data, &peer); err != nil {
		return nil, err
	}

	return &peer, nil
}

func (s *RedisStore) Update(peer *models.Peer) error {
	peerKey := fmt.Sprintf("peer:asn:%d", peer.ASN)

	data, err := json.Marshal(peer)
	if err != nil {
		return fmt.Errorf("failed to marshal peer for update: %w", err)
	}

	return s.client.Set(s.ctx, peerKey, data, s.ttl).Err()
}
