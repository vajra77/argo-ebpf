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
	"argo-ebpf/internal/domain/peer"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisPeerStore struct {
	ctx    context.Context
	client *redis.Client
	ttl    time.Duration
}

func NewRedisPeerStore(ctx context.Context, addr string, ttl time.Duration) *RedisPeerStore {
	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	return new(RedisPeerStore{
		ctx:    ctx,
		client: client,
		ttl:    ttl,
	})
}

func (s *RedisPeerStore) Upsert(p *peer.Peer) error {
	peerKey := fmt.Sprintf("peer:asn:%d", p.ASN())

	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal peer: %w", err)
	}

	pipe := s.client.Pipeline()
	pipe.Set(s.ctx, peerKey, data, s.ttl)

	for _, mac := range p.MACs() {
		macKey := fmt.Sprintf("peer:mac:%s", mac)
		pipe.Set(s.ctx, macKey, p.ASN(), s.ttl)
	}

	_, err = pipe.Exec(s.ctx)
	if err != nil {
		return fmt.Errorf("failed to upsert peer in redis: %w", err)
	}
	return nil
}

func (s *RedisPeerStore) RetrieveByMAC(mac string) (*peer.Peer, error) {
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

func (s *RedisPeerStore) RetrieveByASN(asn int) (*peer.Peer, error) {
	peerKey := fmt.Sprintf("peer:asn:%d", asn)

	data, err := s.client.Get(s.ctx, peerKey).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	var peer peer.Peer
	if err := json.Unmarshal(data, &peer); err != nil {
		return nil, err
	}

	return &peer, nil
}

func (s *RedisPeerStore) Update(peer *peer.Peer) error {
	peerKey := fmt.Sprintf("peer:asn:%d", peer.ASN())

	data, err := json.Marshal(peer)
	if err != nil {
		return fmt.Errorf("failed to marshal peer for update: %w", err)
	}

	return s.client.Set(s.ctx, peerKey, data, s.ttl).Err()
}
