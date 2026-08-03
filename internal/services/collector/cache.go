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
	"argo-ebpf/internal/domain/peer"
	"argo-ebpf/internal/services/ixf"
	"log/slog"
	"sync"
)

const MaxStoreWorkers = 10

type PeerCache struct {
	mapper      *ixf.Mapper
	repo        peer.Repository
	macEntries  map[string]*peer.Peer
	uniquePeers map[int]*peer.Peer
	unknownMACs map[string]uint64
	storeC      chan *peer.Peer

	wg sync.WaitGroup
	mu sync.Mutex
}

func NewPeerCache(mapper *ixf.Mapper, repo peer.Repository) *PeerCache {
	c := new(PeerCache{
		mapper:      mapper,
		repo:        repo,
		macEntries:  make(map[string]*peer.Peer),
		uniquePeers: make(map[int]*peer.Peer),
		unknownMACs: make(map[string]uint64),
		storeC:      make(chan *peer.Peer, 1000),
	})

	for i := 0; i < MaxStoreWorkers; i++ {
		c.wg.Go(func() {
			for snapshot := range c.storeC {
				if err := c.repo.Upsert(snapshot); err != nil {
					slog.Warn("unable to store peer", "error", err, "name", snapshot.Name())
				}
			}
		})
	}

	return c
}

func (c *PeerCache) Close() {
	close(c.storeC)
	c.wg.Wait()
}

func (c *PeerCache) GetOrSet(srcMac string) *peer.Peer {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.macEntries[srcMac]; ok {
		entry.UpdateLastSeen()
		return entry
	}

	info := c.mapper.RetrieveByMAC(srcMac)
	if info == nil {
		c.unknownMACs[srcMac]++
		return nil
	}

	if existing, ok := c.uniquePeers[info.ASN]; ok {
		existing.RegisterMAC(srcMac)
		c.macEntries[srcMac] = existing
		return existing
	}

	newPeer := peer.New(info.Name, info.ASN, info.GetMACs())
	for _, mac := range newPeer.MACs() {
		c.macEntries[mac] = newPeer
	}
	c.uniquePeers[newPeer.ASN()] = newPeer
	return newPeer
}

func (c *PeerCache) Flush() {
	c.mu.Lock()

	uMacs := make([]string, 0)
	var totPkts uint64 = 0
	for k, v := range c.unknownMACs {
		uMacs = append(uMacs, k)
		totPkts += v
	}
	clear(c.unknownMACs)

	for _, p := range c.uniquePeers {
		if p.IsStale() {
			continue
		}
		snapshot := peer.AcquireSnapshot()
		p.DrainTo(snapshot)
		c.storeC <- snapshot
	}

	c.mu.Unlock()

	if len(uMacs) > 0 {
		// save other data under peer ASN 0
		unkPeer := peer.New("Unknown", 0, uMacs)
		unkPeer.UpdateTotalPackets(totPkts)
		if err := c.repo.Upsert(unkPeer); err != nil {
			slog.Warn("unable to store peer", "error", err, "name", unkPeer.Name())
		}
	}
}
