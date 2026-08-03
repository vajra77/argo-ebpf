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
	"sync"
)

type PeerCache struct {
	mapper      *ixf.Mapper
	repo        peer.Repository
	macEntries  map[string]*peer.Peer
	uniquePeers map[int]*peer.Peer
	unknownMACs map[string]uint64
	storeChan   chan peer.Peer

	mu sync.Mutex
}

func NewPeerCache(mapper *ixf.Mapper, repo peer.Repository) *PeerCache {
	return new(PeerCache{
		mapper:      mapper,
		repo:        repo,
		macEntries:  make(map[string]*peer.Peer),
		uniquePeers: make(map[int]*peer.Peer),
		unknownMACs: make(map[string]uint64),
		storeChan:   make(chan peer.Peer, 1000),
	})
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

func (c *PeerCache) Flush() []error {
	flushErrors := make([]error, 0)

	c.mu.Lock()
	for _, p := range c.uniquePeers {
		c.snapshot = append(c.snapshot, p.Clone())
		p.Reset()
	}
	c.unknownMACs = make(map[string]uint64)
	c.mu.Unlock()

	if err := c.mapper.Refresh(); err != nil {
		flushErrors = append(flushErrors, err)
	}

	for _, p := range c.snapshot {
		if !p.IsStale() {
			continue
		}
		if err := c.repo.Upsert(&p); err != nil {
			flushErrors = append(flushErrors, err)
		}
	}

	// save other data under peer ASN 0
	uMacs := make([]string, 0)
	var totPkts uint64 = 0
	for k, v := range c.unknownMACs {
		uMacs = append(uMacs, k)
		totPkts += v
	}
	unkPeer := peer.New("Unknown", 0, uMacs)
	unkPeer.UpdateTotalPackets(totPkts)
	if err := c.repo.Upsert(unkPeer); err != nil {
		flushErrors = append(flushErrors, err)
	}

	return flushErrors
}

func (c *PeerCache) storeWorker() {
	for p := range c.storeChan {
		if err := c.repo.Upsert(new(p)); err != nil {
			// Log dell'errore (usa slog se disponibile nel contesto)
		}
	}
	for _, p := range c.snapshot {
		if !p.IsStale() {
			continue
		}
		if err := c.repo.Upsert(&p); err != nil {
			flushErrors = append(flushErrors, err)
		}
	}
}
