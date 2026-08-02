/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package peer

import (
	"encoding/json"
	"slices"
	"sync"
	"time"
)

type Peer struct {
	name         string
	asn          int
	macs         []string
	totalPackets uint64
	arps         map[string]*ARPRequest
	alerts       map[string]*Alert
	lastSeen     time.Time

	mu sync.RWMutex
}

func New(name string, asn int, macs []string) *Peer {
	return new(Peer{
		name:         name,
		asn:          asn,
		macs:         macs,
		totalPackets: 0,
		arps:         make(map[string]*ARPRequest),
		alerts:       make(map[string]*Alert),
		lastSeen:     time.Now(),
	})
}

func (p *Peer) MarshalJSON() ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return json.Marshal(&struct {
		Name         string                 `json:"name"`
		ASN          int                    `json:"asn"`
		MACs         []string               `json:"macs"`
		TotalPackets uint64                 `json:"total_packets"`
		AveragePPS   float64                `json:"average_pps"`
		ARPs         map[string]*ARPRequest `json:"arps"`
		Alerts       map[string]*Alert      `json:"alerts"`
		LastSeen     time.Time              `json:"last_seen"`
	}{
		Name:         p.name,
		ASN:          p.asn,
		MACs:         p.macs,
		TotalPackets: p.totalPackets,
		AveragePPS:   p.AveragePPS(),
		ARPs:         p.arps,
		Alerts:       p.alerts,
		LastSeen:     p.lastSeen,
	})
}

func (p *Peer) UnmarshalJSON(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	aux := &struct {
		Name         string                 `json:"name"`
		ASN          int                    `json:"asn"`
		MACs         []string               `json:"macs"`
		TotalPackets uint64                 `json:"total_packets"`
		ARPs         map[string]*ARPRequest `json:"arps"`
		Alerts       map[string]*Alert      `json:"alerts"`
		LastSeen     time.Time              `json:"last_seen"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	p.name = aux.Name
	p.asn = aux.ASN
	p.macs = aux.MACs
	p.totalPackets = aux.TotalPackets
	p.arps = aux.ARPs
	p.alerts = aux.Alerts
	p.lastSeen = aux.LastSeen

	return nil
}

func (p *Peer) Name() string {
	return p.name
}

func (p *Peer) ASN() int {
	return p.asn
}

func (p *Peer) MACs() []string {
	return p.macs
}

func (p *Peer) TotalPackets() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.totalPackets
}

func (p *Peer) AveragePPS() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return float64(p.totalPackets) / DefaultTTL().Seconds()
}

func (p *Peer) Alerts() []*Alert {
	p.mu.RLock()
	defer p.mu.RUnlock()

	alerts := make([]*Alert, 0)
	for _, v := range p.alerts {
		alerts = append(alerts, v)
	}
	return alerts
}

func (p *Peer) ARPs() []*ARPRequest {
	p.mu.RLock()
	defer p.mu.RUnlock()

	arpRequests := make([]*ARPRequest, 0)
	for _, v := range p.arps {
		arpRequests = append(arpRequests, v)
	}
	return arpRequests
}

func (p *Peer) LastSeen() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.lastSeen
}

func (p *Peer) RegisterMAC(mac string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !slices.Contains(p.macs, mac) {
		p.macs = append(p.macs, mac)
	}
}

func (p *Peer) RegisterAlert(id, srcMAC, srcIP string, alertType AlertType, severity Severity, act string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if alert, ok := p.alerts[id]; !ok {
		p.alerts[id] = NewAlert(id, srcMAC, srcIP, alertType, severity, act)
	} else {
		alert.Update()
	}
	p.lastSeen = time.Now()
	p.totalPackets++
}

func (p *Peer) RegisterARPRequest(id, srcMAC, targetIP string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if arp, ok := p.arps[id]; ok {
		arp.Update()
	} else {
		newArp := NewARPRequest(id, srcMAC, targetIP)
		p.arps[id] = newArp
	}
	p.lastSeen = time.Now()
	p.totalPackets++
}

func (p *Peer) UpdateTotalPackets(packets uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.totalPackets += packets
}

func (p *Peer) UpdateLastSeen() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.lastSeen = time.Now()
}

func (p *Peer) IsStale() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return time.Since(p.lastSeen) > DefaultTTL()
}

func (p *Peer) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.totalPackets = 0
	p.arps = make(map[string]*ARPRequest)
	p.alerts = make(map[string]*Alert)
}

func DefaultTTL() time.Duration {
	return 15 * time.Minute
}
