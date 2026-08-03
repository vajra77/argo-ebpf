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

const DefaultTTL = 15 * time.Minute

// Peer object collects all arps and alerts about a single peer
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

// New creates a new Peer object
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

// MarshalJSON marshals a Peer object to JSON
func (p *Peer) MarshalJSON() ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return json.Marshal(&struct {
		Name         string       `json:"name"`
		ASN          int          `json:"asn"`
		MACs         []string     `json:"macs"`
		TotalPackets uint64       `json:"total_packets"`
		AveragePPS   float64      `json:"average_pps"`
		ARPs         []ARPRequest `json:"arps"`
		Alerts       []Alert      `json:"alerts"`
		LastSeen     time.Time    `json:"last_seen"`
	}{
		Name:         p.name,
		ASN:          p.asn,
		MACs:         p.macs,
		TotalPackets: p.totalPackets,
		AveragePPS:   float64(p.totalPackets) / DefaultTTL.Seconds(),
		ARPs:         p.arpsUnlocked(),
		Alerts:       p.alertsUnlocked(),
		LastSeen:     p.lastSeen,
	})
}

// UnmarshalJSON unmarshals a Peer object from JSON
func (p *Peer) UnmarshalJSON(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	aux := &struct {
		Name         string       `json:"name"`
		ASN          int          `json:"asn"`
		MACs         []string     `json:"macs"`
		TotalPackets uint64       `json:"total_packets"`
		ARPs         []ARPRequest `json:"arps"`
		Alerts       []Alert      `json:"alerts"`
		LastSeen     time.Time    `json:"last_seen"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	p.name = aux.Name
	p.asn = aux.ASN
	p.macs = aux.MACs
	p.totalPackets = aux.TotalPackets
	p.lastSeen = aux.LastSeen

	p.arps = make(map[string]*ARPRequest, len(aux.ARPs))
	for _, arp := range aux.ARPs {
		a := arp
		p.arps[arp.id] = new(a)
	}

	p.alerts = make(map[string]*Alert, len(aux.Alerts))
	for _, alr := range aux.Alerts {
		a := alr
		p.alerts[alr.id] = new(a)
	}

	return nil
}

// Getters

func (p *Peer) Name() string {

	return p.name
}

func (p *Peer) ASN() int {
	return p.asn
}

func (p *Peer) MACs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

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

	return float64(p.totalPackets) / DefaultTTL.Seconds()
}

// LastSeen returns the last time a Peer object was seen
func (p *Peer) LastSeen() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.lastSeen
}

// Alerts returns the alerts of a Peer object (as a slice)
func (p *Peer) Alerts() []Alert {
	p.mu.RLock()
	defer p.mu.RUnlock()

	alerts := make([]Alert, 0)
	for _, v := range p.alerts {
		alerts = append(alerts, *v)
	}
	return alerts
}

// alertsUnlocked returns the alerts of a Peer object without locking the mutex
func (p *Peer) alertsUnlocked() []Alert {
	alerts := make([]Alert, 0, len(p.alerts))
	for _, v := range p.alerts {
		alerts = append(alerts, *v)
	}
	return alerts
}

// ARPs returns the ARP requests of a Peer object (as a slice)
func (p *Peer) ARPs() []ARPRequest {
	p.mu.RLock()
	defer p.mu.RUnlock()

	arpRequests := make([]ARPRequest, 0)
	for _, v := range p.arps {
		arpRequests = append(arpRequests, *v)
	}
	return arpRequests
}

// arpsUnlocked returns the ARP requests of a Peer object without locking the mutex
func (p *Peer) arpsUnlocked() []ARPRequest {
	arpRequests := make([]ARPRequest, 0, len(p.arps))
	for _, v := range p.arps {
		arpRequests = append(arpRequests, *v)
	}
	return arpRequests
}

// RegisterMAC registers a MAC address for a Peer object
func (p *Peer) RegisterMAC(mac string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !slices.Contains(p.macs, mac) {
		p.macs = append(p.macs, mac)
	}
}

// RegisterAlert registers an alert for a Peer object
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

// RegisterARPRequest registers an ARP request for a Peer object
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

// UpdateTotalPackets updates the absolute value of totalPackets
func (p *Peer) UpdateTotalPackets(packets uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.totalPackets += packets
}

// UpdateLastSeen updates the last time a Peer object was seen
func (p *Peer) UpdateLastSeen() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.lastSeen = time.Now()
}

// IsStale returns true if a Peer object is stale
func (p *Peer) IsStale() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return time.Since(p.lastSeen) > DefaultTTL
}

// sync.Pool to handle object recycling in serialization routines
var peerPool = sync.Pool{
	New: func() any {
		return &Peer{
			arps:   make(map[string]*ARPRequest),
			alerts: make(map[string]*Alert),
		}
	},
}

// AcquireSnapshot gets a recycled *Peer instance from sync.Pool
func AcquireSnapshot() *Peer {
	return peerPool.Get().(*Peer)
}

// Release resets the snapshot used and returns it to sync.Pool
func (p *Peer) Release() {
	p.name = ""
	p.asn = 0
	p.macs = nil
	p.totalPackets = 0

	clear(p.arps)
	clear(p.alerts)

	peerPool.Put(p)
}

// DrainTo copies the current state of the Peer object to the provided snapshot
func (p *Peer) DrainTo(snapshot *Peer) {
	p.mu.Lock()
	defer p.mu.Unlock()

	snapshot.name = p.name
	snapshot.asn = p.asn
	snapshot.macs = p.macs
	snapshot.totalPackets = p.totalPackets
	snapshot.arps = p.arps
	snapshot.alerts = p.alerts
	snapshot.lastSeen = p.lastSeen

	snapshot.arps, p.arps = p.arps, snapshot.arps
	snapshot.alerts, p.alerts = p.alerts, snapshot.alerts
	p.totalPackets = 0
}
