/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package models

import (
	"github.com/google/uuid"
)

type Peer struct {
	ID           string                 `bson:"_id" json:"id"`
	Name         string                 `bson:"name" json:"name"`
	ASN          int                    `bson:"asn" json:"asn"`
	MACs         []string               `bson:"macs" json:"macs"`
	TotalPackets uint64                 `bson:"total_packets" json:"total_packets"`
	ARPs         map[string]*ARPRequest `bson:"arps" json:"arps"`
	Alerts       map[string]*Alert      `bson:"alerts" json:"alerts"`
}

func NewPeer(name string, asn int, macs []string) *Peer {
	return new(Peer{
		ID:           uuid.New().String(),
		Name:         name,
		ASN:          asn,
		MACs:         macs,
		TotalPackets: 0,
		ARPs:         make(map[string]*ARPRequest),
		Alerts:       make(map[string]*Alert),
	})
}

func (p *Peer) RegisterAlert(id, srcMAC, srcIP string, alertType AlertType, severity Severity, act string) {
	if alert, ok := p.Alerts[id]; !ok {
		p.Alerts[id] = NewAlert(id, srcMAC, srcIP, alertType, severity, act)
	} else {
		alert.Update()
	}
	p.TotalPackets++
}

func (p *Peer) RegisterARPRequest(id, srcMAC, targetIP string) {
	if arp, ok := p.ARPs[id]; ok {
		arp.Update()
	} else {
		newArp := NewARPRequest(id, srcMAC, targetIP)
		p.ARPs[id] = newArp
	}
	p.TotalPackets++
}
