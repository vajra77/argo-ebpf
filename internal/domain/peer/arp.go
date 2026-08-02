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
	"time"
)

type ARPRequest struct {
	id          string
	srcMAC      string
	targetIP    string
	packetCount uint64
	firstSeen   time.Time
	lastSeen    time.Time
}

func (a *ARPRequest) ID() string {
	return a.id
}

func (a *ARPRequest) SrcMAC() string {
	return a.srcMAC
}

func (a *ARPRequest) TargetIP() string {
	return a.targetIP
}

func (a *ARPRequest) PacketCount() uint64 {
	return a.packetCount
}

func (a *ARPRequest) FirstSeen() time.Time {
	return a.firstSeen
}

func (a *ARPRequest) LastSeen() time.Time {
	return a.lastSeen
}

func (a *ARPRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID          string    `json:"id"`
		SrcMAC      string    `json:"src_mac"`
		TargetIP    string    `json:"target_ip"`
		PacketCount uint64    `json:"packet_count"`
		FirstSeen   time.Time `json:"first_seen"`
		LastSeen    time.Time `json:"last_seen"`
	}{
		ID:          a.id,
		SrcMAC:      a.srcMAC,
		TargetIP:    a.targetIP,
		PacketCount: a.packetCount,
		FirstSeen:   a.firstSeen,
		LastSeen:    a.lastSeen,
	})
}

func (a *ARPRequest) UnmarshalJSON(data []byte) error {
	aux := &struct {
		ID          string    `json:"id"`
		SrcMAC      string    `json:"src_mac"`
		TargetIP    string    `json:"target_ip"`
		PacketCount uint64    `json:"packet_count"`
		FirstSeen   time.Time `json:"first_seen"`
		LastSeen    time.Time `json:"last_seen"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	a.id = aux.ID
	a.srcMAC = aux.SrcMAC
	a.targetIP = aux.TargetIP
	a.packetCount = aux.PacketCount
	a.firstSeen = aux.FirstSeen
	a.lastSeen = aux.LastSeen

	return nil
}

func NewARPRequest(id, srcMAC, targetIP string) *ARPRequest {
	now := time.Now()
	return new(ARPRequest{
		id:          id,
		srcMAC:      srcMAC,
		targetIP:    targetIP,
		packetCount: 1,
		firstSeen:   now,
		lastSeen:    now,
	})
}

func (a *ARPRequest) Update() {
	a.packetCount++
	a.lastSeen = time.Now()
}
