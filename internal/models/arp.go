/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package models

import "time"

type ARPRequest struct {
	ID          string
	SrcMAC      string
	TargetIP    string
	PacketCount uint64
	FirstSeen   time.Time
	LastSeen    time.Time
}

func NewARPRequest(id, srcMAC, targetIP string) *ARPRequest {
	now := time.Now()
	return new(ARPRequest{
		ID:          id,
		SrcMAC:      srcMAC,
		TargetIP:    targetIP,
		PacketCount: 1,
		FirstSeen:   now,
		LastSeen:    now,
	})
}

func (a *ARPRequest) Update() {
	a.PacketCount++
	a.LastSeen = time.Now()
}
