/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package stats

import (
	"sync"
	"time"
)

const DefaultTimeSlot = 10 * time.Second

type Metric struct {
	SrcMac    string
	ProtoType uint16
	Packets   uint64
	Bytes     uint64
}

type Stats struct {
	metrics      map[string]Metric
	totalPackets uint64
	totalBytes   uint64

	history []uint64

	mu sync.RWMutex
}
