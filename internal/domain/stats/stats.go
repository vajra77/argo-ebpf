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

const slotLen = 10
const DefaultTimeSlot = slotLen * time.Second
const maxHistory = 300 / slotLen

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

	history       []uint64
	hIdx          int
	movingAverage float64

	mu sync.RWMutex
}

func New() *Stats {
	return &Stats{
		metrics: make(map[string]Metric),
		history: make([]uint64, 0, maxHistory),
	}
}

func (s *Stats) Metrics() map[string]Metric {
	return s.metrics
}

func (s *Stats) TotalPackets() uint64 {
	return s.totalPackets
}

func (s *Stats) TotalBytes() uint64 {
	return s.totalBytes
}

func (s *Stats) MovingAverage() float64 {
	return s.movingAverage
}

func (s *Stats) Update(srcMac string, protoType uint16, packets uint64, bytes uint64) {
	if val, exists := s.metrics[srcMac]; exists {
		val.Packets += packets
		val.Bytes += bytes
		s.metrics[srcMac] = val
	} else {
		s.metrics[srcMac] = Metric{
			SrcMac:    srcMac,
			ProtoType: protoType,
			Packets:   packets,
			Bytes:     bytes,
		}
	}
	s.totalPackets += packets
	s.totalBytes += bytes

	s.history[s.hIdx] += packets
	s.hIdx++
	if s.hIdx == maxHistory {
		s.hIdx = 0
	}
	sum := uint64(0)
	for _, v := range s.history {
		sum += v
	}
	s.movingAverage = float64(sum) / float64(len(s.history))
}

var statsPool = sync.Pool{
	New: func() any {
		return new(Stats{
			metrics: make(map[string]Metric),
		})
	},
}

func AcquireSnapshot() *Stats {
	return statsPool.Get().(*Stats)
}

func (s *Stats) Release() {
	clear(s.metrics)
	s.totalPackets = 0
	s.totalBytes = 0
	clear(s.history)
	s.hIdx = 0
	s.movingAverage = 0
	statsPool.Put(s)
}

func (s *Stats) DrainTo(snapshot *Stats) {
	snapshot.totalBytes = s.totalBytes
	snapshot.totalPackets = s.totalPackets
	snapshot.movingAverage = s.movingAverage
	snapshot.metrics, s.metrics = s.metrics, snapshot.metrics
}
