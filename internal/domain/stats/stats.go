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
	"encoding/json"
	"sync"
	"time"
)

const slotLen = 10
const DefaultTimeSlot = slotLen * time.Second
const maxHistory = 300 / slotLen

// Metric is a basic data structure representing
// network statistics for a specific source MAC address and protocol type.
type Metric struct {
	SrcMac    string
	ProtoType uint16
	Packets   uint64
	Bytes     uint64
}

// Stats represent global network statistics
type Stats struct {
	metrics      map[string]Metric
	lastPackets  uint64
	lastBytes    uint64
	totalPackets uint64
	totalBytes   uint64

	history       []uint64
	hIdx          int
	movingAverage float64
	IsAnomaly     bool
}

// New creates a new Stats object
func New() *Stats {
	return &Stats{
		metrics: make(map[string]Metric),
		history: make([]uint64, 0, maxHistory),
	}
}

// Metrics returns a slice of Metric objects representing the current network statistics
func (s *Stats) Metrics() []Metric {
	metrics := make([]Metric, 0, len(s.metrics))
	for _, v := range s.metrics {
		metrics = append(metrics, v)
	}
	return metrics
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

// MarshalJSON converts Stats object to JSON format
func (s *Stats) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Metrics       []Metric `json:"metric"`
		TotalPackets  uint64   `json:"total_packets"`
		TotalBytes    uint64   `json:"total_bytes"`
		MovingAverage float64  `json:"moving_average"`
		IsAnomaly     bool     `json:"is_anomaly"`
	}{
		Metrics:       s.Metrics(),
		TotalPackets:  s.totalPackets,
		TotalBytes:    s.totalBytes,
		MovingAverage: s.movingAverage,
		IsAnomaly:     s.IsAnomaly,
	})
}

// UnmarshalJSON converts JSON data to Stats object
func (s *Stats) UnmarshalJSON(data []byte) error {
	aux := &struct {
		Metrics       []Metric `json:"metric"`
		TotalPackets  uint64   `json:"total_packets"`
		TotalBytes    uint64   `json:"total_bytes"`
		MovingAverage float64  `json:"moving_average"`
		IsAnomaly     bool     `json:"is_anomaly"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	s.totalBytes = aux.TotalBytes
	s.totalPackets = aux.TotalPackets
	s.movingAverage = aux.MovingAverage
	s.IsAnomaly = aux.IsAnomaly
	s.metrics = make(map[string]Metric)

	for _, m := range aux.Metrics {
		s.Update(m.SrcMac, m.ProtoType, m.Packets, m.Bytes)
	}

	return nil
}

// Update updates the network statistics for a specific source MAC address and protocol type
func (s *Stats) Update(srcMac string, protoType uint16, packets uint64, bytes uint64) {
	deltaPackets := packets - s.lastPackets
	deltaBytes := bytes - s.lastBytes

	if val, exists := s.metrics[srcMac]; exists {
		val.Packets += deltaPackets
		val.Bytes += deltaBytes
		s.metrics[srcMac] = val
	} else {
		s.metrics[srcMac] = Metric{
			SrcMac:    srcMac,
			ProtoType: protoType,
			Packets:   deltaPackets,
			Bytes:     deltaBytes,
		}
	}
	s.totalPackets += deltaPackets
	s.totalBytes += deltaBytes
	s.lastPackets = packets
	s.lastBytes = bytes

	if len(s.history) == maxHistory {
		if float64(deltaPackets) > (s.movingAverage*10) && deltaPackets > 500 {
			s.IsAnomaly = true
		} else {
			s.IsAnomaly = false
		}
	}

	if len(s.history) < maxHistory {
		s.history = append(s.history, deltaPackets)
	} else {
		s.history[s.hIdx] = deltaPackets
	}
	s.hIdx = (s.hIdx + 1) % maxHistory

	sum := uint64(0)
	for _, v := range s.history {
		sum += v
	}
	if len(s.history) > 0 {
		s.movingAverage = float64(sum) / float64(len(s.history))
	}
}

// statsPool is a sync.Pool for reusing Stats objects
var statsPool = sync.Pool{
	New: func() any {
		return new(Stats{
			metrics: make(map[string]Metric),
		})
	},
}

// AcquireSnapshot acquires a Stats object from the pool
func AcquireSnapshot() *Stats {
	return statsPool.Get().(*Stats)
}

// Release releases a Stats object back to the pool
func (s *Stats) Release() {
	clear(s.metrics)
	s.lastPackets = 0
	s.lastBytes = 0
	s.totalPackets = 0
	s.totalBytes = 0
	clear(s.history)
	s.hIdx = 0
	s.movingAverage = 0
	s.IsAnomaly = false
	statsPool.Put(s)
}

// DrainTo drains the current statistics to the provided snapshot
func (s *Stats) DrainTo(snapshot *Stats) {
	snapshot.totalBytes = s.totalBytes
	snapshot.totalPackets = s.totalPackets
	snapshot.movingAverage = s.movingAverage
	snapshot.IsAnomaly = s.IsAnomaly
	snapshot.metrics, s.metrics = s.metrics, snapshot.metrics
}
