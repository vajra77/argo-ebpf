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
	"argo-ebpf/internal/domain/network"
	"argo-ebpf/internal/domain/peer"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
)

type RawEvent struct {
	TimestampNs uint64
	SrcIPv4     uint32
	TargetIPv4  uint32
	SrcIPv6     [16]byte
	ProtoType   uint16
	PktLen      uint16
	SrcMAC      [6]byte
}

type EventProcessor struct {
	pCache *PeerCache
	sCache *StatsCache
	logger *slog.Logger
}

func NewEventProcessor(pCache *PeerCache, sCache *StatsCache, logger *slog.Logger) *EventProcessor {
	return new(EventProcessor{
		pCache: pCache,
		sCache: sCache,
		logger: logger,
	})
}

// ProcessRingEvent handles events in streaming from RingBuffer
func (p *EventProcessor) ProcessRingEvent(_ context.Context, event RawEvent) error {
	srcMAC := network.FormatMAC(event.SrcMAC)

	aPeer := p.pCache.GetOrSet(srcMAC)
	if aPeer == nil {
		return fmt.Errorf("failed to retrieve peer for MAC %s", srcMAC)
	}

	proto := network.ProtocolType(event.ProtoType)

	switch proto {
	case network.ProtoIPv6RA:
		srcIP := p.parseIPv6(event.SrcIPv6)
		p.logger.Warn("CRITICAL: IPv6 Router Advertisement detected!", "src_mac", srcMAC, "src_ip", srcIP)

		aPeer.RegisterAlert(
			fmt.Sprintf("viol-ra-%s", srcMAC),
			srcMAC,
			srcIP,
			peer.AlertIPv6RA,
			peer.SeverityCritical,
			ActIPv6RA,
		)

	case network.ProtoMDNS, network.ProtoLLMNR, network.ProtoCDPLLDP:
		srcIP := p.parseIPv4(event.SrcIPv4)
		p.logger.Info("Policy violation detected", "type", proto, "src_mac", srcMAC, "src_ip", srcIP)

		aPeer.RegisterAlert(
			fmt.Sprintf("viol-proto-%d-%s", event.ProtoType, srcMAC),
			srcMAC,
			srcIP,
			network.ProtocolToAlertType(proto),
			peer.SeverityWarning,
			ActMcast,
		)

	case network.ProtoARPReq:
		srcIP := p.parseIPv4(event.SrcIPv4)
		targetIP := p.parseIPv4(event.TargetIPv4)

		aPeer.RegisterARPRequest(
			fmt.Sprintf("arp-%s-%s", srcMAC, targetIP),
			srcMAC, targetIP)

		if p.sCache.HasAnomaly() {
			p.logger.Warn("ARP Flood detected!", "src_mac", srcMAC, "src_ip", srcIP, "target_ip", targetIP)
			aPeer.RegisterAlert(
				fmt.Sprintf("flood-arp-%s", srcMAC),
				srcMAC,
				srcIP,
				peer.AlertFlood,
				peer.SeverityWarning,
				ActFlood,
			)
		} else {
			p.logger.Debug("ARP Request captured", "src_ip", srcIP, "target_ip", targetIP)
		}
	}

	return nil
}

// ProcessStatsMetric stores metrics from eBPF hash maps
func (p *EventProcessor) ProcessStatsMetric(macBytes [6]byte, protoType uint16, packets, bytes uint64) {
	srcMac := network.FormatMAC(macBytes)
	p.sCache.Set(srcMac, protoType, packets, bytes)
}

func (p *EventProcessor) parseIPv4(ipFix uint32) string {
	if ipFix == 0 {
		return ""
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ipFix)
	return netip.AddrFrom4(b).String()
}

func (p *EventProcessor) parseIPv6(ipFix [16]byte) string {
	return netip.AddrFrom16(ipFix).String() // Zero-alloc per la conversione da array
}
