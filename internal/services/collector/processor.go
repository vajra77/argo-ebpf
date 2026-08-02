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
	"net"
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
	cache  *PeerCache
	logger *slog.Logger
}

func NewEventProcessor(cache *PeerCache, logger *slog.Logger) *EventProcessor {
	return new(EventProcessor{
		cache:  cache,
		logger: logger,
	})
}

// ProcessRingEvent gestisce gli eventi in streaming dal RingBuffer
func (p *EventProcessor) ProcessRingEvent(_ context.Context, event RawEvent) error {
	srcMAC := network.FormatMAC(event.SrcMAC)

	aPeer := p.cache.GetOrSet(srcMAC)
	if aPeer == nil {
		return fmt.Errorf("failed to retrieve peer for MAC %s", srcMAC)
	}

	proto := network.ProtocolType(event.ProtoType)

	switch proto {
	case network.ProtoIPv6RA:
		srcIP := net.IP(event.SrcIPv6[:]).String()
		p.logger.Warn("CRITICAL: IPv6 Router Advertisement detected!", "src_mac", srcMAC, "src_ip", srcIP)

		aPeer.RegisterAlert(
			fmt.Sprintf("viol-ra-%s", srcMAC),
			srcMAC,
			srcIP,
			peer.AlertIPv6RA,
			peer.SeverityCritical,
			ActIPv6NDRA,
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
		p.logger.Debug("ARP Request captured", "src_ip", srcIP, "target_ip", targetIP)
	}

	return nil
}

// ProcessStatsMetric elabora le metriche aggregate lette dalle Mappe HASH eBPF
func (p *EventProcessor) ProcessStatsMetric(macBytes [6]byte, protoType uint16, packets, bytes uint64) {
	//	srcMAC := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
	//		macBytes[0], macBytes[1], macBytes[2],
	//		macBytes[3], macBytes[4], macBytes[5])
	//
	//p.repo.UpsertStat(srcMAC, domain.ProtocolType(protoType), packets, bytes)
}

func (p *EventProcessor) parseIPv4(ipFix uint32) string {
	if ipFix == 0 {
		return ""
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipFix)
	return ip.String()
}
