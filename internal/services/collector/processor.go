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
	"argo-ebpf/internal/services/ixf"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"argo-ebpf/internal/models"
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
	mapper *ixf.Mapper
	repo   models.Repository
	logger *slog.Logger
}

func NewEventProcessor(mapper *ixf.Mapper, repo models.Repository, logger *slog.Logger) *EventProcessor {
	return new(EventProcessor{
		mapper: mapper,
		repo:   repo,
		logger: logger,
	})
}

// ProcessRingEvent gestisce gli eventi in streaming dal RingBuffer
func (p *EventProcessor) ProcessRingEvent(_ context.Context, event RawEvent) error {
	srcMAC := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		event.SrcMAC[0], event.SrcMAC[1], event.SrcMAC[2],
		event.SrcMAC[3], event.SrcMAC[4], event.SrcMAC[5])

	var peer *models.Peer
	var err error
	created := false

	peer, err = p.repo.RetrieveByMAC(srcMAC)
	if err != nil {
		info := p.mapper.RetrieveByMAC(srcMAC)
		if info == nil {
			p.logger.Error("peer not found", "err", err, "mac", srcMAC)
			return fmt.Errorf("peer not found: %s", srcMAC)
		}

		created = true
		peer = models.NewPeer(
			info.Name,
			info.ASN,
			info.GetMACs(),
		)
	}

	proto := models.ProtocolType(event.ProtoType)

	switch proto {
	case models.ProtoIPv6RA:
		srcIP := net.IP(event.SrcIPv6[:]).String()
		p.logger.Warn("CRITICAL: IPv6 Router Advertisement detected!", "src_mac", srcMAC, "src_ip", srcIP)

		peer.RegisterAlert(
			fmt.Sprintf("viol-ra-%s", srcMAC),
			srcMAC,
			srcIP,
			models.AlertIPv6RA,
			models.SeverityCritical,
			ActIPv6NDRA,
		)

	case models.ProtoMDNS, models.ProtoLLMNR, models.ProtoCDPLLDP:
		srcIP := p.parseIPv4(event.SrcIPv4)
		p.logger.Info("Policy violation detected", "type", proto, "src_mac", srcMAC, "src_ip", srcIP)

		peer.RegisterAlert(
			fmt.Sprintf("viol-proto-%d-%s", event.ProtoType, srcMAC),
			srcMAC,
			srcIP,
			models.ProtocolToAlertType(proto),
			models.SeverityWarning,
			ActMcast,
		)

	case models.ProtoARPReq:
		srcIP := p.parseIPv4(event.SrcIPv4)
		targetIP := p.parseIPv4(event.TargetIPv4)

		peer.RegisterARPRequest(
			fmt.Sprintf("arp-%s-%s", srcMAC, targetIP),
			srcMAC, targetIP)
		p.logger.Debug("ARP Request captured", "src_ip", srcIP, "target_ip", targetIP)
	}

	if created {
		if err = p.repo.Save(peer); err != nil {
			p.logger.Error("failed to save peer", "err", err)
			return err
		}
	} else {
		if err = p.repo.Update(peer); err != nil {
			p.logger.Error("failed to update peer", "err", err)
			return err
		}
	}

	return nil
}

// ProcessStatsMetric elabora le metriche aggregate lette dalle Mappe HASH eBPF
func (p *EventProcessor) ProcessStatsMetric(macBytes [6]byte, protoType uint16, packets, bytes uint64) {
	//	srcMAC := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
	//		macBytes[0], macBytes[1], macBytes[2],
	//		macBytes[3], macBytes[4], macBytes[5])
	//
	//p.repo.UpsertStat(srcMAC, models.ProtocolType(protoType), packets, bytes)
}

func (p *EventProcessor) parseIPv4(ipFix uint32) string {
	if ipFix == 0 {
		return ""
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipFix)
	return ip.String()
}
