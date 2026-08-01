package collector

import (
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
	repo   models.MetricsRepository
	logger *slog.Logger
}

func NewEventProcessor(repo models.MetricsRepository, logger *slog.Logger) *EventProcessor {
	return &EventProcessor{
		repo:   repo,
		logger: logger,
	}
}

// ProcessRingEvent gestisce gli eventi in streaming dal RingBuffer
func (p *EventProcessor) ProcessRingEvent(_ context.Context, event RawEvent) error {
	srcMAC := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		event.SrcMAC[0], event.SrcMAC[1], event.SrcMAC[2],
		event.SrcMAC[3], event.SrcMAC[4], event.SrcMAC[5])

	proto := models.ProtocolType(event.ProtoType)

	switch proto {
	case models.ProtoIPv6RA:
		srcIP := net.IP(event.SrcIPv6[:]).String()
		p.logger.Warn("CRITICAL: IPv6 Router Advertisement detected!", "src_mac", srcMAC, "src_ip", srcIP)

		p.repo.RecordAlert(models.Alert{
			ID:              fmt.Sprintf("viol-ra-%s", srcMAC),
			PeerMAC:         srcMAC,
			SrcIP:           srcIP,
			Type:            models.AlertIPv6RA,
			Severity:        models.SeverityCritical,
			SuggestedAction: "Avvisare immediatamente il NOC del peer di disattivare 'ipv6 nd send-ra' sull'interfaccia verso l'IXP.",
		})

	case models.ProtoMDNS, models.ProtoLLMNR, models.ProtoCDPLLDP:
		srcIP := p.parseIPv4(event.SrcIPv4)
		p.logger.Info("Policy violation detected", "type", proto, "src_mac", srcMAC, "src_ip", srcIP)

		p.repo.RecordAlert(models.Alert{
			ID:              fmt.Sprintf("viol-proto-%d-%s", event.ProtoType, srcMAC),
			PeerMAC:         srcMAC,
			SrcIP:           srcIP,
			Type:            models.ProtocolToAlertType(proto),
			Severity:        models.SeverityWarning,
			SuggestedAction: "Disattivare i servizi di discovery L2/multicast sul router del peer.",
		})

	case models.ProtoARPReq:
		srcIP := p.parseIPv4(event.SrcIPv4)
		targetIP := p.parseIPv4(event.TargetIPv4)

		// Aggiorna la mappa delle richieste ARP per tracciare tempestivamente Target IP irraggiungibili
		p.repo.RecordARPRequest(srcMAC, targetIP)
		p.logger.Debug("ARP Request captured", "src_ip", srcIP, "target_ip", targetIP)
	}

	return nil
}

// ProcessStatsMetric elabora le metriche aggregate lette dalle Mappe HASH eBPF
func (p *EventProcessor) ProcessStatsMetric(macBytes [6]byte, protoType uint16, packets, bytes uint64) {
	srcMAC := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		macBytes[0], macBytes[1], macBytes[2],
		macBytes[3], macBytes[4], macBytes[5])

	p.repo.UpsertStat(srcMAC, models.ProtocolType(protoType), packets, bytes)
}

func (p *EventProcessor) parseIPv4(ipFix uint32) string {
	if ipFix == 0 {
		return ""
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipFix)
	return ip.String()
}
