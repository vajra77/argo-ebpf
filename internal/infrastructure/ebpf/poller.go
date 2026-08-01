package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"argo-ebpf/internal/services/collector"
)

type BroadcastEventT struct {
	TimestampNs uint64
	SrcIpV4     uint32
	TargetIpV4  uint32
	SrcIpV6     [16]byte
	ProtoType   uint16
	PktLen      uint16
	SrcMac      [6]byte
}

type Poller struct {
	ifaceName string
	processor *collector.EventProcessor
	logger    *slog.Logger
	objs      BpfObjects
	link      link.Link
}

func NewPoller(ifaceName string, processor *collector.EventProcessor, logger *slog.Logger) (*Poller, error) {
	return &Poller{
		ifaceName: ifaceName,
		processor: processor,
		logger:    logger,
	}, nil
}

// Start carica il bytecode nel kernel, esegue l'attach XDP e avvia i worker
func (p *Poller) Start(ctx context.Context) error {
	// 1. Carica i programmi e le mappe eBPF nel kernel
	if err := LoadBpfObjects(&p.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects failed: %w", err)
	}

	// 2. Recupera l'interfaccia di rete per l'attach XDP
	iface, err := net.InterfaceByName(p.ifaceName)
	if err != nil {
		p.Close()
		return fmt.Errorf("failed to find interface %s: %w", p.ifaceName, err)
	}

	// 3. Attach del programma XDP all'interfaccia di rete
	p.logger.Info("Attaching XDP program to interface", "iface", p.ifaceName, "index", iface.Index)
	p.link, err = link.AttachXDP(link.XDPOptions{
		Program:   p.objs.FilterBroadcast,
		Interface: iface.Index,
	})
	if err != nil {
		p.Close()
		return fmt.Errorf("failed to attach XDP program: %w", err)
	}

	// 4. Avvia i Worker per RingBuffer (eventi) e Map Polling (statistiche totali)
	go p.consumeRingBuffer(ctx)
	go p.pollBroadcastStats(ctx)

	return nil
}

// consumeRingBuffer legge in streaming gli eventi emessi da eBPF (RA, ARP, mDNS)
func (p *Poller) consumeRingBuffer(ctx context.Context) {
	rd, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		p.logger.Error("Failed to create ringbuffer reader", "error", err)
		return
	}
	defer rd.Close()

	p.logger.Info("Started eBPF RingBuffer consumer loop")

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				p.logger.Info("RingBuffer reader closed")
				return
			}
			p.logger.Warn("Error reading from RingBuffer", "error", err)
			continue
		}

		if len(record.RawSample) < 44 { // Dimensione attesa della struct packed
			p.logger.Error("Received malformed RingBuffer event: too short")
			continue
		}
		rawEvent := (*BroadcastEventT)(unsafe.Pointer(&record.RawSample[0]))

		// Invia l'evento grezzo al layer Service
		domainEvent := collector.RawEvent{
			TimestampNs: rawEvent.TimestampNs,
			SrcIPv4:     rawEvent.SrcIpV4,
			TargetIPv4:  rawEvent.TargetIpV4,
			SrcIPv6:     rawEvent.SrcIpV6,
			ProtoType:   rawEvent.ProtoType,
			PktLen:      rawEvent.PktLen,
			SrcMAC:      rawEvent.SrcMac,
		}

		if err := p.processor.ProcessRingEvent(ctx, domainEvent); err != nil {
			// Se l'errore è dovuto all'annullamento del contesto, usciamo
			if errors.Is(err, ctx.Err()) {
				return
			}
			p.logger.Warn("Failed to process event in application layer", "error", err)
		}
	}
}

// pollBroadcastStats legge ad intervalli regolari la mappa HASH con i totali dei byte/pacchetti
func (p *Poller) pollBroadcastStats(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var (
				key BpfStatsKeyT
				val BpfStatsValT
			)

			// Iteratore sulla mappa HASH eBPF broadcast_stats
			iterator := p.objs.BroadcastStats.Iterate()
			for iterator.Next(&key, &val) {
				// Passa i dati al processore.
				// Se p.repo.UpsertStat è sincrona, questo loop dura quanto il processamento di tutti i peer.
				p.processor.ProcessStatsMetric(key.SrcMac, key.ProtoType, val.Packets, val.Bytes)
			}

			if err := iterator.Err(); err != nil {
				p.logger.Warn("Error iterating over broadcast_stats map", "error", err)
			}
		}
	}
}

// Close rilascia i file descriptor e rimuove l'hook XDP dall'interfaccia
func (p *Poller) Close() {
	if p.link != nil {
		_ = p.link.Close()
	}
	_ = p.objs.Close()
	p.logger.Info("eBPF loader resources released cleanly")
}
