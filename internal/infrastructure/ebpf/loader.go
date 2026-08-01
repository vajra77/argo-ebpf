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

	"argo-ebpf/bpf"
	"argo-ebpf/internal/service/collector"
)

type BpfBroadcastEventT struct {
	TimestampNs uint64
	SrcIpV4     uint32
	TargetIpV4  uint32
	SrcIpV6     [16]byte
	ProtoType   uint16
	PktLen      uint16
	SrcMac      [6]byte
}

type Loader struct {
	ifaceName string
	processor *collector.EventProcessor
	logger    *slog.Logger
	objs      bpf.BpfObjects
	link      link.Link
}

func NewLoader(ifaceName string, processor *collector.EventProcessor, logger *slog.Logger) (*Loader, error) {
	return &Loader{
		ifaceName: ifaceName,
		processor: processor,
		logger:    logger,
	}, nil
}

// Start carica il bytecode nel kernel, esegue l'attach XDP e avvia i worker
func (l *Loader) Start(ctx context.Context) error {
	// 1. Carica i programmi e le mappe eBPF nel kernel
	if err := bpf.LoadBpfObjects(&l.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects failed: %w", err)
	}

	// 2. Recupera l'interfaccia di rete per l'attach XDP
	iface, err := net.InterfaceByName(l.ifaceName)
	if err != nil {
		l.Close()
		return fmt.Errorf("failed to find interface %s: %w", l.ifaceName, err)
	}

	// 3. Attach del programma XDP all'interfaccia di rete
	l.logger.Info("Attaching XDP program to interface", "iface", l.ifaceName, "index", iface.Index)
	l.link, err = link.AttachXDP(link.XDPOptions{
		Program:   l.objs.FilterBroadcast,
		Interface: iface.Index,
	})
	if err != nil {
		l.Close()
		return fmt.Errorf("failed to attach XDP program: %w", err)
	}

	// 4. Avvia i Worker per RingBuffer (eventi) e Map Polling (statistiche totali)
	go l.consumeRingBuffer(ctx)
	go l.pollBroadcastStats(ctx)

	return nil
}

// consumeRingBuffer legge in streaming gli eventi emessi da eBPF (RA, ARP, mDNS)
func (l *Loader) consumeRingBuffer(ctx context.Context) {
	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.logger.Error("Failed to create ringbuffer reader", "error", err)
		return
	}
	defer rd.Close()

	l.logger.Info("Started eBPF RingBuffer consumer loop")

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				l.logger.Info("RingBuffer reader closed")
				return
			}
			l.logger.Warn("Error reading from RingBuffer", "error", err)
			continue
		}

		if len(record.RawSample) < 44 { // Dimensione attesa della struct packed
			l.logger.Error("Received malformed RingBuffer event: too short")
			continue
		}
		rawEvent := (*BpfBroadcastEventT)(unsafe.Pointer(&record.RawSample[0]))

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

		if err := l.processor.ProcessRingEvent(ctx, domainEvent); err != nil {
			// Se l'errore è dovuto all'annullamento del contesto, usciamo
			if errors.Is(err, ctx.Err()) {
				return
			}
			l.logger.Warn("Failed to process event in application layer", "error", err)
		}
	}
}

// pollBroadcastStats legge ad intervalli regolari la mappa HASH con i totali dei byte/pacchetti
func (l *Loader) pollBroadcastStats(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var (
				key bpf.BpfStatsKeyT
				val bpf.BpfStatsValT
			)

			// Iteratore sulla mappa HASH eBPF broadcast_stats
			iterator := l.objs.BroadcastStats.Iterate()
			for iterator.Next(&key, &val) {
				// Passa i dati al processore.
				// Se p.repo.UpsertStat è sincrona, questo loop dura quanto il processamento di tutti i peer.
				l.processor.ProcessStatsMetric(key.SrcMac, key.ProtoType, val.Packets, val.Bytes)
			}

			if err := iterator.Err(); err != nil {
				l.logger.Warn("Error iterating over broadcast_stats map", "error", err)
			}
		}
	}
}

// Close rilascia i file descriptor e rimuove l'hook XDP dall'interfaccia
func (l *Loader) Close() {
	if l.link != nil {
		_ = l.link.Close()
	}
	_ = l.objs.Close()
	l.logger.Info("eBPF loader resources released cleanly")
}
