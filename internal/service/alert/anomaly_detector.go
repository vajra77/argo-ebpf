package alert

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"argo-ebpf/internal/domain"
)

// Configurazione delle soglie di Anomaly Detection
type DetectorConfig struct {
	PollInterval         time.Duration // Frequenza di campionamento (es. 1s)
	SpikeThresholdFactor float64       // Moltiplicatore spike (es. 3.0 = +300% rispetto alla baseline)
	MinPacketsThreshold  uint64        // Minimo numero di pacchetti per evitare falsi positivi a bassi volumi
	ARPSurgeMaxRequests  uint64        // Soglia di richieste ARP verso uno stesso target per considerarlo DOWN
	MinUniqueRequesters  int           // Numero minimo di MAC distinti che cercano lo stesso target
}

func DefaultConfig() DetectorConfig {
	return DetectorConfig{
		PollInterval:         1 * time.Second,
		SpikeThresholdFactor: 3.0,
		MinPacketsThreshold:  50,
		ARPSurgeMaxRequests:  500,
		MinUniqueRequesters:  5,
	}
}

type PeerBaseline struct {
	LastPackets uint64
	LastBytes   uint64
	EmaPackets  float64
	EmaBytes    float64
	LastUpdated time.Time
}

type AnomalyDetector struct {
	repo      domain.MetricsRepository
	logger    *slog.Logger
	cfg       DetectorConfig
	mu        sync.Mutex
	baselines map[string]*PeerBaseline // "MAC|Proto" -> Baseline
}

func NewAnomalyDetector(repo domain.MetricsRepository, cfg DetectorConfig, logger *slog.Logger) *AnomalyDetector {
	return &AnomalyDetector{
		repo:      repo,
		cfg:       cfg,
		logger:    logger,
		baselines: make(map[string]*PeerBaseline),
	}
}

// Start avvia il loop di anomaly detection in background
func (d *AnomalyDetector) Start(ctx context.Context) {
	ticker := time.NewTicker(d.cfg.PollInterval)
	defer ticker.Stop()

	d.logger.Info("Anomaly Detector Engine started", "poll_interval", d.cfg.PollInterval)

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("Anomaly Detector stopped")
			return
		case <-ticker.C:
			d.evaluateTrafficSpikes(ctx)
			d.evaluateARPAnomalies(ctx)
		}
	}
}

// evaluateTrafficSpikes calcola i deltas e confronta il rate istantaneo con l'EMA
func (d *AnomalyDetector) evaluateTrafficSpikes(ctx context.Context) {
	summaries, err := d.repo.GetTopBroadcasters(ctx, 100)
	if err != nil {
		d.logger.Error("Failed to fetch traffic stats for anomaly evaluation", "error", err)
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	alpha := 0.2 // Fattore di lisciamento EMA (0.2 = peso del 20% all'ultimo secondo)

	for _, s := range summaries {
		for proto, vol := range s.Protocols {
			key := fmt.Sprintf("%s|%d", s.PeerMAC, proto)
			base, exists := d.baselines[key]

			if !exists {
				// Inizializza baseline
				d.baselines[key] = &PeerBaseline{
					LastPackets: vol.Packets,
					LastBytes:   vol.Bytes,
					EmaPackets:  float64(vol.Packets),
					EmaBytes:    float64(vol.Bytes),
					LastUpdated: now,
				}
				continue
			}

			// Calcola i delta istantanei dal tick precedente
			deltaPackets := vol.Packets - base.LastPackets
			deltaBytes := vol.Bytes - base.LastBytes

			// Valuta lo spike solo se superiamo la soglia minima di pacchetti
			if deltaPackets > d.cfg.MinPacketsThreshold && base.EmaPackets > 0 {
				ratio := float64(deltaPackets) / base.EmaPackets

				if ratio >= d.cfg.SpikeThresholdFactor {
					d.logger.Error("ALERT: Traffic Surge Detected!",
						"peer_mac", s.PeerMAC,
						"protocol", proto.String(),
						"current_pps", deltaPackets,
						"baseline_pps", uint64(base.EmaPackets),
						"surge_ratio", fmt.Sprintf("%.2fx", ratio),
					)

					// Registra la violazione di tipo SPIKE nello store per Retool
					d.repo.RecordViolation(domain.Violation{
						ID:              fmt.Sprintf("surge-%s-%d-%d", s.PeerMAC, proto, now.Unix()),
						PeerMAC:         s.PeerMAC,
						Type:            domain.ViolationType("TRAFFIC_SPIKE"),
						Severity:        domain.SeverityCritical,
						PacketCount:     deltaPackets,
						SuggestedAction: fmt.Sprintf("Verificare il peer %s: traffico %s aumentato di %.1f volte rispetto alla media.", s.PeerMAC, proto.String(), ratio),
					})
				}
			}

			// Aggiorna baseline con formula EMA
			base.EmaPackets = alpha*float64(deltaPackets) + (1-alpha)*base.EmaPackets
			base.EmaBytes = alpha*float64(deltaBytes) + (1-alpha)*base.EmaBytes
			base.LastPackets = vol.Packets
			base.LastBytes = vol.Bytes
			base.LastUpdated = now
		}
	}
}

// evaluateARPAnomalies verifica se ci sono Target IP presi d'assalto da ARP Request (Peer Down)
func (d *AnomalyDetector) evaluateARPAnomalies(ctx context.Context) {
	anomalies, err := d.repo.GetARPAnomalies(ctx)
	if err != nil {
		return
	}

	for _, a := range anomalies {
		if a.RequestCount >= d.cfg.ARPSurgeMaxRequests && a.UniqueRequestersCount >= d.cfg.MinUniqueRequesters {
			d.logger.Error("ALERT: Suspected Peer Down via ARP Surge!",
				"target_ip", a.TargetIP,
				"total_arp_requests", a.RequestCount,
				"requesting_peers_count", a.UniqueRequestersCount,
			)
		}
	}
}
