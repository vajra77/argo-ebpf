package repository

import (
	"context"
	"fmt"
	"sync"
	"time"

	"argo-ebpf/internal/domain"
)

type InMemoryStore struct {
	mu sync.RWMutex

	// Mappa aggregata per MAC + Protocollo: "00:11:22:33:44:55|1" -> Stats
	stats map[string]*domain.BroadcastStat

	// Mappa delle violazioni attive: "00:11:22:33:44:55|IPV6_ROUTER_ADVERTISEMENT" -> Violation
	violations map[string]*domain.Violation

	// Mappa per Anomaly Detection ARP: "195.85.100.45" -> TargetARPAnomaly
	arpAnomalies map[string]*domain.TargetARPAnomaly
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		stats:        make(map[string]*domain.BroadcastStat),
		violations:   make(map[string]*domain.Violation),
		arpAnomalies: make(map[string]*domain.TargetARPAnomaly),
	}
}

/* ==========================================================================
 * METRICHE & TOP BROADCASTERS
 * ========================================================================== */

func (s *InMemoryStore) UpsertStat(mac string, proto domain.ProtocolType, packets, bytes uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s|%d", mac, proto)
	now := time.Now()

	if stat, exists := s.stats[key]; exists {
		stat.Packets = packets
		stat.Bytes = bytes
		stat.LastUpdated = now
	} else {
		s.stats[key] = &domain.BroadcastStat{
			PeerMAC:     mac,
			Protocol:    proto,
			Packets:     packets,
			Bytes:       bytes,
			LastUpdated: now,
		}
	}
}

func (s *InMemoryStore) GetTopBroadcasters(ctx context.Context, limit int) ([]domain.PeerTrafficSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Aggregazione per MAC Address
	peerMap := make(map[string]*domain.PeerTrafficSummary)

	for _, stat := range s.stats {
		summary, exists := peerMap[stat.PeerMAC]
		if !exists {
			summary = &domain.PeerTrafficSummary{
				PeerMAC:   stat.PeerMAC,
				Protocols: make(map[domain.ProtocolType]domain.TrafficVolume),
			}
			peerMap[stat.PeerMAC] = summary
		}

		summary.TotalPackets += stat.Packets
		summary.TotalBytes += stat.Bytes

		summary.Protocols[stat.Protocol] = domain.TrafficVolume{
			Packets: stat.Packets,
			Bytes:   stat.Bytes,
		}
	}

	result := make([]domain.PeerTrafficSummary, 0, len(peerMap))
	for _, summary := range peerMap {
		result = append(result, *summary)
	}

	// In un'implementazione reale qui si applica il sorting per TotalBytes/TotalPackets e il trancio [0:limit]
	return result, nil
}

/* ==========================================================================
 * VIOLAZIONI & MISCONFIGURATIONS (IPv6 RA, mDNS, etc.)
 * ========================================================================== */

func (s *InMemoryStore) RecordViolation(v domain.Violation) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s|%s", v.PeerMAC, v.Type)
	now := time.Now()

	if existing, exists := s.violations[key]; exists {
		existing.PacketCount++
		existing.LastSeen = now
		existing.SrcIP = v.SrcIP
	} else {
		newViolation := v
		newViolation.FirstSeen = now
		newViolation.LastSeen = now
		newViolation.PacketCount = 1
		s.violations[key] = &newViolation
	}
}

func (s *InMemoryStore) GetActiveViolations(ctx context.Context) ([]domain.Violation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]domain.Violation, 0, len(s.violations))
	for _, v := range s.violations {
		result = append(result, *v)
	}
	return result, nil
}

/* ==========================================================================
 * ARP TARGET ANOMALIES (PEER DOWN DETECTION)
 * ========================================================================== */

func (s *InMemoryStore) RecordARPRequest(srcMAC string, targetIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	anomaly, exists := s.arpAnomalies[targetIP]

	if !exists {
		anomaly = &domain.TargetARPAnomaly{
			TargetIP:         targetIP,
			RequestCount:     1,
			RequestersMACSet: make(map[string]bool),
			FirstSeen:        now,
			LastSeen:         now,
			IsActive:         true,
		}
		s.arpAnomalies[targetIP] = anomaly
	} else {
		anomaly.RequestCount++
		anomaly.LastSeen = now
	}

	anomaly.RequestersMACSet[srcMAC] = true
	anomaly.UniqueRequestersCount = len(anomaly.RequestersMACSet)
}

func (s *InMemoryStore) GetARPAnomalies(ctx context.Context) ([]domain.TargetARPAnomaly, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]domain.TargetARPAnomaly, 0, len(s.arpAnomalies))
	for _, a := range s.arpAnomalies {
		result = append(result, *a)
	}
	return result, nil
}

func (s *InMemoryStore) Cleanup(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for k, v := range s.stats {
		if now.Sub(v.LastUpdated) > ttl {
			delete(s.stats, k)
		}
	}
	// Ripetere logicamente per violations e arpAnomalies se necessario
}
