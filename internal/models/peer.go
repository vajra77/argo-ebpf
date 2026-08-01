package models

import (
	"slices"
	"sync"
)

// PeerTrafficSummary rappresenta l'aggregazione di tutto il traffico generato da uno specifico MAC
type PeerTrafficSummary struct {
	PeerMAC      string                         `json:"peer_mac"`
	PeerASN      int                            `json:"peer_asn,omitempty"`
	PeerName     string                         `json:"peer_name,omitempty"`
	TotalPackets uint64                         `json:"total_packets"`
	TotalBytes   uint64                         `json:"total_bytes"`
	Protocols    map[ProtocolType]TrafficVolume `json:"protocols"`
}

type Peer struct {
	Name         string             `json:"name"`
	ASN          int                `json:"asn"`
	MACs         []string           `json:"macs"`
	TotalPackets uint64             `json:"total_packets"`
	TotalBytes   uint64             `json:"total_bytes"`
	Alerts       map[string][]Alert `json:"alerts"`
	Pps          float64            `json:"pps"`
	Bps          float64            `json:"bps"`
}

type PeerMap struct {
	Peers       map[int]*Peer `json:"peers"`
	MACs        map[string]*Peer
	UnknownMACs []string

	mu sync.RWMutex
}

func NewPeerMap() *PeerMap {
	return new(PeerMap{
		Peers:       make(map[int]*Peer),
		MACs:        make(map[string]*Peer),
		UnknownMACs: make([]string, 0),
	})
}

func (pm *PeerMap) AddPeerAlert(alert Alert) {

}

func (pm *PeerMap) GetPeerByMAC(mac string) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if _, exists := pm.MACs[mac]; !exists {
		if !slices.Contains(pm.UnknownMACs, mac) {
			pm.UnknownMACs = append(pm.UnknownMACs, mac)
		}
		return nil
	}
	return pm.MACs[mac]
}

func (pm *PeerMap) GetPeerByASN(asn int) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if _, exists := pm.Peers[asn]; !exists {
		return nil
	}
	return pm.Peers[asn]
}
