package models

import "time"

// BroadcastStat rappresenta un singolo record grezzo accumulato dalla mappa eBPF
type BroadcastStat struct {
	PeerMAC     string       `json:"peer_mac"`
	Protocol    ProtocolType `json:"protocol"`
	Packets     uint64       `json:"packets"`
	Bytes       uint64       `json:"bytes"`
	LastPackets uint64       `json:"last_packets"`
	LastBytes   uint64       `json:"last_bytes"`
	PacketRate  float64      `json:"packet_rate"`
	ByteRate    float64      `json:"byte_rate"`
	LastUpdated time.Time    `json:"last_updated"`
}

type TrafficVolume struct {
	Packets    uint64  `json:"packets"`
	Bytes      uint64  `json:"bytes"`
	PacketRate float64 `json:"packet_rate"`
	ByteRate   float64 `json:"byte_rate"`
}
