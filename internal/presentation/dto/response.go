package dto

import "time"

// Standard API Wrapper

type APIResponse struct {
	Success   bool        `json:"success"`
	Timestamp time.Time   `json:"timestamp"`
	Count     int         `json:"count"`
	Data      interface{} `json:"data"`
}

// Top Broadcaster Response Item

type BroadcasterItemDTO struct {
	PeerMAC      string            `json:"peer_mac"`
	PeerASN      int               `json:"peer_asn,omitempty"`
	PeerName     string            `json:"peer_name,omitempty"`
	TotalPackets uint64            `json:"total_packets"`
	TotalBytes   uint64            `json:"total_bytes"`
	PPS          float64           `json:"pps"`
	BPS          float64           `json:"bps"`
	Protocols    map[string]uint64 `json:"protocols_bytes"`
}

// Violation Response Item

type ViolationDTO struct {
	ID              string `json:"id"`
	PeerMAC         string `json:"peer_mac"`
	PeerASN         int    `json:"peer_asn,omitempty"`
	PeerName        string `json:"peer_name,omitempty"`
	SrcIP           string `json:"src_ip"`
	Type            string `json:"type"`
	Severity        string `json:"severity"`
	PacketCount     uint64 `json:"packet_count"`
	FirstSeen       string `json:"first_seen"`
	LastSeen        string `json:"last_seen"`
	SuggestedAction string `json:"suggested_action"`
}
