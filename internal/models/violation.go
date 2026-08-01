package models

import "time"

type AlertType string

const (
	AlertIPv6RA AlertType = "IPV6_ROUTER_ADVERTISEMENT"
	AlertMDNS   AlertType = "MDNS_BROADCAST"
	AlertLLMNR  AlertType = "LLMNR_BROADCAST"
	AlertCDP    AlertType = "CDP_LLDP_FRAME"
)

type Severity string

const (
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

type Alert struct {
	ID              string    `json:"id"`
	PeerMAC         string    `json:"peer_mac"`
	PeerASN         int       `json:"peer_asn,omitempty"`
	PeerName        string    `json:"peer_name,omitempty"`
	SrcIP           string    `json:"src_ip"`
	Type            AlertType `json:"type"`
	Severity        Severity  `json:"severity"`
	PacketCount     uint64    `json:"packet_count"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	SuggestedAction string    `json:"suggested_action"`
}
