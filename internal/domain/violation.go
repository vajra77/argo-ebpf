package domain

import "time"

type ViolationType string

const (
	ViolationIPv6RA ViolationType = "IPV6_ROUTER_ADVERTISEMENT"
	ViolationMDNS   ViolationType = "MDNS_BROADCAST"
	ViolationLLMNR  ViolationType = "LLMNR_BROADCAST"
	ViolationCDP    ViolationType = "CDP_LLDP_FRAME"
)

type Severity string

const (
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

type Violation struct {
	ID              string        `json:"id"`
	PeerMAC         string        `json:"peer_mac"`
	PeerASN         int           `json:"peer_asn,omitempty"`
	PeerName        string        `json:"peer_name,omitempty"`
	SrcIP           string        `json:"src_ip"`
	Type            ViolationType `json:"type"`
	Severity        Severity      `json:"severity"`
	PacketCount     uint64        `json:"packet_count"`
	FirstSeen       time.Time     `json:"first_seen"`
	LastSeen        time.Time     `json:"last_seen"`
	SuggestedAction string        `json:"suggested_action"`
}
