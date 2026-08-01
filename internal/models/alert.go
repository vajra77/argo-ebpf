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
	SrcIP           string    `json:"src_ip"`
	Type            AlertType `json:"type"`
	Severity        Severity  `json:"severity"`
	SuggestedAction string    `json:"suggested_action"`
	PacketCount     uint64    `json:"packet_count"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

func NewAlert(id string, srcMAC, srcIP string, alertType AlertType, severity Severity, sugg string) *Alert {
	now := time.Now()
	return new(Alert{
		ID:              id,
		PeerMAC:         srcMAC,
		SrcIP:           srcIP,
		Type:            alertType,
		Severity:        severity,
		SuggestedAction: sugg,
		PacketCount:     1,
		FirstSeen:       now,
		LastSeen:        now,
	})
}

func (a Alert) Update() {
	a.PacketCount++
	a.LastSeen = time.Now()
}
