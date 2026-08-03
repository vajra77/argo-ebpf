/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package peer

import (
	"encoding/json"
	"time"
)

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

// Alert represents a network alert (a security event detected by the system)
type Alert struct {
	id              string
	peerMAC         string
	srcIP           string
	alertType       AlertType
	severity        Severity
	suggestedAction string
	packetCount     uint64
	firstSeen       time.Time
	lastSeen        time.Time
}

// Getters

func (a *Alert) ID() string {
	return a.id
}

func (a *Alert) PeerMAC() string {
	return a.peerMAC
}

func (a *Alert) SrcIP() string {
	return a.srcIP
}

func (a *Alert) AlertType() AlertType {
	return a.alertType
}

func (a *Alert) Severity() Severity {
	return a.severity
}

func (a *Alert) SuggestedAction() string {
	return a.suggestedAction
}

func (a *Alert) PacketCount() uint64 {
	return a.packetCount
}

func (a *Alert) FirstSeen() time.Time {
	return a.firstSeen
}

func (a *Alert) LastSeen() time.Time {
	return a.lastSeen
}

// MarshalJSON marshals an Alert to JSON
func (a *Alert) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID              string    `json:"id"`
		PeerMAC         string    `json:"peer_mac"`
		SrcIP           string    `json:"src_ip"`
		AlertType       AlertType `json:"type"`
		Severity        Severity  `json:"severity"`
		SuggestedAction string    `json:"suggested_action"`
		PacketCount     uint64    `json:"packet_count"`
		FirstSeen       time.Time `json:"first_seen"`
		LastSeen        time.Time `json:"last_seen"`
	}{
		ID:              a.id,
		PeerMAC:         a.peerMAC,
		SrcIP:           a.srcIP,
		AlertType:       a.alertType,
		Severity:        a.severity,
		SuggestedAction: a.suggestedAction,
		PacketCount:     a.packetCount,
		FirstSeen:       a.firstSeen,
		LastSeen:        a.lastSeen,
	})
}

// UnmarshalJSON unmarshals an Alert from JSON
func (a *Alert) UnmarshalJSON(data []byte) error {
	aux := &struct {
		ID              string    `json:"id"`
		PeerMAC         string    `json:"peer_mac"`
		SrcIP           string    `json:"src_ip"`
		AlertType       AlertType `json:"type"`
		Severity        Severity  `json:"severity"`
		SuggestedAction string    `json:"suggested_action"`
		PacketCount     uint64    `json:"packet_count"`
		FirstSeen       time.Time `json:"first_seen"`
		LastSeen        time.Time `json:"last_seen"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	a.id = aux.ID
	a.peerMAC = aux.PeerMAC
	a.srcIP = aux.SrcIP
	a.alertType = aux.AlertType
	a.severity = aux.Severity
	a.suggestedAction = aux.SuggestedAction
	a.packetCount = aux.PacketCount
	a.firstSeen = aux.FirstSeen
	a.lastSeen = aux.LastSeen

	return nil
}

// NewAlert creates a new Alert instance
func NewAlert(id string, srcMAC, srcIP string, alertType AlertType, severity Severity, sugg string) *Alert {
	now := time.Now()
	return new(Alert{
		id:              id,
		peerMAC:         srcMAC,
		srcIP:           srcIP,
		alertType:       alertType,
		severity:        severity,
		suggestedAction: sugg,
		packetCount:     1,
		firstSeen:       now,
		lastSeen:        now,
	})
}

// Update updates an existing alert
func (a *Alert) Update() {
	a.packetCount++
	a.lastSeen = time.Now()
}
