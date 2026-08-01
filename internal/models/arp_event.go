package models

import "time"

type TargetARPAnomaly struct {
	TargetIP              string          `json:"target_ip"`
	TargetPeerName        string          `json:"target_peer_name,omitempty"`
	RequestCount          uint64          `json:"request_count"`
	UniqueRequestersCount int             `json:"unique_requesters_count"`
	RequestersMACSet      map[string]bool `json:"-"` // Utilizzato internamente per deduplicare i MAC
	FirstSeen             time.Time       `json:"first_seen"`
	LastSeen              time.Time       `json:"last_seen"`
	IsActive              bool            `json:"is_active"`
	DetectedAt            time.Time       `json:"detected_at"`
}
