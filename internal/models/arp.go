package models

import "time"

type ARPRequest struct {
	ID          string
	SrcMAC      string
	TargetIP    string
	PacketCount uint64
	FirstSeen   time.Time
	LastSeen    time.Time
}

func NewARPRequest(id, srcMAC, targetIP string) *ARPRequest {
	now := time.Now()
	return new(ARPRequest{
		ID:          id,
		SrcMAC:      srcMAC,
		TargetIP:    targetIP,
		PacketCount: 1,
		FirstSeen:   now,
		LastSeen:    now,
	})
}

func (a *ARPRequest) Update() {
	a.PacketCount++
	a.LastSeen = time.Now()
}
