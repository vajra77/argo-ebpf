package models

import (
	"github.com/google/uuid"
)

type Peer struct {
	ID           string   `bson:"_id" json:"id"`
	Name         string   `bson:"name" json:"name"`
	ASN          int      `bson:"asn" json:"asn"`
	MACs         []string `bson:"macs" json:"macs"`
	TotalPackets uint64   `bson:"total_packets" json:"total_packets"`
	TotalBytes   uint64   `bson:"total_bytes" json:"total_bytes"`
	Alerts       []Alert  `bson:"alerts" json:"alerts"`
	Pps          float64  `bson:"pps" json:"pps"`
	Bps          float64  `bson:"bps" json:"bps"`
}

func NewPeer(name string, asn int, macs []string) *Peer {
	return new(Peer{
		ID:     uuid.New().String(),
		Name:   name,
		ASN:    asn,
		MACs:   macs,
		Alerts: make([]Alert, 0),
	})
}
