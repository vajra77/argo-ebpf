package models

type PeerRepository interface {
	Save(peer *Peer) error
	Update(peer *Peer) error
	RetrieveByMAC(mac string) (*Peer, error)
	RetrieveByASN(asn int) (*Peer, error)
}
