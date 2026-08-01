package models

type Repository interface {
	Save(peer *Peer) error
	Update(peer *Peer) error
	RetrieveByMAC(mac string) (*Peer, error)
	RetrieveByASN(asn int) (*Peer, error)
}
