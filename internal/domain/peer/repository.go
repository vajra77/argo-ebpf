/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package peer

// Repository interface defines the methods for interacting with the peer repository
type Repository interface {
	Upsert(p *Peer) error
	RetrieveByMAC(mac string) (*Peer, error)
	RetrieveByASN(asn int) (*Peer, error)
}
