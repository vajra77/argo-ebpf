/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package models

type Repository interface {
	Save(peer *Peer) error
	Update(peer *Peer) error
	RetrieveByMAC(mac string) (*Peer, error)
	RetrieveByASN(asn int) (*Peer, error)
}
