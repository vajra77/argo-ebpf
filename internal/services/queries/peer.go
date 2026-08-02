/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package queries

import (
	"argo-ebpf/internal/domain/peer"
	"fmt"
)

type PeerQueryService struct {
	repo peer.Repository
}

func NewPeerQueryService(repo peer.Repository) *PeerQueryService {
	return new(PeerQueryService{repo: repo})
}

func (s *PeerQueryService) GetPeerByASN(asn int) ([]byte, error) {
	p, err := s.repo.RetrieveByASN(asn)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("peer not found: AS%d", asn)
	}

	return p.MarshalJSON()
}
