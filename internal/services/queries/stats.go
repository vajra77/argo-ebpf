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
	"argo-ebpf/internal/domain/stats"
	"fmt"
)

type StatsQueryService struct {
	repo stats.Repository
}

func NewStatsQueryService(repo stats.Repository) *StatsQueryService {
	return new(StatsQueryService{repo: repo})
}

func (s *StatsQueryService) Get() ([]byte, error) {
	p, err := s.repo.Retrieve()
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("stats not found")
	}

	return p.MarshalJSON()
}
