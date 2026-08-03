/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package api

import (
	"argo-ebpf/internal/services/queries"
	"net/http"
)

type StatsAPI struct {
	auth    *AuthMiddleware
	queries *queries.StatsQueryService
}

func NewStatsAPI(qs *queries.StatsQueryService, keys []string) *StatsAPI {
	return new(StatsAPI{
		auth:    NewAuthMiddleware(keys),
		queries: qs,
	})
}

func (api *StatsAPI) RegisterRoutes(mux *http.ServeMux, basePath string) {
	mux.HandleFunc("GET "+basePath+"/stats", api.auth.RequireReadAccess(api.handleGet))
}

func (api *StatsAPI) handleGet(w http.ResponseWriter, _ *http.Request) {
	data, err := api.queries.Get()
	if err != nil {
		ResponseIntError(w, err)
		return
	}

	ResponseJSON(w, http.StatusOK, data)
}
