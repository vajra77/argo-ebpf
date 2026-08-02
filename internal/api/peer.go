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
	"strconv"
)

type PeerAPI struct {
	auth    *AuthMiddleware
	queries *queries.PeerQueryService
}

func NewPeerAPI(qs *queries.PeerQueryService, keys []string) *PeerAPI {
	return new(PeerAPI{
		auth:    NewAuthMiddleware(keys),
		queries: qs,
	})
}

func (api *PeerAPI) RegisterRoutes(mux *http.ServeMux, basePath string) {
	mux.HandleFunc("GET "+basePath+"/peer/{asn}", api.auth.RequireReadAccess(api.handleGetPeerByASN))
}

func (api *PeerAPI) handleGetPeerByASN(w http.ResponseWriter, r *http.Request) {
	asnStr := r.PathValue("asn")
	if asnStr == "" {
		ResponseReqError(w, "missing asn")
		return
	}

	asn, err := strconv.Atoi(asnStr)
	if err != nil {
		ResponseReqError(w, "invalid asn")
		return
	}

	data, err := api.queries.GetPeerByASN(asn)
	if err != nil {
		ResponseIntError(w, err)
		return
	}

	ResponseJSON(w, http.StatusOK, data)
}
