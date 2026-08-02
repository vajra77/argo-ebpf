/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package handler

import (
	"net/http"
	"strconv"
	"time"

	"argo-ebpf/internal/api/dto"
	"argo-ebpf/internal/domain"
)

type BroadcasterHandler struct {
	repo domain.MetricsRepository
}

func NewBroadcasterHandler(repo domain.MetricsRepository) *BroadcasterHandler {
	return &BroadcasterHandler{repo: repo}
}

func (h *BroadcasterHandler) GetTopBroadcasters(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 10
	if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
		limit = parsedLimit
	}

	summaries, err := h.repo.GetTopBroadcasters(r.Context(), limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to retrieve broadcasters metrics")
		return
	}

	// Mappatura verso DTO
	items := make([]dto.BroadcasterItemDTO, 0, len(summaries))
	for _, s := range summaries {
		protoMap := make(map[string]uint64)
		for proto, vol := range s.Protocols {
			protoMap[proto.String()] = vol.Bytes
		}

		items = append(items, dto.BroadcasterItemDTO{
			PeerMAC:      s.PeerMAC,
			PeerASN:      s.PeerASN,
			PeerName:     s.PeerName,
			TotalPackets: s.TotalPackets,
			TotalBytes:   s.TotalBytes,
			Protocols:    protoMap,
		})
	}

	writeJSONResponse(w, http.StatusOK, dto.APIResponse{
		Success:   true,
		Timestamp: time.Now(),
		Count:     len(items),
		Data:      items,
	})
}
