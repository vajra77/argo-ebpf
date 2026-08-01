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
	"argo-ebpf/internal/api/dto"
	"encoding/json"
	"net/http"
	"time"
)

// Helpers di scrittura JSON
func writeJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSONResponse(w, status, dto.APIResponse{
		Success:   false,
		Timestamp: time.Now(),
		Data:      map[string]string{"error": message},
	})
}
