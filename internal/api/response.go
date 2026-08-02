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
	"encoding/json"
	"net/http"
)

type Response struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Content any    `json:"content"`
}

func ResponseJSON(w http.ResponseWriter, status int, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Response{
		Status:  status,
		Message: "ok",
		Content: data,
	})
}

func ResponseIntError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func ResponseNotFound(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusNotFound)
}

func ResponseReqError(w http.ResponseWriter, reason string) {
	http.Error(w, reason, http.StatusBadRequest)
}

func ResponseForbidden(w http.ResponseWriter, reason string) {
	http.Error(w, reason, http.StatusForbidden)
}
