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
	"net/http"
	"slices"
)

type AuthMiddleware struct {
	roKeys []string
}

func NewAuthMiddleware(keys []string) *AuthMiddleware {
	return new(AuthMiddleware{roKeys: keys})
}

// RequireReadAccess è l'equivalente di @api_auth_read (API Key OR Valid JWT)
func (m *AuthMiddleware) RequireReadAccess(next http.HandlerFunc) http.HandlerFunc {
	return m.baseAuth(next, m.roKeys)
}

// baseAuth contiene la logica condivisa per leggere API Key o decodificare JWT
func (m *AuthMiddleware) baseAuth(next http.HandlerFunc, allowedKeys []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Controllo API Key
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" {
			if slices.Contains(allowedKeys, apiKey) {
				next(w, r)
				return
			}
			// Se c'è un'API Key ma è invalida, per sicurezza interrompiamo
			ResponseForbidden(w, "invalid API key")
			return
		}

		ResponseForbidden(w, "missing API key")
		return
	}
}
