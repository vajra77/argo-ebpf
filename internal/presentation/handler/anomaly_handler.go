package handler

import (
	"net/http"
	"time"

	"argo-ebpf/internal/domain"
	"argo-ebpf/internal/presentation/dto"
)

type AnomalyHandler struct {
	repo domain.MetricsRepository
}

func NewAnomalyHandler(repo domain.MetricsRepository) *AnomalyHandler {
	return &AnomalyHandler{repo: repo}
}

func (h *AnomalyHandler) GetARPAnomalies(w http.ResponseWriter, r *http.Request) {
	anomalies, err := h.repo.GetARPAnomalies(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to retrieve ARP anomalies")
		return
	}

	writeJSONResponse(w, http.StatusOK, dto.APIResponse{
		Success:   true,
		Timestamp: time.Now(),
		Count:     len(anomalies),
		Data:      anomalies,
	})
}
