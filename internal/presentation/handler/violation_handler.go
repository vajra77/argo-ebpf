package handler

import (
	"net/http"
	"time"

	"argo-ebpf/internal/domain"
	"argo-ebpf/internal/presentation/dto"
)

type ViolationHandler struct {
	repo domain.MetricsRepository
}

func NewViolationHandler(repo domain.MetricsRepository) *ViolationHandler {
	return &ViolationHandler{repo: repo}
}

func (h *ViolationHandler) GetActiveViolations(w http.ResponseWriter, r *http.Request) {
	violations, err := h.repo.GetActiveViolations(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to retrieve policy violations")
		return
	}

	items := make([]dto.ViolationDTO, 0, len(violations))
	for _, v := range violations {
		items = append(items, dto.ViolationDTO{
			ID:              v.ID,
			PeerMAC:         v.PeerMAC,
			PeerASN:         v.PeerASN,
			PeerName:        v.PeerName,
			SrcIP:           v.SrcIP,
			Type:            string(v.Type),
			Severity:        string(v.Severity),
			PacketCount:     v.PacketCount,
			FirstSeen:       v.FirstSeen.Format(time.RFC3339),
			LastSeen:        v.LastSeen.Format(time.RFC3339),
			SuggestedAction: v.SuggestedAction,
		})
	}

	writeJSONResponse(w, http.StatusOK, dto.APIResponse{
		Success:   true,
		Timestamp: time.Now(),
		Count:     len(items),
		Data:      items,
	})
}
