package presentation

import (
	"net/http"

	"argo-ebpf/internal/domain"
	"argo-ebpf/internal/presentation/handler"
)

func NewRouter(repo domain.MetricsRepository) http.Handler {
	mux := http.NewServeMux()

	broadcasterH := handler.NewBroadcasterHandler(repo)
	violationH := handler.NewViolationHandler(repo)
	anomalyH := handler.NewAnomalyHandler(repo)

	// Registrazione delle Rotte REST
	mux.HandleFunc("/api/v1/broadcasters/top", broadcasterH.GetTopBroadcasters)
	mux.HandleFunc("/api/v1/violations", violationH.GetActiveViolations)
	mux.HandleFunc("/api/v1/anomalies/arp", anomalyH.GetARPAnomalies)

	// Healthcheck endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Wrap con Middleware CORS
	return enableCORS(mux)
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
