package domain

import "context"

type MetricsRepository interface {
	// Metriche aggregate
	UpsertStat(mac string, proto ProtocolType, packets, bytes uint64)
	GetTopBroadcasters(ctx context.Context, limit int) ([]PeerTrafficSummary, error)

	// Violazioni di protocollo
	RecordViolation(v Violation)
	GetActiveViolations(ctx context.Context) ([]Violation, error)

	// ARP Target Anomalies (Peer Down)
	RecordARPRequest(srcMAC string, targetIP string)
	GetARPAnomalies(ctx context.Context) ([]TargetARPAnomaly, error)
}
