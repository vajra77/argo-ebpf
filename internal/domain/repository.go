package domain

import "context"

type MetricsRepository interface {
	UpsertStat(mac string, proto ProtocolType, packets, bytes uint64)
	GetTopBroadcasters(ctx context.Context, limit int) ([]PeerTrafficSummary, error)

	RecordViolation(v Violation)
	GetActiveViolations(ctx context.Context) ([]Violation, error)

	RecordARPRequest(srcMAC string, targetIP string)
	GetARPAnomalies(ctx context.Context) ([]TargetARPAnomaly, error)
}
