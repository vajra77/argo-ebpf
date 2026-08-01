package models

import "context"

type MetricsRepository interface {
	UpsertStat(mac string, proto ProtocolType, packets, bytes uint64)
	GetTopBroadcasters(ctx context.Context, limit int) ([]PeerTrafficSummary, error)

	RecordAlert(a Alert)
	GetActiveAlerts(ctx context.Context) ([]Alert, error)

	RecordARPRequest(srcMAC string, targetIP string)
	GetARPAnomalies(ctx context.Context) ([]TargetARPAnomaly, error)
}
