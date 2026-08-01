package repository

import (
	"argo-ebpf/internal/domain"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	client *redis.Client
	ctx    context.Context
	ttl    time.Duration
}

func NewRedisStore(addr string, password string, db int) *RedisStore {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return &RedisStore{
		client: rdb,
		ctx:    context.Background(),
		ttl:    24 * time.Hour, // TTL di default per i dati
	}
}

func (r *RedisStore) UpsertStat(mac string, proto domain.ProtocolType, packets, bytes uint64) {
	key := fmt.Sprintf("stats:%s:%d", mac, proto)
	now := time.Now()

	// 1. Recupera lo stato precedente
	val, err := r.client.Get(r.ctx, key).Result()

	var stat domain.BroadcastStat
	if err == nil {
		_ = json.Unmarshal([]byte(val), &stat)

		duration := now.Sub(stat.LastUpdated).Seconds()
		if duration > 0 {
			// Calcolo Rate (PPS / BPS)
			stat.PacketRate = float64(packets-stat.Packets) / duration
			stat.ByteRate = float64(bytes-stat.Bytes) / duration
		}
		stat.Packets = packets
		stat.Bytes = bytes
		stat.LastUpdated = now
	} else {
		// Nuovo record
		stat = domain.BroadcastStat{
			PeerMAC:     mac,
			Protocol:    proto,
			Packets:     packets,
			Bytes:       bytes,
			LastUpdated: now,
		}
	}

	// 2. Salva in Redis
	data, _ := json.Marshal(stat)
	r.client.Set(r.ctx, key, data, r.ttl)

	// 3. (Opzionale) Aggiorna uno ZSET per la classifica dei Broadcaster
	r.client.ZAdd(r.ctx, "broadcasters:total_bytes", redis.Z{
		Score:  float64(bytes),
		Member: mac,
	})
}

func (r *RedisStore) RecordViolation(v domain.Violation) {
	key := fmt.Sprintf("violation:%s:%s", v.PeerMAC, v.Type)

	// Utilizziamo un approccio atomico o leggiamo/modifichiamo
	val, err := r.client.Get(r.ctx, key).Result()

	var existing domain.Violation
	if err == nil {
		_ = json.Unmarshal([]byte(val), &existing)
		existing.PacketCount++
		existing.LastSeen = time.Now()
		existing.SrcIP = v.SrcIP
		v = existing
	} else {
		v.FirstSeen = time.Now()
		v.LastSeen = time.Now()
		v.PacketCount = 1
	}

	data, _ := json.Marshal(v)
	r.client.Set(r.ctx, key, data, r.ttl)
}

func (r *RedisStore) GetTopBroadcasters(ctx context.Context, limit int) ([]domain.PeerTrafficSummary, error) {
	// 1. Prendi i MAC con più traffico dallo ZSET
	macs, err := r.client.ZRangeArgs(ctx, redis.ZRangeArgs{
		Key:   "broadcasters:total_bytes",
		Start: 0,
		Stop:  int64(limit - 1),
		Rev:   true,
	}).Result()

	if err != nil {
		return nil, err
	}

	result := make([]domain.PeerTrafficSummary, 0, len(macs))
	for _, mac := range macs {
		summary := domain.PeerTrafficSummary{
			PeerMAC:   mac,
			Protocols: make(map[domain.ProtocolType]domain.TrafficVolume),
		}

		// 2. Recupera tutte le chiavi stats per questo MAC (tutti i protocolli)
		pattern := fmt.Sprintf("stats:%s:*", mac)
		keys, _ := r.client.Keys(ctx, pattern).Result()

		for _, k := range keys {
			val, _ := r.client.Get(ctx, k).Result()
			var stat domain.BroadcastStat
			if err := json.Unmarshal([]byte(val), &stat); err == nil {
				summary.TotalPackets += stat.Packets
				summary.TotalBytes += stat.Bytes
				summary.Protocols[stat.Protocol] = domain.TrafficVolume{
					Packets:    stat.Packets,
					Bytes:      stat.Bytes,
					PacketRate: stat.PacketRate,
					ByteRate:   stat.ByteRate,
				}
			}
		}
		result = append(result, summary)
	}
	return result, nil
}

func (r *RedisStore) GetActiveViolations(ctx context.Context) ([]domain.Violation, error) {
	keys, err := r.client.SMembers(ctx, "active_violations").Result()
	if err != nil {
		return nil, err
	}

	result := make([]domain.Violation, 0, len(keys))
	for _, k := range keys {
		val, err := r.client.Get(ctx, k).Result()
		if errors.Is(err, redis.Nil) {
			r.client.SRem(ctx, "active_violations", k) // Pulizia indice se TTL scaduto
			continue
		}
		var v domain.Violation
		if err := json.Unmarshal([]byte(val), &v); err == nil {
			result = append(result, v)
		}
	}
	return result, nil
}

func (r *RedisStore) RecordARPRequest(srcMAC string, targetIP string) {
	key := fmt.Sprintf("arp_anomaly:%s", targetIP)

	val, err := r.client.Get(r.ctx, key).Result()
	var anomaly domain.TargetARPAnomaly

	if err == nil {
		_ = json.Unmarshal([]byte(val), &anomaly)
		anomaly.RequestCount++
		anomaly.LastSeen = time.Now()
	} else {
		anomaly = domain.TargetARPAnomaly{
			TargetIP:         targetIP,
			RequestCount:     1,
			RequestersMACSet: make(map[string]bool),
			FirstSeen:        time.Now(),
			LastSeen:         time.Now(),
			IsActive:         true,
		}
	}

	anomaly.RequestersMACSet[srcMAC] = true
	anomaly.UniqueRequestersCount = len(anomaly.RequestersMACSet)

	data, _ := json.Marshal(anomaly)
	r.client.Set(r.ctx, key, data, r.ttl)
	r.client.SAdd(r.ctx, "active_arp_anomalies", key)
}

func (r *RedisStore) GetARPAnomalies(ctx context.Context) ([]domain.TargetARPAnomaly, error) {
	keys, err := r.client.SMembers(ctx, "active_arp_anomalies").Result()
	if err != nil {
		return nil, err
	}

	result := make([]domain.TargetARPAnomaly, 0, len(keys))
	for _, k := range keys {
		val, err := r.client.Get(ctx, k).Result()
		if errors.Is(err, redis.Nil) {
			r.client.SRem(ctx, "active_arp_anomalies", k)
			continue
		}
		var a domain.TargetARPAnomaly
		if err := json.Unmarshal([]byte(val), &a); err == nil {
			result = append(result, a)
		}
	}
	return result, nil
}
