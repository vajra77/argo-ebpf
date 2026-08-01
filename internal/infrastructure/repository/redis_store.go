package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"argo-ebpf/internal/models"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	client *redis.Client
	ctx    context.Context
	ttl    time.Duration
}

func (s *RedisStore) AddPeer(name string, asn int, macs []string) error {
	peerKey := fmt.Sprintf("peer:asn:%d", asn)

	// Creiamo o recuperiamo il peer
	peer := new(models.Peer{
		Name:         name,
		ASN:          asn,
		MACs:         macs,
		Alerts:       make(map[string][]models.Alert),
		TotalPackets: 0,
		TotalBytes:   0,
	})

	data, err := json.Marshal(peer)
	if err != nil {
		return err
	}

	// Usiamo una Pipeline per garantire l'atomicità delle operazioni di mapping
	pipe := s.client.Pipeline()
	pipe.Set(s.ctx, peerKey, data, s.ttl)

	for _, mac := range macs {
		macKey := fmt.Sprintf("peer:mac:%s", mac)
		pipe.Set(s.ctx, macKey, asn, s.ttl)
	}

	_, err = pipe.Exec(s.ctx)
	return err
}

func (s *RedisStore) GetPeerByMAC(mac string) (*models.Peer, error) {
	macKey := fmt.Sprintf("peer:mac:%s", mac)

	asn, err := s.client.Get(s.ctx, macKey).Int()
	if errors.Is(err, redis.Nil) {
		// Logica UnknownMACs
		s.client.SAdd(s.ctx, "peers:unknown_macs", mac)
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return s.GetPeerByASN(asn)
}

func (s *RedisStore) GetPeerByASN(asn int) (*models.Peer, error) {
	peerKey := fmt.Sprintf("peer:asn:%d", asn)

	data, err := s.client.Get(s.ctx, peerKey).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	var peer models.Peer
	if err := json.Unmarshal(data, &peer); err != nil {
		return nil, err
	}

	return &peer, nil
}

func (s *RedisStore) AddPeerAlert(mac string, alert models.Alert) error {
	peer, err := s.GetPeerByMAC(mac)
	if err != nil || peer == nil {
		return fmt.Errorf("peer not found for mac %s", mac)
	}

	if peer.Alerts == nil {
		peer.Alerts = make(map[string][]models.Alert)
	}

	peer.Alerts[string(alert.Type)] = append(peer.Alerts[string(alert.Type)], alert)

	// Riassegniamo i dati aggiornati
	peerKey := fmt.Sprintf("peer:asn:%d", peer.ASN)
	data, _ := json.Marshal(peer)

	return s.client.Set(s.ctx, peerKey, data, s.ttl).Err()
}
