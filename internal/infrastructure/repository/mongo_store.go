/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package repository

import (
	"context"
	"fmt"

	"argo-ebpf/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoStore struct {
	collection *mongo.Collection
	ctx        context.Context
}

func NewMongoStore(client *mongo.Client, dbName, collName string) *MongoStore {
	return &MongoStore{
		collection: client.Database(dbName).Collection(collName),
		ctx:        context.Background(),
	}
}

// Save inserisce un nuovo peer. Usiamo Upsert per gestire eventuali duplicati
func (m *MongoStore) Save(peer *models.Peer) error {
	filter := bson.M{"asn": peer.ASN}
	update := bson.M{"$set": peer}
	opts := options.Update().SetUpsert(true)

	_, err := m.collection.UpdateOne(m.ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to save peer to mongo: %w", err)
	}
	return nil
}

// Update aggiorna il documento esistente filtrando per ASN
func (m *MongoStore) Update(peer *models.Peer) error {
	filter := bson.M{"asn": peer.ASN}
	update := bson.M{"$set": peer}

	_, err := m.collection.UpdateOne(m.ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update peer in mongo: %w", err)
	}
	return nil
}

// RetrieveByMAC cerca un peer che contenga il MAC specificato nell'array macs
func (m *MongoStore) RetrieveByMAC(mac string) (*models.Peer, error) {
	var peer models.Peer
	filter := bson.M{"macs": mac}

	err := m.collection.FindOne(m.ctx, filter).Decode(&peer)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &peer, nil
}

// RetrieveByASN cerca un peer per il suo ASN
func (m *MongoStore) RetrieveByASN(asn int) (*models.Peer, error) {
	var peer models.Peer
	filter := bson.M{"asn": asn}

	err := m.collection.FindOne(m.ctx, filter).Decode(&peer)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &peer, nil
}
