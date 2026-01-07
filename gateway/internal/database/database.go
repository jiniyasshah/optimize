package database

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Connect initializes the MongoDB client and verifies the connection
func Connect(uri string) (*mongo.Client, error) {
	// 1. Create a context with a 10-second timeout
	// This ensures your app doesn't hang forever if the DB is down
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 2. Configure the client
	clientOptions := options.Client().ApplyURI(uri)
	
	// 3. Connect
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, err
	}

	// 4. Ping the database to verify the connection is actually alive
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	return client, nil
}