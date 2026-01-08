package mongo

import (
	"context"
	"errors"
	"time"

	"web-app-firewall-ml-detection/internal/core"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserRepository struct {
	db *mongo.Database
}

func NewUserRepository(client *mongo.Client) *UserRepository {
	return &UserRepository{
		db: client.Database("waf"),
	}
}

func (r *UserRepository) Create(ctx context.Context, user core.User) error {
	// Check duplicate
	var existing core.User
	err := r.db.Collection("users").FindOne(ctx, bson.M{"email": user.Email}).Decode(&existing)
	if err == nil {
		return errors.New("email already registered")
	}

	if user.ID == "" {
		user.ID = primitive.NewObjectID().Hex()
	}
	user.CreatedAt = time.Now()

	_, err = r.db.Collection("users").InsertOne(ctx, user)
	return err
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*core.User, error) {
	var user core.User
	err := r.db.Collection("users").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*core.User, error) {
	var user core.User
	err := r.db.Collection("users").FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

