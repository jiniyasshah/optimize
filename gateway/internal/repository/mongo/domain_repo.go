package mongo

import (
	"context"
	"time"

	"web-app-firewall-ml-detection/internal/core"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type DomainRepository struct {
	db *mongo.Database
}

func NewDomainRepository(client *mongo.Client) *DomainRepository {
	return &DomainRepository{
		db: client.Database("waf"),
	}
}

// --- Domain Methods ---

func (r *DomainRepository) Create(ctx context.Context, domain core.Domain) (core.Domain, error) {
	if domain.ID == "" {
		domain.ID = primitive.NewObjectID().Hex()
	}
	domain.CreatedAt = time.Now()
	_, err := r.db.Collection("domains").InsertOne(ctx, domain)
	return domain, err
}

func (r *DomainRepository) GetByUser(ctx context.Context, userID string) ([]core.Domain, error) {
	cursor, err := r.db.Collection("domains").Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var domains []core.Domain
	err = cursor.All(ctx, &domains)
	return domains, err
}

func (r *DomainRepository) GetByName(ctx context.Context, name string) (*core.Domain, error) {
	var domain core.Domain
	// Only active domains
	err := r.db.Collection("domains").FindOne(ctx, bson.M{"name": name, "status": "active"}).Decode(&domain)
	if err != nil {
		return nil, err
	}
	return &domain, nil
}

func (r *DomainRepository) GetByID(ctx context.Context, id string) (*core.Domain, error) {
	var domain core.Domain
	err := r.db.Collection("domains").FindOne(ctx, bson.M{"_id": id}).Decode(&domain)
	if err != nil {
		return nil, err
	}
	return &domain, nil
}

func (r *DomainRepository) UpdateStatus(ctx context.Context, id, status string) error {
	_, err := r.db.Collection("domains").UpdateOne(ctx, bson.M{"_id": id}, bson.M{
		"$set": bson.M{"status": status, "updated_at": time.Now()},
	})
	return err
}

func (r *DomainRepository) RevokeOldOwnership(ctx context.Context, name, newOwnerID string) error {
	filter := bson.M{
		"name": name,
		"_id":  bson.M{"$ne": newOwnerID},
	}
	_, err := r.db.Collection("domains").DeleteMany(ctx, filter)
	return err
}

func (r *DomainRepository) GetAll(ctx context.Context) ([]core.Domain, error) {
	cursor, err := r.db.Collection("domains").Find(ctx, bson.M{})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	var domains []core.Domain
	err = cursor.All(ctx, &domains)
	return domains, err
}

// --- DNS Methods ---

func (r *DomainRepository) CreateRecord(ctx context.Context, record core.DNSRecord) (string, error) {
	if record.ID == "" {
		record.ID = primitive.NewObjectID().Hex()
	}
	record.CreatedAt = time.Now()
	_, err := r.db.Collection("dns_records").InsertOne(ctx, record)
	return record.ID, err
}

func (r *DomainRepository) GetRecords(ctx context.Context, domainID string) ([]core.DNSRecord, error) {
	cursor, err := r.db.Collection("dns_records").Find(ctx, bson.M{"domain_id": domainID})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	var records []core.DNSRecord
	err = cursor.All(ctx, &records)
	if records == nil { records = []core.DNSRecord{} }
	return records, err
}

func (r *DomainRepository) GetRecordByID(ctx context.Context, id string) (*core.DNSRecord, error) {
	var record core.DNSRecord
	err := r.db.Collection("dns_records").FindOne(ctx, bson.M{"_id": id}).Decode(&record)
	return &record, err
}

func (r *DomainRepository) DeleteRecord(ctx context.Context, id string) error {
	_, err := r.db.Collection("dns_records").DeleteOne(ctx, bson.M{"_id": id})
	return err
}

func (r *DomainRepository) UpdateRecordProxy(ctx context.Context, id string, proxied bool) error {
	_, err := r.db.Collection("dns_records").UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"proxied": proxied}})
	return err
}

func (r *DomainRepository) UpdateRecordSSL(ctx context.Context, id string, ssl bool) error {
	_, err := r.db.Collection("dns_records").UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"origin_ssl": ssl}})
	return err
}

func (r *DomainRepository) CheckDuplicateRecord(ctx context.Context, domainID, name, rType, content string) (bool, error) {
	err := r.db.Collection("dns_records").FindOne(ctx, bson.M{
		"domain_id": domainID, "name": name, "type": rType, "content": content,
	}).Err()
	if err == mongo.ErrNoDocuments { return false, nil }
	return err == nil, err
}

func (r *DomainRepository) GetAllRecords(ctx context.Context) ([]core.DNSRecord, error) {
	cursor, err := r.db.Collection("dns_records").Find(ctx, bson.M{})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	var records []core.DNSRecord
	err = cursor.All(ctx, &records)
	return records, err
}

func (r *DomainRepository) GetOriginRecord(ctx context.Context, host string) (*core.DNSRecord, error) {
	var record core.DNSRecord
	// Try A record first
	err := r.db.Collection("dns_records").FindOne(ctx, bson.M{"name": host, "type": "A"}).Decode(&record)
	if err == nil { return &record, nil }
	
	// Try CNAME
	err = r.db.Collection("dns_records").FindOne(ctx, bson.M{"name": host, "type": "CNAME"}).Decode(&record)
	if err == nil { return &record, nil }
	
	return nil, err
}