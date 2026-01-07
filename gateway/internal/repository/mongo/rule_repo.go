package mongo

import (
	"context"
	"errors"
	"log"
	"regexp"

	"web-app-firewall-ml-detection/internal/core"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type RuleRepository struct {
	db *mongo.Database
}

func NewRuleRepository(client *mongo.Client) *RuleRepository {
	return &RuleRepository{
		db: client.Database("waf"),
	}
}

func (r *RuleRepository) GetAll(ctx context.Context) ([]core.WAFRule, error) {
	opts := options.Find().SetSort(bson.D{{Key: "_id", Value: 1}})
	cursor, err := r.db.Collection("rules").Find(ctx, bson.M{}, opts)
	if err != nil { return nil, err }
	defer cursor.Close(ctx)

	var rules []core.WAFRule
	if err = cursor.All(ctx, &rules); err != nil { return nil, err }
	
	// Compile Regexes before returning
	for i := range rules {
		for j := range rules[i].Conditions {
			cond := &rules[i].Conditions[j]
			if cond.Operator == "regex" {
				if strVal, ok := cond.Value.(string); ok {
					if re, err := regexp.Compile(strVal); err == nil {
						cond.CompiledRegex = re
					} else {
						log.Printf("Error compiling regex for rule %s: %v", rules[i].ID, err)
					}
				}
			}
		}
	}
	return rules, nil
}

func (r *RuleRepository) Add(ctx context.Context, rule core.WAFRule) error {
	if rule.ID == "" {
		rule.ID = primitive.NewObjectID().Hex()
	}
	_, err := r.db.Collection("rules").InsertOne(ctx, rule)
	return err
}

func (r *RuleRepository) Update(ctx context.Context, rule core.WAFRule) error {
	_, err := r.db.Collection("rules").UpdateOne(ctx, bson.M{"_id": rule.ID}, bson.M{"$set": rule})
	return err
}

func (r *RuleRepository) Delete(ctx context.Context, ruleID, ownerID string) error {
	filter := bson.M{"_id": ruleID, "owner_id": ownerID}
	res, err := r.db.Collection("rules").DeleteOne(ctx, filter)
	if err != nil { return err }
	if res.DeletedCount == 0 { return errors.New("rule not found or unauthorized") }
	return nil
}

// --- Policy Methods ---

func (r *RuleRepository) GetPolicies(ctx context.Context, userID string) ([]core.RulePolicy, error) {
	cursor, err := r.db.Collection("rule_policies").Find(ctx, bson.M{"user_id": userID})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	var policies []core.RulePolicy
	err = cursor.All(ctx, &policies)
	return policies, err
}

func (r *RuleRepository) GetAllPolicies(ctx context.Context) ([]core.RulePolicy, error) {
	cursor, err := r.db.Collection("rule_policies").Find(ctx, bson.M{})
	if err != nil { return nil, err }
	defer cursor.Close(ctx)
	var policies []core.RulePolicy
	err = cursor.All(ctx, &policies)
	return policies, err
}

func (r *RuleRepository) UpsertPolicy(ctx context.Context, policy core.RulePolicy) error {
	filter := bson.M{
		"user_id":   policy.UserID,
		"rule_id":   policy.RuleID,
		"domain_id": policy.DomainID,
	}
	update := bson.M{"$set": bson.M{"enabled": policy.Enabled}}
	opts := options.Update().SetUpsert(true)
	_, err := r.db.Collection("rule_policies").UpdateOne(ctx, filter, update, opts)
	return err
}