package service

import (
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/detector"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type RuleService struct {
	Mongo *mongo.Client
}

func NewRuleService(client *mongo.Client) *RuleService {
	return &RuleService{Mongo: client}
}

func (s *RuleService) GetGlobalRules() ([]detector.WAFRule, error) {
	return database.GetRules(s.Mongo, bson.M{"owner_id": ""})
}

func (s *RuleService) GetCustomRules(userID string) ([]detector.WAFRule, error) {
	return database.GetRules(s.Mongo, bson.M{"owner_id": userID})
}

func (s *RuleService) AddCustomRule(rule detector.WAFRule) error {
	return database.AddRule(s.Mongo, rule)
}

func (s *RuleService) DeleteRule(ruleID, userID string) error {
	return database.DeleteRule(s.Mongo, ruleID, userID)
}

func (s *RuleService) ToggleRule(input detector.PolicyInput, userID string) error {
	policy := detector.RulePolicy{
		UserID:   userID,
		RuleID:   input.RuleID,
		DomainID: input.DomainID,
		Enabled:  input.Enabled,
	}
	return database.UpsertRulePolicy(s.Mongo, policy)
}