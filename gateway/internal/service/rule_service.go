package service

import (
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type RuleService struct {
	Mongo *mongo.Client
}

func NewRuleService(client *mongo.Client) *RuleService {
	return &RuleService{Mongo: client}
}

func (s *RuleService) GetGlobalRules() ([]models.WAFRule, error) {
	return database.GetRules(s.Mongo, bson.M{"owner_id": ""})
}

func (s *RuleService) GetCustomRules(userID string) ([]models.WAFRule, error) {
	return database.GetRules(s.Mongo, bson.M{"owner_id": userID})
}

func (s *RuleService) AddCustomRule(rule models.WAFRule) error {
	return database.AddRule(s.Mongo, rule)
}

func (s *RuleService) DeleteRule(ruleID, userID string) error {
	return database.DeleteRule(s.Mongo, ruleID, userID)
}

func (s *RuleService) ToggleRule(input models.PolicyInput, userID string) error {
	policy := models.RulePolicy{
		UserID:   userID,
		RuleID:   input.RuleID,
		DomainID: input.DomainID,
		Enabled:  input.Enabled,
	}
	return database.UpsertRulePolicy(s.Mongo, policy)
}
