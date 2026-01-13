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

// Helper to merge rules with policies
func (s *RuleService) mergeRulesWithPolicies(rules []models.WAFRule, userID, domainID string) ([]models.WAFRule, error) {
	// 1. Fetch the user's policies for this domain
	policies, err := database.GetPoliciesByUserAndDomain(s.Mongo, userID, domainID)
	if err != nil {
		return rules, err
	}

	// 2. Create a map for quick lookup: RuleID -> Enabled Status
	policyMap := make(map[string]bool)
	for _, p := range policies {
		policyMap[p.RuleID] = p.Enabled
	}

	// 3. Update the rules with the policy status
	for i := range rules {
		if enabled, exists := policyMap[rules[i].ID]; exists {
			// If a specific policy exists (user toggled it), respect that choice
			rules[i].Enabled = enabled
		} else {
			// [FIXED] Default to TRUE if no policy exists. 
			// Global rules should be active by default until turned off.
			rules[i].Enabled = true 
		}
	}
	return rules, nil
}

func (s *RuleService) GetGlobalRules(userID, domainID string) ([]models.WAFRule, error) {
	rules, err := database.GetRules(s.Mongo, bson.M{"owner_id": ""})
	if err != nil {
		return nil, err
	}
	return s.mergeRulesWithPolicies(rules, userID, domainID)
}

func (s *RuleService) GetCustomRules(userID, domainID string) ([]models.WAFRule, error) {
	rules, err := database.GetRules(s.Mongo, bson.M{"owner_id": userID})
	if err != nil {
		return nil, err
	}
	return s.mergeRulesWithPolicies(rules, userID, domainID)
}

func (s *RuleService) AddCustomRule(rule models.WAFRule) error {
	// Custom rules are enabled by default upon creation
	rule.Enabled = true 
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