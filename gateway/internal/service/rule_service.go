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

// [UPDATED] Helper to merge rules with policies
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
			rules[i].Enabled = enabled
		} else {
			// Default behavior if no policy exists:
			// Custom rules: Default to TRUE (usually user wants them active upon creation)
			// Global rules: Default to TRUE (standard protection) or FALSE depending on your preference.
			// Here we default to FALSE if no policy exists, to force explicit enabling, 
			// OR you can change this to 'true' if you want global rules auto-enabled.
			rules[i].Enabled = false 
		}
	}
	return rules, nil
}

// [UPDATED] Accept UserID and DomainID to determine enabled state
func (s *RuleService) GetGlobalRules(userID, domainID string) ([]models.WAFRule, error) {
	// 1. Get all global rules
	rules, err := database.GetRules(s.Mongo, bson.M{"owner_id": ""})
	if err != nil {
		return nil, err
	}
	// 2. Merge with user policies
	return s.mergeRulesWithPolicies(rules, userID, domainID)
}

// [UPDATED] Accept UserID and DomainID
func (s *RuleService) GetCustomRules(userID, domainID string) ([]models.WAFRule, error) {
	rules, err := database.GetRules(s.Mongo, bson.M{"owner_id": userID})
	if err != nil {
		return nil, err
	}
	return s.mergeRulesWithPolicies(rules, userID, domainID)
}

func (s *RuleService) AddCustomRule(rule models.WAFRule) error {
	// When adding a rule, we might want to auto-enable it in policy or just set Enabled=true in DB object
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
		DomainID: input.DomainID, // Ensure this is passed from frontend
		Enabled:  input.Enabled,
	}
	return database.UpsertRulePolicy(s.Mongo, policy)
}