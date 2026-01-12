package service

import (
	"log"
	"net/url"
	"sync"
	"web-app-firewall-ml-detection/internal/config"
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type policyKey struct {
	RuleID   string
	DomainID string
}

type WAFService struct {
	Mongo *mongo.Client
	Cfg   *config.Config

	// Cache
	mu             sync.RWMutex
	domainRules    map[string][]models.WAFRule
	domainMap      map[string]models.Domain
	globalFallback []models.WAFRule
}

func NewWAFService(client *mongo.Client, cfg *config.Config) *WAFService {
	s := &WAFService{
		Mongo:       client,
		Cfg:         cfg,
		domainRules: make(map[string][]models.WAFRule),
		domainMap:   make(map[string]models.Domain),
	}
	s.ReloadRules() // Load immediately on startup
	return s
}

// GetRoutingInfo returns the rules and domain metadata for a specific host
func (s *WAFService) GetRoutingInfo(host string) ([]models.WAFRule, models.Domain, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rules, rulesExist := s.domainRules[host]
	domain, domainExists := s.domainMap[host]

	return rules, domain, rulesExist && domainExists
}

// GetTargetURL determines where to proxy the request (formerly in main.go director)
func (s *WAFService) GetTargetURL(incomingHost string) *url.URL {
	// 1. Check DB for specific Origin Record
	record, err := database.GetOriginRecord(s.Mongo, incomingHost)
	if err == nil && record != nil {
		rawTarget := record.Content

		// Dynamic Scheme Selection
		if record.OriginSSL {
			if len(rawTarget) < 4 || rawTarget[:4] != "http" {
				rawTarget = "https://" + rawTarget
			}
		} else {
			if len(rawTarget) < 4 || rawTarget[:4] != "http" {
				rawTarget = "http://" + rawTarget
			}
		}

		u, _ := url.Parse(rawTarget)
		return u
	}

	// 2. Fallback to Default Origin
	u, _ := url.Parse(s.Cfg.OriginURL)
	return u
}

// ReloadRules loads all configurations from DB (extracted from api.go)
func (s *WAFService) ReloadRules() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Fetch All Data
	allRules, err := database.GetRules(s.Mongo, bson.M{})
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load rules: %v", err)
		return
	}
	policies, err := database.GetAllPolicies(s.Mongo)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load policies: %v", err)
		return
	}
	domains, err := database.GetAllDomains(s.Mongo)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load domains: %v", err)
		return
	}
	dnsRecords, err := database.GetAllDNSRecords(s.Mongo)
	if err != nil {
		log.Printf("[ERROR] ReloadRules: Failed to load dns records: %v", err)
		return
	}

	// 2. Build Domain Map
	newDomainMap := make(map[string]models.Domain)
	activeDomainsByID := make(map[string]models.Domain)

	for _, d := range domains {
		if d.Status == "active" {
			newDomainMap[d.Name] = d
			activeDomainsByID[d.ID] = d
		}
	}

	for _, r := range dnsRecords {
		if parentDomain, ok := activeDomainsByID[r.DomainID]; ok {
			newDomainMap[r.Name] = parentDomain
		}
	}
	s.domainMap = newDomainMap

	// 3. Separate Rules
	globalRules := []models.WAFRule{}
	privateRules := make(map[string][]models.WAFRule)

	for _, r := range allRules {
		if r.OwnerID == "" {
			globalRules = append(globalRules, r)
		} else {
			privateRules[r.OwnerID] = append(privateRules[r.OwnerID], r)
		}
	}

	// 4. Index Policies
	policyMap := make(map[policyKey]bool)
	for _, p := range policies {
		policyMap[policyKey{RuleID: p.RuleID, DomainID: p.DomainID}] = p.Enabled
	}

	// 5. Build Effective Ruleset
	newDomainRules := make(map[string][]models.WAFRule)
	for _, d := range domains {
		if d.Status != "active" {
			continue
		}

		var effective []models.WAFRule
		// Global
		for _, r := range globalRules {
			if s.isEnabled(r.ID, d.ID, policyMap, true) {
				effective = append(effective, r)
			}
		}
		// Private
		if userRules, ok := privateRules[d.UserID]; ok {
			for _, r := range userRules {
				if s.isEnabled(r.ID, d.ID, policyMap, true) {
					effective = append(effective, r)
				}
			}
		}

		newDomainRules[d.Name] = effective
		for _, r := range dnsRecords {
			if r.DomainID == d.ID {
				newDomainRules[r.Name] = effective
			}
		}
	}

	s.domainRules = newDomainRules
	s.globalFallback = globalRules

	log.Printf("♻️  Rules Reloaded. Routing active for %d hosts.", len(s.domainMap))
}

func (s *WAFService) isEnabled(ruleID, domainID string, policies map[policyKey]bool, def bool) bool {
	if status, exists := policies[policyKey{RuleID: ruleID, DomainID: domainID}]; exists {
		return status
	}
	if status, exists := policies[policyKey{RuleID: ruleID, DomainID: ""}]; exists {
		return status
	}
	return def
}
