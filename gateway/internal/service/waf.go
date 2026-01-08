package service

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"web-app-firewall-ml-detection/internal/core"
	"web-app-firewall-ml-detection/internal/service/detector"
	"web-app-firewall-ml-detection/internal/utils/limiter"
	"web-app-firewall-ml-detection/internal/utils/logger"
)

type WAFService struct {
	domainRepo  core.DomainRepository
	ruleRepo    core.RuleRepository
	logRepo     core.LogRepository
	mlURL       string
	rateLimiter *limiter.RateLimiter

	// Cache
	mu          sync.RWMutex
	domainMap   map[string]core.Domain    // Host -> Domain Config
	domainRules map[string][]core.WAFRule // Host -> Active Rules
}

func NewWAFService(d core.DomainRepository, r core.RuleRepository, l core.LogRepository, mlURL string, rateLimiter *limiter.RateLimiter) *WAFService {
	s := &WAFService{
		domainRepo:  d,
		ruleRepo:    r,
		logRepo:     l,
		mlURL:       mlURL,
		rateLimiter: rateLimiter,
		domainMap:   make(map[string]core.Domain),
		domainRules: make(map[string][]core.WAFRule),
	}
	s.ReloadRules()
	return s
}

// ReloadRules refreshes the in-memory cache of domains and rules
func (s *WAFService) ReloadRules() {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Fetch Data
	domains, _ := s.domainRepo.GetAll(ctx)
	dnsRecords, _ := s.domainRepo.GetAllRecords(ctx)
	allRules, _ := s.ruleRepo.GetAll(ctx)
	policies, _ := s.ruleRepo.GetAllPolicies(ctx)

	// 2. Build Policy Map
	policyMap := make(map[string]bool)
	for _, p := range policies {
		key := p.RuleID + "|" + p.DomainID
		policyMap[key] = p.Enabled
	}

	// 3. Build Domain Map (Host -> Domain)
	newDomainMap := make(map[string]core.Domain)
	activeDomainsByID := make(map[string]core.Domain)

	for _, d := range domains {
		if d.Status == "active" {
			newDomainMap[d.Name] = d
			activeDomainsByID[d.ID] = d
		}
	}

	for _, r := range dnsRecords {
		if parent, ok := activeDomainsByID[r.DomainID]; ok {
			newDomainMap[r.Name] = parent
		}
	}

	// 4. Assign Rules to Domains
	newDomainRules := make(map[string][]core.WAFRule)

	for host, domain := range newDomainMap {
		var effective []core.WAFRule
		for _, rule := range allRules {
			// Check ownership (Global vs Private)
			if rule.OwnerID != "" && rule.OwnerID != domain.UserID {
				continue
			}

			// Check Policy Override
			isEnabled := rule.Enabled
			if val, ok := policyMap[rule.ID+"|"+domain.ID]; ok {
				isEnabled = val
			} else if val, ok := policyMap[rule.ID+"|"]; ok {
				// Check global policy for this rule
				isEnabled = val
			}

			if isEnabled {
				effective = append(effective, rule)
			}
		}
		newDomainRules[host] = effective
	}

	s.domainMap = newDomainMap
	s.domainRules = newDomainRules
	log.Printf("♻️  WAF Cache Reloaded: %d Hosts Configured", len(newDomainMap))
}

// CheckRequest is the main entry point for the HTTP handler
func (s *WAFService) CheckRequest(r *http.Request, clientIP string) (action string, reason string) {
	host := r.Host
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}

	isRateLimited := s.rateLimiter.IsRateLimited(clientIP)

	s.mu.RLock()
	domain, exists := s.domainMap[host]
	rules := s.domainRules[host]
	s.mu.RUnlock()

	if !exists {
		return "404", "Domain not configured"
	}

	// 1. Rule Check
	score, tags, block, payload := detector.CheckRequest(r, rules, isRateLimited)

	// 2. ML Check
	var isAnomaly bool
	var confidence float64
	var mlTag, mlTrigger string

	if !block && score < 15 {
		// Re-read body for ML (it was buffered in CheckRequest)
		isAnomaly, confidence, mlTag, mlTrigger = detector.CheckML(r, []byte(payload), s.mlURL)
	}

	// 3. Decision
	if mlTag != "" && (isAnomaly || confidence > 0.80) {
		tags = append(tags, mlTag)
	}

	finalTrigger := payload
	if mlTrigger != "" {
		finalTrigger = mlTrigger
	}

	verdict := "Allow"
	reason = "Clean"

	if block || score >= 10 {
		verdict = "Block"
		reason = "Rule Violation"
	} else if isAnomaly {
		verdict = "Block"
		reason = "ML Anomaly"
	} else if score >= 5 {
		verdict = "Monitor"
		reason = "Suspicious"
	}

go func() {
    ctx, cancel := context.WithTimeout(context. Background(), 5*time.Second)
    defer cancel()

    logEntry := core.AttackLog{
        UserID:      domain.UserID,
        DomainID:    domain.ID,
        Timestamp:   time.Now(),
        ClientIP:    clientIP,
        RequestPath: r.URL.Path,
        Reason:      reason,
        Action:      verdict,
        Source:      "WAF",
        Tags:        tags,
        RuleScore:   score,
        MLScore:     confidence,
        Trigger:     finalTrigger,
    }

    // A. Save to Database (Persistent Storage)
    if err := s.logRepo.LogAttack(ctx, logEntry); err != nil {
        log.Printf("❌ Failed to save log to DB: %v", err)
    }
	// B. Broadcast to SSE Stream
        logger.LogAttack(logEntry)
        log.Printf("📡 Broadcasted log:  %s | %s", clientIP, reason)

}()
    return verdict, reason
}