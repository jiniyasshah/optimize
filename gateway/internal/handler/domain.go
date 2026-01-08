package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"web-app-firewall-ml-detection/internal/core"
	"web-app-firewall-ml-detection/internal/repository/sql"
)

var realNameservers = []string{
	"jiniyas", "rabin", "niraj", "sabin", "rita", 
	"sneha", "exam", "bikalpa", "raju", "dhiren", "sanket",
}

const nsSuffix = ".ns.minishield.tech"

type RDAPResponse struct {
	Nameservers []struct {
		LdhName string `json:"ldhName"`
	} `json:"nameservers"`
}

type DomainHandler struct {
    repo    core.DomainRepository
    dnsRepo *sql.DNSRepository 
    wafIP   string // [NEW] Store the WAF Public IP
}

// [UPDATED] Accept wafIP here
func NewDomainHandler(r core.DomainRepository, d *sql.DNSRepository, wafIP string) *DomainHandler {
    return &DomainHandler{repo: r, dnsRepo: d, wafIP: wafIP}
}

// ... (getRootDomain and checkRegistrarRDAP helper functions remain the same) ...
func getRootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 { return domain }
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func checkRegistrarRDAP(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	url := fmt.Sprintf("https://rdap.org/domain/%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Accept", "application/rdap+json")
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	
	if resp.StatusCode == 404 { return nil, fmt.Errorf("domain not found") }
	body, _ := io.ReadAll(resp.Body)
	
	var rdapResp RDAPResponse
	json.Unmarshal(body, &rdapResp)
	
	var nameservers []string
	for _, ns := range rdapResp.Nameservers {
		nameservers = append(nameservers, strings.TrimSuffix(ns.LdhName, "."))
	}
	return nameservers, nil
}

func (h *DomainHandler) AddDomain(w http.ResponseWriter, r *http.Request) {
	var domain core.Domain
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		JSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	userID, ok := r.Context().Value("user_id").(string)
	if !ok {
		JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	domain.UserID = userID

	// Strict Subdomain Check
	rootZone := getRootDomain(domain.Name)
	if rootZone != domain.Name {
		existingRoot, err := h.repo.GetByName(r.Context(), rootZone)
		if err == nil && existingRoot != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "Root domain exists",
				"message": fmt.Sprintf("The root domain '%s' is already registered.", rootZone),
			})
			return
		}
	}

	// Assign NS
	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)
	idx1 := rng.Intn(len(realNameservers))
	idx2 := rng.Intn(len(realNameservers))
	for idx1 == idx2 { idx2 = rng.Intn(len(realNameservers)) }
	
	ns1 := realNameservers[idx1] + nsSuffix
	ns2 := realNameservers[idx2] + nsSuffix
	domain.Nameservers = []string{ns1, ns2}
	domain.Status = "pending_verification"

	// Create in Mongo
	createdDomain, err := h.repo.Create(r.Context(), domain)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			JSONError(w, "Domain already exists", http.StatusConflict)
			return
		}
		JSONError(w, "Failed to create domain", http.StatusInternalServerError)
		return
	}

	// Provision PowerDNS (SOA + NS)
	go func(d core.Domain, n1, n2 string) {
		if h.dnsRepo == nil { return }
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		serial := time.Now().Format("2006010201")
		soaContent := fmt.Sprintf("ns1.minishield.tech. hostmaster.minishield.tech. %s 10800 3600 604800 3600", serial)
		
		// [FIXED] Using 3-arg CreateRecord(ctx, zoneName, record)
		h.dnsRepo.CreateRecord(ctx, d.Name, core.DNSRecord{Name: d.Name, Type: "SOA", Content: soaContent, TTL: 3600})
		h.dnsRepo.CreateRecord(ctx, d.Name, core.DNSRecord{Name: d.Name, Type: "NS", Content: n1, TTL: 3600})
		h.dnsRepo.CreateRecord(ctx, d.Name, core.DNSRecord{Name: d.Name, Type: "NS", Content: n2, TTL: 3600})
	}(createdDomain, ns1, ns2)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(createdDomain)
}

func (h *DomainHandler) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domainID := r.URL.Query().Get("id")
	if domainID == "" {
		JSONError(w, "Missing domain id", http.StatusBadRequest)
		return
	}

	domain, err := h.repo.GetByID(r.Context(), domainID)
	if err != nil {
		JSONError(w, "Domain not found", http.StatusNotFound)
		return
	}

	userID := r.Context().Value("user_id").(string)
	if domain.UserID != userID {
		JSONError(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Security Check
	foundNS, err := checkRegistrarRDAP(domain.Name)
	if err != nil {
		log.Printf("RDAP Lookup failed: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "Verification Unavailable", "details": err.Error()})
		return
	}

	matchedCount := 0
	for _, assignedNS := range domain.Nameservers {
		for _, liveNS := range foundNS {
			if strings.EqualFold(liveNS, assignedNS) {
				matchedCount++
				break
			}
		}
	}

	verified := (matchedCount == len(domain.Nameservers)) && (len(domain.Nameservers) > 0)

	w.Header().Set("Content-Type", "application/json")

	if verified {
		h.repo.RevokeOldOwnership(r.Context(), domain.Name, domain.ID)
		err = h.repo.UpdateStatus(r.Context(), domain.ID, "active")
		if err != nil {
			JSONError(w, "DB Update failed", http.StatusInternalServerError)
			return
		}

		// [FIXED] Default Addition of A Record pointing to WAF IP
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			log.Printf("🔹 Adding Default A Record for verified domain: %s -> %s", domain.Name, h.wafIP)
			
			h.dnsRepo.CreateRecord(ctx, domain.Name, core.DNSRecord{
				Name:    domain.Name,
				Type:    "A",
				Content: h.wafIP, // Uses the WAFPublicIP from Config
				TTL:     3600,
			})
			
			// If it's a subdomain, we might want to add 'www' too, but keeping it simple for now.
		}()

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "active",
			"message": "Domain verified! Traffic is now routing through WAF.",
		})
	} else {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":             "pending_verification",
			"message":            "Verification failed. Nameservers do not match.",
			"assigned_ns":        domain.Nameservers,
			"found_at_registrar": foundNS,
		})
	}
}

func (h *DomainHandler) ManageRecords(w http.ResponseWriter, r *http.Request) {
	if h.dnsRepo == nil {
		JSONError(w, "DNS service unavailable", http.StatusServiceUnavailable)
		return
	}

	// 1. Get Domain ID (Best Practice)
	domainID := r.URL.Query().Get("domain_id") // or "id"
	if domainID == "" {
		JSONError(w, "Missing domain_id", http.StatusBadRequest)
		return
	}

	// 2. SECURITY CHECK: Verify User Owns this Domain
	// We must fetch from Mongo first to ensure the user is authorized.
	domain, err := h.repo.GetByID(r.Context(), domainID)
	if err != nil {
		JSONError(w, "Domain not found", http.StatusNotFound)
		return
	}

	userID, ok := r.Context().Value("user_id").(string)
	if !ok || domain.UserID != userID {
		JSONError(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// 3. Now safe to proceed using domain.Name
	switch r.Method {
	case "GET":
		records, err := h.dnsRepo.GetRecords(r.Context(), domain.Name)
		if err != nil {
			JSONError(w, "Failed to fetch records", http.StatusInternalServerError)
			return
		}
		JSONSuccess(w, records)

	case "POST":
		var record core.DNSRecord
		if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
			JSONError(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		
		// Use the verified domain.Name from the DB, not from the user input
		id, err := h.dnsRepo.CreateRecord(r.Context(), domain.Name, record)
		if err != nil {
			JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		JSONSuccess(w, map[string]string{"id": id})
	
	default:
		JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *DomainHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("user_id").(string)
	domains, err := h.repo.GetByUser(r.Context(), userID)
	if err != nil {
		JSONError(w, "Failed to fetch domains", http.StatusInternalServerError)
		return
	}
	JSONSuccess(w, domains)
}