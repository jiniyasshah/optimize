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
	wafIP   string 
}

func NewDomainHandler(r core.DomainRepository, d *sql.DNSRepository, wafIP string) *DomainHandler {
	return &DomainHandler{repo: r, dnsRepo: d, wafIP: wafIP}
}

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
	domain.ProxyEnabled = true // Default setting

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

	// Provision PowerDNS (SOA + NS only)
	go func(d core.Domain, n1, n2 string) {
		if h.dnsRepo == nil { return }
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		serial := time.Now().Format("2006010201")
		soaContent := fmt.Sprintf("ns1.minishield.tech. hostmaster.minishield.tech. %s 10800 3600 604800 3600", serial)
		
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

	// Security Check (RDAP)
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
		
		// Activate AND Enable Proxy
		domain.Status = "active"
		domain.ProxyEnabled = true

		h.repo.UpdateStatus(r.Context(), domain.ID, "active")
		h.repo.UpdateProxyMode(r.Context(), domain.ID, true)

		// [SPLIT BRAIN] Add Default WAF A Record to SQL ONLY
		// We do NOT add this to Mongo because it's a system record, not user input.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			log.Printf("🔹 Adding Default WAF A Record to SQL: %s -> %s", domain.Name, h.wafIP)
			h.dnsRepo.CreateRecord(ctx, domain.Name, core.DNSRecord{
				Name:    domain.Name,
				Type:    "A",
				Content: h.wafIP, 
				TTL:     3600,
			})
		}()

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "active",
			"message": "Domain verified! Proxy Mode is ON by default.",
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

	domainID := r.URL.Query().Get("domain_id")
	if domainID == "" {
		JSONError(w, "Missing domain_id", http.StatusBadRequest)
		return
	}

	// Ownership Check
	domain, err := h.repo.GetByID(r.Context(), domainID)
	if err != nil {
		JSONError(w, "Domain not found", http.StatusNotFound)
		return
	}
	userID, _ := r.Context().Value("user_id").(string)
	if domain.UserID != userID {
		JSONError(w, "Unauthorized", http.StatusForbidden)
		return
	}

	switch r.Method {
	case "GET":
		// [FIX] Fetch from Mongo (User View)
		// We want to show the user what THEY configured, not the underlying WAF IPs
		records, err := h.repo.GetRecords(r.Context(), domainID)
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
		
		record.DomainID = domainID
		
		// 1. Save to MongoDB (Source of Truth)
		id, err := h.repo.CreateRecord(r.Context(), record)
		if err != nil {
			JSONError(w, "Database error", http.StatusInternalServerError)
			return
		}
		
		// 2. SQL Sync Logic (Split Brain)
		// Non-routable records (MX, TXT, NS) must always go to SQL to work.
		if record.Type == "NS" || record.Type == "MX" || record.Type == "TXT" {
			go h.dnsRepo.CreateRecord(context.Background(), domain.Name, record)
		} else if record.Type == "A" || record.Type == "CNAME" {
			// Routable records only go to SQL if Proxy is OFF.
			// If Proxy is ON, we ignore them in SQL (so the default WAF IP stays active).
			if !domain.ProxyEnabled {
				go h.dnsRepo.CreateRecord(context.Background(), domain.Name, record)
			}
		}

		JSONSuccess(w, map[string]string{"id": id})
	
	default:
		JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// [NEW] Toggle Proxy Mode
func (h *DomainHandler) ToggleProxyMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DomainID string `json:"domain_id"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 1. Get Domain & Verify Ownership
	domain, err := h.repo.GetByID(r.Context(), req.DomainID)
	if err != nil || domain.UserID != r.Context().Value("user_id").(string) {
		JSONError(w, "Unauthorized or not found", http.StatusForbidden)
		return
	}

	// 2. Update Mongo Status
	err = h.repo.UpdateProxyMode(r.Context(), req.DomainID, req.Enabled)
	if err != nil {
		JSONError(w, "Failed to update status", http.StatusInternalServerError)
		return
	}

	// 3. Switch SQL Records (The Big Swap)
	go func() {
		ctx := context.Background()
		
		if req.Enabled {
			// --- ENABLING PROXY MODE ---
			// 1. Remove User's A/CNAME records from SQL (they expose the real IP)
			h.dnsRepo.DeleteRecordsByType(ctx, domain.Name, "A")
			h.dnsRepo.DeleteRecordsByType(ctx, domain.Name, "CNAME")
			
			// 2. Add the "Shield" (Default WAF A Record)
			h.dnsRepo.CreateRecord(ctx, domain.Name, core.DNSRecord{
				Name:    domain.Name,
				Type:    "A",
				Content: h.wafIP,
				TTL:     300,
			})
			log.Printf("🛡️ Proxy Enabled for %s: Switched DNS to WAF IP", domain.Name)

		} else {
			// --- DISABLING PROXY MODE (DNS ONLY) ---
			// 1. Remove the "Shield" (WAF IP)
			h.dnsRepo.DeleteRecordsByType(ctx, domain.Name, "A")
			
			// 2. Push ALL User A/CNAME records from Mongo -> SQL
			userRecords, _ := h.repo.GetRecords(ctx, req.DomainID)
			for _, rec := range userRecords {
				if rec.Type == "A" || rec.Type == "CNAME" {
					h.dnsRepo.CreateRecord(ctx, domain.Name, rec)
				}
			}
			log.Printf("🌍 DNS Mode for %s: Exposed User Records directly", domain.Name)
		}
	}()

	JSONSuccess(w, map[string]bool{"proxy_enabled": req.Enabled})
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