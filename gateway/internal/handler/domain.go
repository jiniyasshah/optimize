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
}

func NewDomainHandler(r core.DomainRepository, d *sql.DNSRepository) *DomainHandler {
    return &DomainHandler{repo: r, dnsRepo: d}
}

func getRootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func checkRegistrarRDAP(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// rdap.org is a redirector that finds the correct registry (like Verisign, Radix, etc.)
	url := fmt.Sprintf("https://rdap.org/domain/%s", domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("domain not registered or found")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rdapResp RDAPResponse
	if err := json.Unmarshal(body, &rdapResp); err != nil {
		return nil, err
	}

	var nameservers []string
	for _, ns := range rdapResp.Nameservers {
		cleanName := strings.TrimSuffix(ns.LdhName, ".")
		nameservers = append(nameservers, cleanName)
	}

	return nameservers, nil
}

func (h *DomainHandler) AddDomain(w http.ResponseWriter, r *http.Request) {
	// 1. Decode & Validate
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


	rootZone := getRootDomain(domain.Name)
	if rootZone != domain.Name {
		existingRoot, err := h.repo.GetByName(r.Context(), rootZone)
		if err == nil && existingRoot != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "Root domain exists",
				"message": fmt.Sprintf("The root domain '%s' is already registered. Please add '%s' as an A Record.", rootZone, domain.Name),
			})
			return
		}
	}


	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)
	
	idx1 := rng.Intn(len(realNameservers))
	idx2 := rng.Intn(len(realNameservers))
	for idx1 == idx2 {
		idx2 = rng.Intn(len(realNameservers))
	}
	
	ns1 := realNameservers[idx1] + nsSuffix
	ns2 := realNameservers[idx2] + nsSuffix
	
	// Ensure your core.Domain struct has this field. If not, you must add it.
	domain.Nameservers = []string{ns1, ns2} 
	domain.Status = "pending_verification"

	// 4. Create in Mongo (Repo)
	createdDomain, err := h.repo.Create(r.Context(), domain)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			JSONError(w, "Domain already exists", http.StatusConflict)
			return
		}
		log.Printf("Failed to create domain in DB: %v", err)
		JSONError(w, "Failed to create domain", http.StatusInternalServerError)
		return
	}

	// 5. Provision PowerDNS Zone (SOA and NS only)
	// We do this via the dnsRepo directly to keep handler explicit
	go func(d core.Domain, n1, n2 string) {
		if h.dnsRepo == nil {
			log.Println("⚠️ DNS Repo is nil, skipping PowerDNS provisioning")
			return
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// A. Create SOA Record
		serial := time.Now().Format("2006010201")
		soaContent := fmt.Sprintf("ns1.minishield.tech. hostmaster.minishield.tech. %s 10800 3600 604800 3600", serial)
		
		soaRecord := core.DNSRecord{
			Name:    d.Name,
			Type:    "SOA",
			Content: soaContent,
			TTL:     3600,
		}
		if _, err := h.dnsRepo.CreateRecord(ctx, d.Name, soaRecord); err != nil {
			log.Printf("Failed to create SOA for %s: %v", d.Name, err)
		}

		// B. Create NS Records
		for _, ns := range []string{n1, n2} {
			nsRecord := core.DNSRecord{
				Name:    d.Name,
				Type:    "NS",
				Content: ns,
				TTL:     3600,
			}
			if _, err := h.dnsRepo.CreateRecord(ctx, d.Name, nsRecord); err != nil {
				log.Printf("Failed to create NS for %s: %v", d.Name, err)
			}
		}
	}(createdDomain, ns1, ns2)

	// Return the FULL domain object with Nameservers
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

	// 1. Get Domain from Repo
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

	// 2. SECURITY CHECK: Use RDAP to check the Registrar directly.
	foundNS, err := checkRegistrarRDAP(domain.Name)
	if err != nil {
		log.Printf("RDAP Lookup failed: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Verification Unavailable", 
			"details": err.Error(),
		})
		return
	}

	// 3. STRICT VERIFICATION
	matchedCount := 0
	for _, assignedNS := range domain.Nameservers {
		found := false
		for _, liveNS := range foundNS {
			if strings.EqualFold(liveNS, assignedNS) {
				found = true
				break
			}
		}
		if found {
			matchedCount++
		}
	}

	verified := (matchedCount == len(domain.Nameservers)) && (len(domain.Nameservers) > 0)

	w.Header().Set("Content-Type", "application/json")

	if verified {
		// 4. CRITICAL: Revoke old ownership
		// We use the Repo method for this now
		err := h.repo.RevokeOldOwnership(r.Context(), domain.Name, domain.ID)
		if err != nil {
			log.Printf("Error revoking old ownership for %s: %v", domain.Name, err)
		}

		// 5. Activate the new domain
		err = h.repo.UpdateStatus(r.Context(), domain.ID, "active")
		if err != nil {
			JSONError(w, "DB Update failed", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "active",
			"message": "Domain successfully verified! You are now the owner.",
		})
	} else {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":             "pending_verification",
			"message":            "Verification failed. Your Registrar nameservers do not match the assigned ones.",
			"assigned_ns":        domain.Nameservers,
			"found_at_registrar": foundNS,
		})
	}
}

func (h *DomainHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok {
		JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	domains, err := h.repo.GetByUser(r.Context(), userID)
	if err != nil {
		JSONError(w, "Failed to fetch domains", http.StatusInternalServerError)
		return
	}
	JSONSuccess(w, domains)
}

func (h *DomainHandler) ManageRecords(w http.ResponseWriter, r *http.Request) {
	if h.dnsRepo == nil {
		JSONError(w, "DNS service unavailable", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case "GET":
		domainName := r.URL.Query().Get("domain")
		if domainName == "" {
			JSONError(w, "Missing domain parameter", http.StatusBadRequest)
			return
		}
		records, err := h.dnsRepo.GetRecords(r.Context(), domainName)
		if err != nil {
			JSONError(w, "Failed to fetch records", http.StatusInternalServerError)
			return
		}
		JSONSuccess(w, records)

case "POST":
		domainName := r.URL.Query().Get("domain")
		if domainName == "" {
			JSONError(w, "Missing domain parameter", http.StatusBadRequest)
			return
		}

		var record core.DNSRecord
		if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
			JSONError(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		
		id, err := h.dnsRepo.CreateRecord(r.Context(), domainName, record)
		
		if err != nil {
			JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		JSONSuccess(w, map[string]string{"id": id})
	}
}