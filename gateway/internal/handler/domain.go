package handler

import (
	"encoding/json"
	"net/http"

	"web-app-firewall-ml-detection/internal/core"
	"web-app-firewall-ml-detection/internal/repository/sql"
)

type DomainHandler struct {
    repo    core.DomainRepository
    dnsRepo *sql.DNSRepository 
}

func NewDomainHandler(r core.DomainRepository, d *sql.DNSRepository) *DomainHandler {
    return &DomainHandler{repo: r, dnsRepo: d}
}

func (h *DomainHandler) AddDomain(w http.ResponseWriter, r *http.Request) {
	var domain core.Domain
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		JSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Get UserID from Context (set by Middleware later)
	userID, _ := r.Context().Value("user_id").(string)
	domain.UserID = userID
	domain.Status = "pending"

	// Logic to revoke old ownership if needed
	h.repo.RevokeOldOwnership(r.Context(), domain.Name, userID)

	newDomain, err := h.repo.Create(r.Context(), domain)
	if err != nil {
		JSONError(w, "Failed to create domain", http.StatusInternalServerError)
		return
	}

	JSONSuccess(w, newDomain)
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

func (h *DomainHandler) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	// For now, we can just check if the domain exists and set status to active
	// Real implementation would check DNS TXT records
	var req struct {
		DomainID string `json:"domain_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	err := h.repo.UpdateStatus(r.Context(), req.DomainID, "active")
	if err != nil {
		JSONError(w, "Verification failed", http.StatusInternalServerError)
		return
	}
	JSONSuccess(w, map[string]string{"status": "verified"})
}

func (h *DomainHandler) ManageRecords(w http.ResponseWriter, r *http.Request) {
	if h.dnsRepo == nil {
		JSONError(w, "DNS service unavailable", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case "GET":
		domainName := r.URL.Query().Get("domain")
		records, err := h.dnsRepo.GetRecords(r.Context(), domainName)
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
		
		// Basic validation: ensure user owns the domain (logic omitted for brevity)
		
		id, err := h.dnsRepo.CreateRecord(r.Context(), record)
		if err != nil {
			JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		JSONSuccess(w, map[string]string{"id": id})
	}
}