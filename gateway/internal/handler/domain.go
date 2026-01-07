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