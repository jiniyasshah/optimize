package api

import (
	"encoding/json"
	"net/http"
	"web-app-firewall-ml-detection/internal/models"
	"web-app-firewall-ml-detection/internal/service"
	"web-app-firewall-ml-detection/internal/utils"
)

type RuleHandler struct {
	Service *service.RuleService
}

func NewRuleHandler(s *service.RuleService) *RuleHandler {
	return &RuleHandler{Service: s}
}

// [UPDATED]
func (h *RuleHandler) GetGlobal(w http.ResponseWriter, r *http.Request) {
	// Get Domain ID from Query Params to fetch specific policies
	domainID := r.URL.Query().Get("domain_id")
	userID := r.Context().Value("user_id").(string)

	rules, err := h.Service.GetGlobalRules(userID, domainID)
	if err != nil {
		utils.WriteError(w, "Failed to fetch global rules", http.StatusInternalServerError)
		return
	}
	utils.WriteSuccess(w, rules, http.StatusOK)
}

// [UPDATED]
func (h *RuleHandler) GetCustom(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")
	userID := r.Context().Value("user_id").(string)

	rules, err := h.Service.GetCustomRules(userID, domainID)
	if err != nil {
		utils.WriteError(w, "Failed to fetch custom rules", http.StatusInternalServerError)
		return
	}
	utils.WriteSuccess(w, rules, http.StatusOK)
}

func (h *RuleHandler) AddCustom(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	var rule models.WAFRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}
	rule.OwnerID = userID
	if err := h.Service.AddCustomRule(rule); err != nil {
		utils.WriteError(w, "Failed to add rule", http.StatusInternalServerError)
		return
	}
	utils.WriteMessage(w, "Rule added", http.StatusCreated)
}

func (h *RuleHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	var input models.PolicyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}
	
	// Ensure DomainID is present (frontend must send it)
	if input.DomainID == "" {
		// Optional: fail if domain is required, or allow global toggle if business logic permits
		// utils.WriteError(w, "Domain ID is required", http.StatusBadRequest)
		// return
	}

	if err := h.Service.ToggleRule(input, userID); err != nil {
		utils.WriteError(w, "Failed to toggle rule", http.StatusInternalServerError)
		return
	}
	utils.WriteMessage(w, "Rule updated", http.StatusOK)
}