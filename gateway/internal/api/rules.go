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

//  Reads domain_id from Query Params
func (h *RuleHandler) GetGlobal(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domainID := r.URL.Query().Get("domain_id")

	rules, err := h.Service.GetGlobalRules(userID, domainID)
	if err != nil {
		utils.WriteError(w, "Failed to fetch global rules", http.StatusInternalServerError)
		return
	}
	utils.WriteSuccess(w, rules, http.StatusOK)
}

//  Reads domain_id from Query Params
func (h *RuleHandler) GetCustom(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	domainID := r.URL.Query().Get("domain_id")

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

//  Passes entire input (including DomainID) to Service
func (h *RuleHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	var input models.PolicyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}
	
	// Ensure ID is present
	if input.RuleID == "" {
		utils.WriteError(w, "Rule ID required", http.StatusBadRequest)
		return
	}

	if err := h.Service.ToggleRule(input, userID); err != nil {
		utils.WriteError(w, "Failed to toggle rule", http.StatusInternalServerError)
		return
	}
	utils.WriteMessage(w, "Rule updated", http.StatusOK)
}