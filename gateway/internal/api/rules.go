package api

import (
	"encoding/json"
	"net/http"
	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/internal/service"
	"web-app-firewall-ml-detection/internal/utils"
)

type RuleHandler struct {
	Service *service.RuleService
}

func NewRuleHandler(s *service.RuleService) *RuleHandler {
	return &RuleHandler{Service: s}
}

func (h *RuleHandler) GetGlobal(w http.ResponseWriter, r *http.Request) {
	rules, err := h.Service.GetGlobalRules()
	if err != nil {
		utils.WriteError(w, "Failed to fetch global rules", http.StatusInternalServerError)
		return
	}
	utils.WriteSuccess(w, rules, http.StatusOK)
}

func (h *RuleHandler) GetCustom(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	rules, err := h.Service.GetCustomRules(userID)
	if err != nil {
		utils.WriteError(w, "Failed to fetch custom rules", http.StatusInternalServerError)
		return
	}
	utils.WriteSuccess(w, rules, http.StatusOK)
}

func (h *RuleHandler) AddCustom(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	var rule detector.WAFRule
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
	var input detector.PolicyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, "Invalid input", http.StatusBadRequest)
		return
	}
	
	if err := h.Service.ToggleRule(input, userID); err != nil {
		utils.WriteError(w, "Failed to toggle rule", http.StatusInternalServerError)
		return
	}
	utils.WriteMessage(w, "Rule updated", http.StatusOK)
}