package handler

import (
	"encoding/json"
	"net/http"

	"web-app-firewall-ml-detection/internal/core"
)

type RuleHandler struct {
	repo core.RuleRepository
}

func NewRuleHandler(r core.RuleRepository) *RuleHandler {
	return &RuleHandler{repo: r}
}

func (h *RuleHandler) GetGlobalRules(w http.ResponseWriter, r *http.Request) {
	// In a real app, you might filter this to only show "public" rules
	rules, err := h.repo.GetAll(r.Context())
	if err != nil {
		JSONError(w, "Failed to fetch rules", http.StatusInternalServerError)
		return
	}
	JSONSuccess(w, rules)
}

func (h *RuleHandler) ToggleRule(w http.ResponseWriter, r *http.Request) {
	var policy core.RulePolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		JSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	userID, _ := r.Context().Value("user_id").(string)
	policy.UserID = userID

	if err := h.repo.UpsertPolicy(r.Context(), policy); err != nil {
		JSONError(w, "Failed to update policy", http.StatusInternalServerError)
		return
	}

	JSONSuccess(w, map[string]string{"message": "Rule updated"})
}

func (h *RuleHandler) GetCustomRules(w http.ResponseWriter, r *http.Request) {
	// Currently RuleRepo.GetAll fetches everything. 
	// You might want to implement GetByOwner in repo.
	userID := r.Context().Value("user_id").(string)
	_ = userID // use to filter if you update repo
	
	rules, err := h.repo.GetAll(r.Context())
	if err != nil {
		JSONError(w, "Failed to fetch rules", http.StatusInternalServerError)
		return
	}
	JSONSuccess(w, rules)
}

func (h *RuleHandler) AddCustomRule(w http.ResponseWriter, r *http.Request) {
	var rule core.WAFRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		JSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	rule.OwnerID = r.Context().Value("user_id").(string)
	if err := h.repo.Add(r.Context(), rule); err != nil {
		JSONError(w, "Failed to add rule", http.StatusInternalServerError)
		return
	}
	JSONSuccess(w, rule)
}

func (h *RuleHandler) DeleteCustomRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.URL.Query().Get("id")
	userID := r.Context().Value("user_id").(string)

	if err := h.repo.Delete(r.Context(), ruleID, userID); err != nil {
		JSONError(w, "Failed to delete rule", http.StatusInternalServerError)
		return
	}
	JSONSuccess(w, map[string]string{"status": "deleted"})
}