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