package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"web-app-firewall-ml-detection/internal/core"
	"web-app-firewall-ml-detection/internal/service"
)

type AuthHandler struct {
	svc *service.AuthService
}

func NewAuthHandler(svc *service.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var input core.UserInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := h.svc.Register(r.Context(), input); err != nil {
		JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	JSONSuccess(w, map[string]string{"message": "User registered successfully"})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var input core.UserInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		JSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	token, user, err := h.svc.Login(r.Context(), input.Email, input.Password)
	if err != nil {
		JSONError(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Set Cookie
	isProd := os.Getenv("APP_ENV") == "production"
	cookieDomain := ""
	if isProd {
		cookieDomain = ".minishield.tech"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
		Domain:   cookieDomain,
		Secure:   isProd, // True in Prod
		SameSite: http.SameSiteLaxMode,
	})

	JSONSuccess(w, map[string]interface{}{
		"message": "Login successful",
		"user":    user,
	})
}

func (h *AuthHandler) CheckAuth(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	JSONSuccess(w, map[string]string{
		"status": "authenticated",
		"user_id": userID,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	isProd := os.Getenv("APP_ENV") == "production"
	cookieDomain := ""
	if isProd {
		cookieDomain = ".minishield.tech"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
		Domain:   cookieDomain,
		Secure:   isProd,
		SameSite: http.SameSiteLaxMode,
	})

	JSONSuccess(w, map[string]string{"message": "Logged out"})
}