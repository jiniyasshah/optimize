package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware(jwtSecret string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// 1. Get Token from Cookie
			cookie, err := r.Cookie("auth_token")
			if err != nil {
				unauthorized(w, "Unauthorized: No session cookie")
				return
			}

			// 2. Parse Token
			token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
				return []byte(jwtSecret), nil
			})

			if err != nil || !token.Valid {
				unauthorized(w, "Unauthorized: Invalid token")
				return
			}

			// 3. Extract Claims
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				unauthorized(w, "Unauthorized: Invalid claims")
				return
			}

			userID, ok := claims["user_id"].(string)
			if !ok {
				unauthorized(w, "Unauthorized")
				return
			}

			// 4. Inject into Context
			ctx := context.WithValue(r.Context(), "user_id", userID)
			next(w, r.WithContext(ctx))
		}
	}
}

func unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "error",
		"message": message,
	})
}