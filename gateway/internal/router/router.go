package router

import (
	"net/http"
	"github.com/gorilla/mux"
	"gateway/pkg/middleware"
	"gateway/internal/api"
)

func NewRouter() http.Handler {
	r := mux.NewRouter()

	// Public routes
	r.HandleFunc("/public", api.PublicHandler).Methods("GET")

	// Protected routes
	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(middleware.Auth)
	protected.HandleFunc("/protected", api.ProtectedHandler).Methods("GET")

	// Apply CORS middleware globally
	return middleware.CORS(r)
}
