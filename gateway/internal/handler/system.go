package handler

import (
	"context"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

type SystemHandler struct {
	mongoClient *mongo.Client
}

func NewSystemHandler(client *mongo.Client) *SystemHandler {
	return &SystemHandler{mongoClient: client}
}

func (h *SystemHandler) SystemStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]string{
		"system": "operational",
		"db":     "unknown",
		"time":   time.Now().Format(time.RFC3339),
	}

	// Check MongoDB
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.mongoClient.Ping(ctx, nil); err != nil {
		status["db"] = "disconnected"
	} else {
		status["db"] = "connected"
	}

	JSONSuccess(w, status)
}