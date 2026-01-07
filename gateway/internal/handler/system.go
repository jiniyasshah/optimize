package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

// ComponentStatus defines the exact structure you want
type ComponentStatus struct {
	Status  string `json:"status"`
	CPU     string `json:"cpu"`
	Memory  string `json:"memory"`
	Network string `json:"network"`
}

type SystemHandler struct {
	mongoClient *mongo.Client
	mlURL       string
}

// NewSystemHandler now requires mlURL to check the Scorer's health
func NewSystemHandler(client *mongo.Client, mlURL string) *SystemHandler {
	return &SystemHandler{
		mongoClient: client,
		mlURL:       mlURL,
	}
}

func (h *SystemHandler) SystemStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	statusMap := make(map[string]ComponentStatus)

	// 1. GATEWAY STATS (Self)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	// Note: In this modular design, we'd need a shared counter for accurate RPM.
	// For now, we report the runtime stats which are always available.
	statusMap["gateway"] = ComponentStatus{
		Status:  "Online",
		Memory:  fmt.Sprintf("%v MB", m.Alloc/1024/1024),
		CPU:     fmt.Sprintf("%d Goroutines", runtime.NumGoroutine()),
		Network: "N/A", // Placeholder until we link the middleware counter
	}

	// 2. DATABASE STATS
	// We ping MongoDB to check connection status
	dbStatus := ComponentStatus{
		Status:  "Offline",
		Memory:  "0 MB",
		CPU:     "0%",
		Network: "0 Req/min",
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := h.mongoClient.Ping(ctx, nil); err == nil {
		dbStatus = ComponentStatus{
			Status:  "Online",
			Memory:  "Managed (External)",
			CPU:     "Managed (External)",
			Network: "N/A",
		}
	}
	statusMap["database"] = dbStatus

	// 3. ML SCORER STATS
	statusMap["ml_scorer"] = h.fetchRemoteHealth(h.mlURL)

	json.NewEncoder(w).Encode(statusMap)
}

// fetchRemoteHealth talks to the Python service to get its internal stats
func (h *SystemHandler) fetchRemoteHealth(baseURL string) ComponentStatus {
	// Clean up URL: remove trailing slash or /predict endpoint
	rootURL := baseURL
	if len(rootURL) > 0 && rootURL[len(rootURL)-1] == '/' {
		rootURL = rootURL[:len(rootURL)-1]
	}
	if len(rootURL) > 8 && rootURL[len(rootURL)-8:] == "/predict" {
		rootURL = rootURL[:len(rootURL)-8]
	}

	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(rootURL + "/health")
	if err != nil {
		return ComponentStatus{Status: "Offline", Memory: "0 MB", CPU: "0%", Network: "0 Req/min"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ComponentStatus{Status: "Error", Memory: "Unknown", CPU: "Unknown", Network: "0 Req/min"}
	}

	var pythonStats struct {
		Status  string `json:"status"`
		CPU     string `json:"cpu"`
		Memory  string `json:"memory"`
		Network string `json:"network"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&pythonStats); err != nil {
		return ComponentStatus{Status: "Online", Memory: "Unknown", CPU: "Unknown", Network: "Unknown"}
	}

	// Capitalize status to match Go convention
	status := "Online"
	if pythonStats.Status != "online" && pythonStats.Status != "" {
		status = pythonStats.Status
	}

	return ComponentStatus{
		Status:  status,
		CPU:     pythonStats.CPU,
		Memory:  pythonStats.Memory,
		Network: pythonStats.Network,
	}
}