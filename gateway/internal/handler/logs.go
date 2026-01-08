package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"web-app-firewall-ml-detection/internal/core"
	"web-app-firewall-ml-detection/internal/utils/logger"
)

type LogHandler struct {
	repo core.LogRepository
}

func NewLogHandler(repo core.LogRepository) *LogHandler {
	return &LogHandler{repo: repo}
}

// SSEHandler implements a robust Event Stream with heartbeats and cleanup
func (h *LogHandler) SSEHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Set Critical Headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no") // Disables Nginx buffering

	// 2. Ensure Client supports streaming
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// 3. Subscribe to the Broker
	// This gives us a unique channel just for this HTTP request
	logChan := logger.Subscribe()
	
	// 4. CLEANUP: Must unsubscribe when function exits (connection closes)
	defer func() {
		logger.Unsubscribe(logChan)
	}()

	// 5. Heartbeat Ticker
	// Sends a "ping" every 15s to keep the TCP connection alive
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// 6. Send initial "connected" message (Optional, helps frontend know stream started)
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	// 7. Main Event Loop
	for {
		select {
		// Case A: Client Disconnected (Tab closed, network lost)
		case <-r.Context().Done():
			return // Exits function, triggers defer cleanup

		// Case B: Heartbeat Timer
		case <-ticker.C:
			// SSE Comment (starts with :) is ignored by JS EventSource but keeps socket open
			fmt.Fprintf(w, ": keep-alive\n\n")
			flusher.Flush()

		// Case C: Real Log Data
		case entry, ok := <-logChan:
			if !ok {
				return // Channel closed (shutdown)
			}
			data, err := json.Marshal(entry)
			if err == nil {
				// Prefix "data: " is required by SSE spec
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
}

// SecuredLogsHandler remains unchanged...
func (h *LogHandler) SecuredLogsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	page, _ := strconv.ParseInt(r.URL.Query().Get("page"), 10, 64)
	if page < 1 { page = 1 }
	limit, _ := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 64)
	if limit < 1 { limit = 20 }

	filter := core.LogFilter{
		UserID: userID,
		Page:   page,
		Limit:  limit,
	}

	logs, err := h.repo.GetLogs(r.Context(), filter)
	if err != nil {
		JSONError(w, "Failed to fetch logs", http.StatusInternalServerError)
		return
	}
	JSONSuccess(w, logs)
}