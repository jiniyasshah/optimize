package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"web-app-firewall-ml-detection/internal/core"
	"web-app-firewall-ml-detection/internal/utils/logger" // Ensure this path matches your folder structure
)

type LogHandler struct {
	repo core.LogRepository
}

func NewLogHandler(repo core.LogRepository) *LogHandler {
	return &LogHandler{repo: repo}
}

// SSEHandler streams real-time logs to the frontend
func (h *LogHandler) SSEHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Set standard SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	// 2. Disable Nginx buffering (Crucial for SSE to work behind proxies)
	w.Header().Set("X-Accel-Buffering", "no")

	// 3. Subscribe to the logger
	logChan := logger.Subscribe()
	defer logger.Unsubscribe(logChan) // Clean up when client disconnects

	// 4. Create a ticker for Heartbeats (Keep-Alive)
	// Sends a ping every 15 seconds so the browser doesn't close the connection
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	// 5. Check if Flusher is supported
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// 6. Main Loop
	// Listen for Logs, Heartbeats, or Disconnects
	for {
		select {
		// Case A: Client disconnected
		case <-r.Context().Done():
			return

		// Case B: Send Heartbeat (Comment starting with :)
		case <-heartbeat.C:
			fmt.Fprintf(w, ": keep-alive\n\n")
			flusher.Flush()

		// Case C: New Log Entry Received
		case logEntry := <-logChan:
			// Format: data: <json>\n\n
			// We build the JSON manually or use json.Marshal
			fmt.Fprintf(w, "data: {\"ip\": \"%s\", \"reason\": \"%s\", \"action\": \"%s\", \"timestamp\": \"%s\"}\n\n",
				logEntry.ClientIP, logEntry.Reason, logEntry.Action, logEntry.Timestamp.Format(time.RFC3339))
			flusher.Flush()
		}
	}
}

// SecuredLogsHandler remains the same...
func (h *LogHandler) SecuredLogsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	page, _ := strconv.ParseInt(r.URL.Query().Get("page"), 10, 64)
	limit, _ := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 64)

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