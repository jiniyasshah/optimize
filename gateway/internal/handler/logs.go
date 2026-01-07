package handler

import (
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

// SSEHandler streams real-time logs to the frontend
func (h *LogHandler) SSEHandler(w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	clientChan := make(chan core.AttackLog, 100)
	broadcast := logger.GetBroadcastChannel()

	// Simple loop to copy broadcast messages to this client
	// In a real prod app, you'd want a proper pub/sub manager to avoid blocking
	go func() {
		for msg := range broadcast {
			clientChan <- msg
		}
	}()

	notify := r.Context().Done()

	for {
		select {
		case <-notify:
			return
		case logEntry := <-clientChan:
			// Format: data: <json>\n\n
			fmt.Fprintf(w, "data: {\"ip\": \"%s\", \"reason\": \"%s\", \"action\": \"%s\", \"timestamp\": \"%s\"}\n\n",
				logEntry.ClientIP, logEntry.Reason, logEntry.Action, logEntry.Timestamp.Format(time.RFC3339))
			w.(http.Flusher).Flush()
		}
	}
}

// SecuredLogsHandler fetches historical logs with pagination
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