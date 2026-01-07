package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"web-app-firewall-ml-detection/internal/core"
	"web-app-firewall-ml-detection/internal/utils/logger"
)

type LogHandler struct {
	repo core.LogRepository
}

func NewLogHandler(repo core.LogRepository) *LogHandler {
	return &LogHandler{repo: repo}
}

// SSEHandler - Reverted to your previous working version
func (h *LogHandler) SSEHandler(w http.ResponseWriter, r *http.Request) {
	// Standard SSE Headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Get the global channel
	logsCh := logger.GetBroadcastChannel()

	for {
		select {
		case entry := <-logsCh:
			// Marshal the log entry to JSON
			data, _ := json.Marshal(entry)
			
			// Write the event: data: <JSON>\n\n
			fmt.Fprintf(w, "data: %s\n\n", data)
			
			// Flush immediately to client
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-r.Context().Done():
			// Client disconnected
			return
		}
	}
}

// SecuredLogsHandler - Keeps the clean repository pattern
func (h *LogHandler) SecuredLogsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	page, _ := strconv.ParseInt(r.URL.Query().Get("page"), 10, 64)
	if page < 1 {
		page = 1
	}

	limit, _ := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 64)
	if limit < 1 {
		limit = 20
	}

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