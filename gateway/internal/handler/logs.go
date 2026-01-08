package handler

import (
	"encoding/json"
	"fmt"
	"log"
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

func (h *LogHandler) SSEHandler(w http.ResponseWriter, r *http.Request) {
 w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    w.Header().Set("X-Accel-Buffering", "no")

    // 2. Check for Flusher
    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, ":  connected\n\n")
    flusher.Flush()
    log.Printf("🔌 SSE client connected")

    logsCh := logger.GetBroadcastChannel()
    ticker := time.NewTicker(15 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case entry := <-logsCh: 
            log.Printf("📤 Sending log to SSE client: %s", entry.ClientIP)
            data, _ := json.Marshal(entry)
            fmt.Fprintf(w, "data: %s\n\n", data)
            flusher. Flush()

        case <-ticker.C:
            fmt.Fprintf(w, ": keep-alive\n\n")
            flusher.Flush()

        case <-r.Context().Done():
            log.Printf("🔌 SSE client disconnected")
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