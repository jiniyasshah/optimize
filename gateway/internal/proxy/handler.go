package proxy

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"time"

	"web-app-firewall-ml-detection/internal/config"
	"web-app-firewall-ml-detection/internal/detector"
	"web-app-firewall-ml-detection/internal/limiter"
	"web-app-firewall-ml-detection/internal/logger"
	"web-app-firewall-ml-detection/internal/models"
	"web-app-firewall-ml-detection/internal/service"
)

type WAFHandler struct {
	Service     *service.WAFService
	Proxy       *httputil.ReverseProxy
	RateLimiter *limiter.RateLimiter
	Cfg         *config.Config

	UnconfiguredPage []byte

	// Stats for System Status
	reqCount uint64 // Live counter
	rpm      uint64 // Calculated RPM (Requests Per Minute)
}

func NewWAFHandler(svc *service.WAFService, proxy *httputil.ReverseProxy, rl *limiter.RateLimiter, cfg *config.Config, page404 []byte) *WAFHandler {
	h := &WAFHandler{
		Service:          svc,
		Proxy:            proxy,
		RateLimiter:      rl,
		Cfg:              cfg,
		UnconfiguredPage: page404,
	}

	// Start Background Stats Ticker for RPM calculation
	go h.startStatsTicker()

	return h
}

func (h *WAFHandler) startStatsTicker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		// Atomic swap to reset count and store last minute's value
		count := atomic.SwapUint64(&h.reqCount, 0)
		atomic.StoreUint64(&h.rpm, count)
	}
}

// GetRPM returns the requests per minute from the last interval
func (h *WAFHandler) GetRPM() uint64 {
	return atomic.LoadUint64(&h.rpm)
}

// Helper to extract IP
func getRealIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func getHost(r *http.Request) string {
	host := r.Host
	if strings.Contains(host, ":") {
		if hostname, _, err := net.SplitHostPort(host); err == nil {
			return hostname
		}
	}
	return host
}

func (h *WAFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&h.reqCount, 1)
	clientIP := getRealIP(r)

	// Buffer Body for Analysis
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	host := getHost(r)

	// 1. Get Rules & Metadata from Service
	rules, domainInfo, configured := h.Service.GetRoutingInfo(host)

	// 2. UNCONFIGURED DOMAIN CHECK
	if !configured {
		log.Printf("⚠️ Unknown Domain: %s. Returning 404.", host)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		if len(h.UnconfiguredPage) > 0 {
			w.Write(h.UnconfiguredPage)
		} else {
			w.Write([]byte("Domain not configured"))
		}
		return
	}

	// 3. Rate Limit Check
	limitReached := h.RateLimiter.IsRateLimited(clientIP)

	// 4. Rule Engine Check
	ruleScore, triggeredTags, ruleBlock, rulePayload := detector.CheckRequest(r, rules, limitReached)

	// 5. ML Engine Check
	var isAnomaly bool
	var confidence float64
	var mlTag, mlTrigger string

	if !ruleBlock && ruleScore < 15 {
		isAnomaly, confidence, mlTag, mlTrigger = detector.CheckML(r, bodyBytes, h.Cfg.MLURL)
	}

	// 6. Final Decision
	verdict, reason, source := detector.Decide(ruleScore, ruleBlock, isAnomaly, confidence)

	if mlTag != "" && mlTag != "Normal" && (isAnomaly || confidence > 0.60) {
		triggeredTags = append(triggeredTags, mlTag)
	}

	finalTrigger := rulePayload
	if source == "ML Engine" || (source == "Hybrid" && mlTrigger != "") {
		finalTrigger = mlTrigger
	}

	// [ADDED] Track Request Statistics
	isFlagged := (verdict == detector.Block || verdict == detector.Monitor)
	isBlocked := (verdict == detector.Block)
	h.Service.TrackRequest(domainInfo.ID, isFlagged, isBlocked)

	// 7. Logging & Action
	headers := make(map[string][]string)
	for k, v := range r.Header {
		headers[k] = v
	}
	headers["Host"] = []string{host}

	fullReq := models.FullRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: headers,
		Body:    string(bodyBytes),
	}

	switch verdict {
	case detector.Block:
		log.Printf("⛔ BLOCKED IP: %s | Host: %s | Reason: %s", clientIP, host, reason)
		logger.LogAttack(domainInfo.UserID, domainInfo.ID, clientIP, r.URL.Path, reason, "Blocked", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("WAF Blocked: " + reason))

	case detector.Monitor:
		log.Printf("⚠️ FLAGGED IP: %s | Host: %s", clientIP, host)
		logger.LogAttack(domainInfo.UserID, domainInfo.ID, clientIP, r.URL.Path, reason, "Flagged", source, triggeredTags, ruleScore, confidence, fullReq, finalTrigger)
		h.Proxy.ServeHTTP(w, r)

	case detector.Allow:
		h.Proxy.ServeHTTP(w, r)
	}
}