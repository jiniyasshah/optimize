package handler

import (
	"log"
	"net/http"
	"net/http/httputil"

	"web-app-firewall-ml-detection/internal/service"
)

type WAFHandler struct {
	wafService *service.WAFService
	proxy      *httputil.ReverseProxy
}

func NewWAFHandler(waf *service.WAFService, proxy *httputil.ReverseProxy) *WAFHandler {
	return &WAFHandler{
		wafService: waf,
		proxy:      proxy,
	}
}

func (h *WAFHandler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Get Client IP
	clientIP := r.RemoteAddr // You might want a helper for X-Forwarded-For here

	// 2. Check WAF Logic
	action, reason := h.wafService.CheckRequest(r, clientIP)

	// 3. Act on Decision
	if action == "Block" {
		log.Printf("⛔ BLOCKED: %s | %s", clientIP, reason)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("WAF Blocked: " + reason))
		return
	}

	// 4. Forward Request
	if action == "Monitor" {
		log.Printf("⚠️ FLAGGED: %s | %s", clientIP, reason)
	}

	h.proxy.ServeHTTP(w, r)
}