package proxy

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"web-app-firewall-ml-detection/internal/core"
)

type ProxyManager struct {
	repo          core.DomainRepository
	defaultOrigin string
	errorPage     []byte
}

func NewProxy(repo core.DomainRepository, defaultOrigin string) *httputil.ReverseProxy {
	// Load 502 Page once
	page502, err := os.ReadFile("pages/502.html")
	if err != nil {
		log.Printf("⚠️ Warning: Could not load pages/502.html")
		page502 = []byte("502 Bad Gateway")
	}

	p := &ProxyManager{
		repo:          repo,
		defaultOrigin: defaultOrigin,
		errorPage:     page502,
	}

	return &httputil.ReverseProxy{
		Director:      p.director,
		ErrorHandler:  p.errorHandler,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Trust backend IPs
		},
	}
}

func (p *ProxyManager) director(req *http.Request) {
	incomingHost := req.Host
	var targetURL *url.URL

	// 1. Lookup Origin Record
	// Use a short timeout to avoid hanging the request on DB lookups
	ctx, cancel := context.WithTimeout(req.Context(), 1*time.Second)
	defer cancel()

	record, err := p.repo.GetOriginRecord(ctx, incomingHost)

	if err == nil && record != nil {
		rawTarget := record.Content
		
		// 2. Dynamic Scheme Selection (HTTP vs HTTPS)
		if record.OriginSSL {
			if len(rawTarget) < 4 || rawTarget[:4] != "http" {
				rawTarget = "https://" + rawTarget
			}
		} else {
			if len(rawTarget) < 4 || rawTarget[:4] != "http" {
				rawTarget = "http://" + rawTarget
			}
		}

		targetURL, _ = url.Parse(rawTarget)
	} else {
		// 3. Fallback
		targetURL, _ = url.Parse(p.defaultOrigin)
	}

	// 4. Rewrite Request
	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host
	req.Header.Set("X-Forwarded-Host", incomingHost)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Real-IP", req.RemoteAddr)
}

func (p *ProxyManager) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("🔥 Proxy Error for %s: %v", r.Host, err)
	if r.Context().Err() != nil {
		return // Client disconnected
	}
	w.WriteHeader(http.StatusBadGateway)
	w.Header().Set("Content-Type", "text/html")
	w.Write(p.errorPage)
}