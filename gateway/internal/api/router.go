package api

import (
	"net/http"

	"web-app-firewall-ml-detection/internal/config"
	"web-app-firewall-ml-detection/internal/middleware"
	"web-app-firewall-ml-detection/internal/proxy"
)

func NewRouter(
	cfg *config.Config,
	wafHandler *proxy.WAFHandler,
	authHandler *AuthHandler,
	domainHandler *DomainHandler,
	ruleHandler *RuleHandler,
	dnsHandler *DNSHandler,
	logHandler *LogHandler,       // [ADDED]
	systemHandler *SystemHandler, // [ADDED]
) http.Handler {

	mux := http.NewServeMux()

	// --- WAF Traffic (Root) ---
	mux.Handle("/", wafHandler)

	// --- Auth Routes ---
	mux.HandleFunc("/api/auth/register", authHandler.Register)
	mux.HandleFunc("/api/auth/login", authHandler.Login)
	mux.HandleFunc("/api/auth/logout", authHandler.Logout)
	mux.HandleFunc("/api/auth/check", authHandler.Middleware(authHandler.CheckAuth))

	// --- Domain Routes ---
	mux.HandleFunc("/api/domains", authHandler.Middleware(domainHandler.ListDomains))
	mux.HandleFunc("/api/domains/add", authHandler.Middleware(domainHandler.AddDomain))
	mux.HandleFunc("/api/domains/verify", authHandler.Middleware(domainHandler.Verify))

	// --- DNS Routes ---
	mux.HandleFunc("/api/dns/records", authHandler.Middleware(dnsHandler.ManageRecords))

	// --- Rule Routes ---
	mux.HandleFunc("/api/rules/global", authHandler.Middleware(ruleHandler.GetGlobal))
	mux.HandleFunc("/api/rules/custom", authHandler.Middleware(ruleHandler.GetCustom))
	mux.HandleFunc("/api/rules/custom/add", authHandler.Middleware(ruleHandler.AddCustom))
	mux.HandleFunc("/api/rules/toggle", authHandler.Middleware(ruleHandler.Toggle))

	// --- Log Routes [ADDED] ---
	mux.HandleFunc("/api/logs", authHandler.Middleware(logHandler.GetLogs))
	mux.HandleFunc("/api/logs/stream", logHandler.SSEHandler) // SSE usually doesn't use standard Auth header middleware

	// --- System Status Routes [ADDED] ---
	// (Usually protected, but can be open if needed for status pages)
	mux.HandleFunc("/api/system/status", authHandler.Middleware(systemHandler.GetSystemStatus))

	return middleware.CORS(cfg)(mux)
}