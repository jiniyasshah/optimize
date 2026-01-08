package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"web-app-firewall-ml-detection/internal/config"
	"web-app-firewall-ml-detection/internal/database"
	"web-app-firewall-ml-detection/internal/handler"
	"web-app-firewall-ml-detection/internal/middleware"
	"web-app-firewall-ml-detection/internal/proxy"
	"web-app-firewall-ml-detection/internal/repository/mongo"
	"web-app-firewall-ml-detection/internal/repository/sql"
	"web-app-firewall-ml-detection/internal/service"
	"web-app-firewall-ml-detection/internal/utils/limiter"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	// 1. Config
	cfg := config.Load()
	log.Printf("🚀 Starting WAF Gateway in %s mode...", cfg.AppEnv)

	// 2. Databases
	mongoClient, err := database.Connect(cfg.MongoURI)
	if err != nil {
		log.Fatalf("❌ MongoDB Connection failed: %v", err)
	}
	defer mongoClient.Disconnect(context.Background())

	dnsDB, err := database.ConnectSQL(cfg.DNSUser, cfg.DNSPass, cfg.DNSHost, cfg.DNSName)
	if err != nil {
		log.Printf("⚠️ DNS Database Connection failed: %v", err)
	} else {
		defer dnsDB.Close()
	}

	// 3. Repositories
	userRepo := mongo.NewUserRepository(mongoClient)
	domainRepo := mongo.NewDomainRepository(mongoClient)
	ruleRepo := mongo.NewRuleRepository(mongoClient)
	logRepo := mongo.NewLogRepository(mongoClient)
	
	var dnsRepo *sql.DNSRepository
	if dnsDB != nil {
		dnsRepo = sql.NewDNSRepository(dnsDB)
	}

	// 4. Services
	authService := service.NewAuthService(userRepo, cfg.JWTSecret)
	rateLimiter := limiter.New(100, 1*time.Minute)
	wafService := service.NewWAFService(domainRepo, ruleRepo, logRepo, cfg.MLURL, rateLimiter)

	// 5. Proxy
	reverseProxy := proxy.NewProxy(domainRepo, cfg.DefaultOrigin)

	// 6. Handlers
	authHandler := handler.NewAuthHandler(authService)
	wafHandler := handler.NewWAFHandler(wafService, reverseProxy)
	domainHandler := handler.NewDomainHandler(domainRepo, dnsRepo) // Pass dnsRepo
	ruleHandler := handler.NewRuleHandler(ruleRepo)
	logHandler := handler.NewLogHandler(logRepo)       // [NEW]
	systemHandler := handler.NewSystemHandler(mongoClient, cfg.MLURL)

	// 7. Routes
	mux := http.NewServeMux()
	authMiddleware := middleware.AuthMiddleware(cfg.JWTSecret)

	// --- Public API ---
	mux.HandleFunc("/api/status", systemHandler.SystemStatus)
	mux.HandleFunc("/api/auth/register", authHandler.Register)
	mux.HandleFunc("/api/auth/login", authHandler.Login)
	mux.HandleFunc("/api/auth/logout", authHandler.Logout)
	mux.HandleFunc("/api/stream", logHandler.SSEHandler) // SSE often needs to be public or handled with query param token

	// --- Protected API ---
	mux.HandleFunc("/api/auth/check", authMiddleware(authHandler.CheckAuth))
	
	// Domains
	mux.HandleFunc("/api/domains", authMiddleware(domainHandler.ListDomains))
	mux.HandleFunc("/api/domains/add", authMiddleware(domainHandler.AddDomain))
	mux.HandleFunc("/api/domains/verify", authMiddleware(domainHandler.VerifyDomain))
	mux.HandleFunc("/api/dns/records", authMiddleware(domainHandler.ManageRecords))

	// Rules
	mux.HandleFunc("/api/rules/global", authMiddleware(ruleHandler.GetGlobalRules))
	mux.HandleFunc("/api/rules/custom", authMiddleware(ruleHandler.GetCustomRules))
	mux.HandleFunc("/api/rules/custom/add", authMiddleware(ruleHandler.AddCustomRule))
	mux.HandleFunc("/api/rules/custom/delete", authMiddleware(ruleHandler.DeleteCustomRule))
	mux.HandleFunc("/api/rules/toggle", authMiddleware(ruleHandler.ToggleRule))

	// Logs
	mux.HandleFunc("/api/logs/secure", authMiddleware(logHandler.SecuredLogsHandler))

	// --- WAF (Catch-All) ---
	mux.HandleFunc("/", wafHandler.HandleRequest)

	// 8. Middleware Chain
	loggedRouter := middleware.RequestLogger(mux)
	finalHandler := middleware.CORSMiddleware(cfg.FrontendURL)(loggedRouter)

	// 9. Start Server
	hostPolicy := func(ctx context.Context, host string) error {
		if host == "api.minishield.tech" || host == "test2.minishield.tech" {
			return nil
		}
		if _, err := domainRepo.GetByName(ctx, host); err == nil {
			return nil
		}
		return fmt.Errorf("host %s not allowed", host)
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      autocert.DirCache("certs"),
	}

httpsServer := &http.Server{
    Addr:      ":443",
    Handler:   finalHandler,
    TLSConfig: &tls. Config{
        GetCertificate: certManager.GetCertificate,
        MinVersion:  tls.VersionTLS12,
        Renegotiation: tls.RenegotiateNever,
    },
    ReadTimeout:  15 * time.Second,
    WriteTimeout: 60 * time.Second,  // Increased for SSE heartbeats (every 15s)
    IdleTimeout:  90 * time.Second,  // Connection idle timeout
}

	go func() {
		log.Printf("✅ HTTP Server running on :80")
		if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
			log.Fatalf("HTTP Server Failed: %v", err)
		}
	}()

	log.Printf("🔒 HTTPS WAF Server running on :443")
	if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("HTTPS Server Failed: %v", err)
	}
}