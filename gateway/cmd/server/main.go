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
	"web-app-firewall-ml-detection/internal/repository/sql" // [NEW] Import SQL Repo
	"web-app-firewall-ml-detection/internal/service"
	"web-app-firewall-ml-detection/internal/utils/limiter"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	// 1. Load Configuration
	cfg := config.Load()
	log.Printf("🚀 Starting WAF Gateway in %s mode...", cfg.AppEnv)

	// 2. Connect to Databases

	// A. Connect to MongoDB
	log.Println("🔌 Connecting to MongoDB...")
	mongoClient, err := database.Connect(cfg.MongoURI)
	if err != nil {
		log.Fatalf("❌ MongoDB Connection failed: %v", err)
	}
	defer mongoClient.Disconnect(context.Background())

	// B. [NEW] Connect to DNS Database (MariaDB/MySQL)
	log.Println("🔌 Connecting to DNS Database...")
	// Ensure you have implemented ConnectSQL in internal/database
	dnsDB, err := database.ConnectSQL(cfg.DNSUser, cfg.DNSPass, cfg.DNSHost, cfg.DNSName)
	if err != nil {
		// We log error but don't crash, in case you want to run WAF without DNS features initially
		log.Printf("⚠️ DNS Database Connection failed: %v", err)
	} else {
		defer dnsDB.Close()
		log.Println("✅ Connected to DNS Database")
	}

	// 3. Initialize Repositories
	userRepo := mongo.NewUserRepository(mongoClient)
	domainRepo := mongo.NewDomainRepository(mongoClient)
	ruleRepo := mongo.NewRuleRepository(mongoClient)
	logRepo := mongo.NewLogRepository(mongoClient)

	// [NEW] Initialize DNS SQL Repository
	var dnsRepo *sql.DNSRepository
	if dnsDB != nil {
		dnsRepo = sql.NewDNSRepository(dnsDB)
	}

	// 4. Initialize Services
	authService := service.NewAuthService(userRepo, cfg.JWTSecret)

	// Initialize Limiter
	rateLimiter := limiter.New(100, 1*time.Minute)

	// Initialize WAF Service
	wafService := service.NewWAFService(domainRepo, ruleRepo, logRepo, cfg.MLURL, rateLimiter)

	// 5. Initialize Proxy
	reverseProxy := proxy.NewProxy(domainRepo, cfg.DefaultOrigin)

	// 6. Initialize Handlers
	authHandler := handler.NewAuthHandler(authService)
	wafHandler := handler.NewWAFHandler(wafService, reverseProxy)

	// [UPDATED] Pass dnsRepo to DomainHandler so it can manage Records
	// You need to update NewDomainHandler signature in internal/handler/domain.go
	domainHandler := handler.NewDomainHandler(domainRepo, dnsRepo)

	ruleHandler := handler.NewRuleHandler(ruleRepo)

	// 7. Define Routes
	mux := http.NewServeMux()

	// Public Routes
	mux.HandleFunc("/api/auth/register", authHandler.Register)
	mux.HandleFunc("/api/auth/login", authHandler.Login)
	mux.HandleFunc("/api/auth/logout", authHandler.Logout)

	// Protected Routes
	authMiddleware := middleware.AuthMiddleware(cfg.JWTSecret)
	mux.HandleFunc("/api/domains", authMiddleware(domainHandler.ListDomains))
	mux.HandleFunc("/api/domains/add", authMiddleware(domainHandler.AddDomain))
	mux.HandleFunc("/api/rules/global", authMiddleware(ruleHandler.GetGlobalRules))
	mux.HandleFunc("/api/rules/toggle", authMiddleware(ruleHandler.ToggleRule))

	// WAF Traffic Handler
	mux.HandleFunc("/", wafHandler.HandleRequest)

	// 8. MIDDLEWARE CHAIN
	loggedRouter := middleware.RequestLogger(mux)
	finalHandler := middleware.CORSMiddleware(cfg.FrontendURL)(loggedRouter)

	// ---------------------------------------------------------
	// 9. Server Start
	// ---------------------------------------------------------

	hostPolicy := func(ctx context.Context, host string) error {
		if host == "api.minishield.tech" || host == "dashboard.minishield.tech" {
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
		Addr:    ":443",
		Handler: finalHandler,
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		log.Printf("✅ HTTP Server running on :80 (Redirects to HTTPS)")
		if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
			log.Fatalf("HTTP Server Failed: %v", err)
		}
	}()

	log.Printf("🔒 HTTPS WAF Server running on :443")
	if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("HTTPS Server Failed: %v", err)
	}
}