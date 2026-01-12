package config

import (
	"os"
	"strings"
)

type Config struct {
	AppEnv         string
	Port           string
	MongoURI       string
	FrontendURL    string
	AllowedOrigins []string
	
	// WAF Settings
	OriginURL   string
	MLURL       string
	WafPublicIP string
	
	// DNS DB
	DNSUser string
	DNSPass string
	DNSHost string
	DNSName string

	// Security
	JWTSecret string
}

func Load() *Config {
	return &Config{
		AppEnv:         getEnv("APP_ENV", "development"),
		Port:           getEnv("PORT", "443"),
		MongoURI:       getEnv("MONGO_URI", "mongodb://mongo:27017"),
		FrontendURL:    getEnv("FRONTEND_URL", "https://www.minishield.tech"),
		AllowedOrigins: strings.Split(getEnv("FRONTEND_URL", "https://www.minishield.tech"), ","),
		
		OriginURL:   getEnv("ORIGIN_URL", "http://origin:3000"),
		MLURL:       getEnv("ML_URL", "http://ml_scorer:8000/predict"),
		WafPublicIP: getEnv("WAF_PUBLIC_IP", "64.227.156.70"),

		DNSUser: getEnv("DNS_DB_USER", "pdns"),
		DNSPass: getEnv("DNS_DB_PASS", "pdns_password"),
		DNSHost: getEnv("DNS_DB_HOST", "dns_sql_db"),
		DNSName: getEnv("DNS_DB_NAME", "powerdns"),

		// Ideally load this from a secure secret manager or ENV, never hardcode in prod
		JWTSecret: getEnv("JWT_SECRET", "super_secret_waf_key_change_me"),
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}