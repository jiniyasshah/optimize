package config

import (
	"os"
	"strings"
)

type Config struct {
	// App Settings
	AppEnv      string 
	Port        string
	WAFPublicIP string

	// URLs
	FrontendURL   string
	DefaultOrigin string
	MLURL         string

	// Secrets
	JWTSecret string

	// Database - MongoDB
	MongoURI string

	// Database - DNS (SQL)
	DNSUser string
	DNSPass string
	DNSHost string
	DNSName string
}

func Load() *Config {
	return &Config{
		// App
		AppEnv:      getEnv("APP_ENV", "development"),
		Port:        getEnv("PORT", ":80"),
		WAFPublicIP: getEnv("WAF_PUBLIC_IP", "157.245.100.147"),

		// URLs
		FrontendURL:   getEnv("FRONTEND_URL", "https://www.minishield.tech"),
		DefaultOrigin: getEnv("ORIGIN_URL", "http://origin:3000"),
		MLURL:         getEnv("ML_URL", "http://ml_scorer:8000/predict"),

		// Secrets
		JWTSecret: getEnv("JWT_SECRET", "super_secret_waf_key_change_me"),
		MongoURI: getEnv("MONGO_URI", "mongodb://mongo:27017"),
		DNSUser: getEnv("DNS_DB_USER", "pdns"),
		DNSPass: getEnv("DNS_DB_PASS", "pdns_password"),
		DNSHost: getEnv("DNS_DB_HOST", "dns_sql_db"),
		DNSName: getEnv("DNS_DB_NAME", "powerdns"),
	}
}

// handle fallback values
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return strings.TrimSpace(value)
	}
	return fallback
}