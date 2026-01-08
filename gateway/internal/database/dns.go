package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql" // Ensure you run 'go mod tidy'
)

var DNSDB *sql.DB

// ConnectDNS establishes connection to PowerDNS MariaDB/MySQL
func ConnectDNS(user, pass, host, dbName string) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?parseTime=true", user, pass, host, dbName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	if err := db.Ping(); err != nil {
		return err
	}
	DNSDB = db
	return nil
}

// CreateDNSZone provisions the domain in PowerDNS so NS records work
func CreateDNSZone(domainName string, nameservers []string) error {
	if DNSDB == nil {
		log.Println("⚠️ DNS DB not connected. Skipping PowerDNS zone creation.")
		return nil
	}

	// 1. Create Domain in 'domains' table (NATIVE type for PowerDNS)
	res, err := DNSDB.Exec("INSERT INTO domains (name, type) VALUES (?, 'NATIVE')", domainName)
	if err != nil {
		return fmt.Errorf("failed to insert domain: %v", err)
	}
	
	domainID, err := res.LastInsertId()
	if err != nil {
		return err
	}

	// 2. Add SOA Record (Start of Authority)
	// Serial format: YYYYMMDDNN
	serial := time.Now().Format("2006010201")
	soaContent := fmt.Sprintf("ns1.minishield.tech. hostmaster.minishield.tech. %s 10800 3600 604800 3600", serial)
	
	_, err = DNSDB.Exec("INSERT INTO records (domain_id, name, type, content, ttl, prio) VALUES (?, ?, 'SOA', ?, 3600, 0)", domainID, domainName, soaContent)
	if err != nil {
		return fmt.Errorf("failed to insert SOA: %v", err)
	}

	// 3. Add NS Records
	for _, ns := range nameservers {
		_, err = DNSDB.Exec("INSERT INTO records (domain_id, name, type, content, ttl, prio) VALUES (?, ?, 'NS', ?, 3600, 0)", domainID, domainName, ns)
		if err != nil {
			log.Printf("⚠️ Failed to add NS record %s: %v", ns, err)
		}
	}

	return nil
}