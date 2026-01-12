package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Package-level variable for MySQL connection
var dnsDB *sql.DB

// ConnectDNS establishes connection to PowerDNS MySQL database with retries
func ConnectDNS(user, pass, host, dbName string) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?parseTime=true", user, pass, host, dbName)

	var db *sql.DB
	var err error

	// Retry logic: Try 10 times, waiting 2 seconds between attempts
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		db, err = sql.Open("mysql", dsn)
		if err == nil {
			err = db.Ping()
			if err == nil {
				// Success!
				fmt.Println("✅ Connected to DNS SQL Database")
				dnsDB = db
				return nil
			}
		}

		fmt.Printf("⚠️  DNS DB unavailable (Attempt %d/%d): %v. Retrying in 2s...\n", i+1, maxRetries, err)
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("failed to connect to DNS DB after %d attempts: %v", maxRetries, err)
}

// CreateDNSZone creates the SOA and NS records for a domain in PowerDNS
func CreateDNSZone(domainName string, nameservers []string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}

	// 1. Insert Domain
	// Using 'NATIVE' type for PowerDNS
	result, err := dnsDB.Exec("INSERT INTO domains (name, type) VALUES (?, 'NATIVE')", domainName)
	if err != nil {
		return fmt.Errorf("failed to insert domain into SQL: %v", err)
	}

	domainID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get zone ID: %v", err)
	}

	// 2. Insert SOA Record
	soaContent := fmt.Sprintf("%s hostmaster.%s 1 10800 3600 604800 3600",
		nameservers[0], domainName)
	
	// [UPDATED] Added change_date and created_at
	_, err = dnsDB.Exec(`
		INSERT INTO records (domain_id, name, type, content, ttl, disabled, change_date, created_at)
		VALUES (?, ?, 'SOA', ?, 3600, 0, UNIX_TIMESTAMP(), NOW())
	`, domainID, domainName, soaContent)
	if err != nil {
		return fmt.Errorf("failed to create SOA record: %v", err)
	}

	// 3. Insert NS Records
	for _, ns := range nameservers {
		// [UPDATED] Added change_date and created_at
		_, err = dnsDB.Exec(`
			INSERT INTO records (domain_id, name, type, content, ttl, disabled, change_date, created_at)
			VALUES (?, ?, 'NS', ?, 3600, 0, UNIX_TIMESTAMP(), NOW())
		`, domainID, domainName, ns)
		if err != nil {
			return fmt.Errorf("failed to create NS record: %v", err)
		}
	}

	return nil
}

// DeleteDNSZone removes a zone and all its records from PowerDNS
func DeleteDNSZone(domainName string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}
	// Cascade delete in SQL schema handles records if configured, but deleting domain is the entry point
	_, err := dnsDB.Exec("DELETE FROM domains WHERE name = ?", domainName)
	return err
}

// AddPowerDNSRecord inserts a new record with the correct IP (Real or WAF)
func AddPowerDNSRecord(name, rType, content string, proxied bool, wafIP string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}

	// Find Domain ID by matching the suffix
	var domainID int64
	row := dnsDB.QueryRow("SELECT id FROM domains WHERE ? LIKE CONCAT('%%', name) ORDER BY LENGTH(name) DESC LIMIT 1", name)
	if err := row.Scan(&domainID); err != nil {
		return fmt.Errorf("domain not found in SQL for record %s: %v", name, err)
	}

	finalContent := content
	if proxied && (rType == "A" || rType == "AAAA") {
		finalContent = wafIP
	}

	// [UPDATED] Added change_date (Unix timestamp) and created_at (DateTime)
	_, err := dnsDB.Exec(`
		INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, change_date, created_at) 
		VALUES (?, ?, ?, ?, 300, 0, 0, UNIX_TIMESTAMP(), NOW())`, 
		domainID, name, rType, finalContent)
	
	return err
}

// DeletePowerDNSRecordByContent removes a specific record
func DeletePowerDNSRecordByContent(name, rType, content string) error {
	if dnsDB == nil {
		return fmt.Errorf("DNS database not connected")
	}
	_, err := dnsDB.Exec("DELETE FROM records WHERE name=? AND type=? AND content=?", name, rType, content)
	return err
}