package sql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"web-app-firewall-ml-detection/internal/core"

	_ "github.com/go-sql-driver/mysql"
)

type DNSRepository struct {
	db *sql.DB
}

func NewDNSRepository(db *sql.DB) *DNSRepository {
	return &DNSRepository{db: db}
}

// CreateRecord now accepts zoneName to ensure records are grouped under the correct Domain ID
func (r *DNSRepository) CreateRecord(ctx context.Context, zoneName string, record core.DNSRecord) (string, error) {
	var domainID int64
	// 1. Find Zone ID
	err := r.db.QueryRowContext(ctx, "SELECT id FROM domains WHERE name = ?", zoneName).Scan(&domainID)
	
	if err == sql.ErrNoRows {
		// 2. Create Zone if missing
		res, err := r.db.ExecContext(ctx, "INSERT INTO domains (name, type) VALUES (?, 'NATIVE')", zoneName)
		if err != nil {
			return "", fmt.Errorf("failed to create domain in DNS DB: %w", err)
		}
		domainID, _ = res.LastInsertId()
	} else if err != nil {
		return "", fmt.Errorf("failed to lookup domain ID: %w", err)
	}

	// 3. Insert Record
	query := `INSERT INTO records (domain_id, name, type, content, ttl, prio, change_date) 
	          VALUES (?, ?, ?, ?, ?, ?, ?)`

	changeDate := time.Now().Unix()
	res, err := r.db.ExecContext(ctx, query, 
		domainID, 
		record.Name, 
		record.Type, 
		record.Content, 
		record.TTL, 
		0, 
		changeDate,
	)

	if err != nil {
		return "", err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%d", id), nil
}

// ... (GetRecords, DeleteRecord, GetRecordByID remain the same as before)
func (r *DNSRepository) GetRecords(ctx context.Context, domainName string) ([]core.DNSRecord, error) {
	query := `
		SELECT r.id, r.name, r.type, r.content, r.ttl 
		FROM records r
		JOIN domains d ON r.domain_id = d.id
		WHERE d.name = ?`

	rows, err := r.db.QueryContext(ctx, query, domainName)
	if err != nil { return nil, err }
	defer rows.Close()

	var records []core.DNSRecord
	for rows.Next() {
		var rec core.DNSRecord
		var id int64
		rows.Scan(&id, &rec.Name, &rec.Type, &rec.Content, &rec.TTL)
		rec.ID = fmt.Sprintf("%d", id)
		records = append(records, rec)
	}
	return records, nil
}