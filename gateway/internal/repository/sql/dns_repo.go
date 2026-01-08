package sql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"web-app-firewall-ml-detection/internal/core"

	_ "github.com/go-sql-driver/mysql" // Ensure mysql driver is imported anonymously
)

type DNSRepository struct {
	db *sql.DB
}

func NewDNSRepository(db *sql.DB) *DNSRepository {
	return &DNSRepository{db: db}
}

func (r *DNSRepository) CreateRecord(ctx context.Context, zoneName string, record core.DNSRecord) (string, error) {
	// 1. Find the numeric ID for the ZONE (e.g., "example.com")
	// We search for the ZONE NAME, not the record name.
	var domainID int64
	err := r.db.QueryRowContext(ctx, "SELECT id FROM domains WHERE name = ?", zoneName).Scan(&domainID)
	
	// 2. If the ZONE doesn't exist, create it.
	if err == sql.ErrNoRows {
		// Use zoneName here to create the container (Zone)
		res, err := r.db.ExecContext(ctx, "INSERT INTO domains (name, type) VALUES (?, 'NATIVE')", zoneName)
		if err != nil {
			return "", fmt.Errorf("failed to create domain in DNS DB: %w", err)
		}
		domainID, _ = res.LastInsertId()
	} else if err != nil {
		return "", fmt.Errorf("failed to lookup domain ID: %w", err)
	}

	// 3. Insert the Record
	query := `INSERT INTO records (domain_id, name, type, content, ttl, prio, change_date) 
	          VALUES (?, ?, ?, ?, ?, ?, ?)`

	// Use Unix timestamp for change_date
	changeDate := time.Now().Unix()

	res, err := r.db.ExecContext(ctx, query, 
		domainID, 
		record.Name,    // This is the specific record (e.g. "api.example.com")
		record.Type, 
		record.Content, 
		record.TTL, 
		0,              // Priority is usually 0 for non-MX records
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

// GetRecords retrieves all records for a specific domain name.
func (r *DNSRepository) GetRecords(ctx context.Context, domainName string) ([]core.DNSRecord, error) {
	// We join with the domains table to filter by the domain name
	query := `
		SELECT r.id, r.name, r.type, r.content, r.ttl 
		FROM records r
		JOIN domains d ON r.domain_id = d.id
		WHERE d.name = ?`

	rows, err := r.db.QueryContext(ctx, query, domainName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []core.DNSRecord
	for rows.Next() {
		var rec core.DNSRecord
		var id int64
		if err := rows.Scan(&id, &rec.Name, &rec.Type, &rec.Content, &rec.TTL); err != nil {
			return nil, err
		}
		rec.ID = fmt.Sprintf("%d", id)
		// Note: We don't populate fields like CreatedAt or Proxied here if they aren't in standard PowerDNS tables.
		records = append(records, rec)
	}

	return records, nil
}

// DeleteRecord removes a record by its ID.
func (r *DNSRepository) DeleteRecord(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM records WHERE id = ?", id)
	return err
}

// GetRecordByID fetches a single record.
func (r *DNSRepository) GetRecordByID(ctx context.Context, id string) (*core.DNSRecord, error) {
	query := "SELECT id, name, type, content, ttl FROM records WHERE id = ?"
	
	var rec core.DNSRecord
	var intID int64
	err := r.db.QueryRowContext(ctx, query, id).Scan(&intID, &rec.Name, &rec.Type, &rec.Content, &rec.TTL)
	if err != nil {
		return nil, err
	}
	rec.ID = fmt.Sprintf("%d", intID)
	return &rec, nil
}