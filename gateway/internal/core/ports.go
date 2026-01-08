package core

import (
	"context"
)

// UserRepository handles user authentication and management
type UserRepository interface {
	Create(ctx context.Context, user User) error
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)
}

// DomainRepository handles domains and DNS records
type DomainRepository interface {
	// Domain Methods
	Create(ctx context.Context, domain Domain) (Domain, error)
	GetByUser(ctx context.Context, userID string) ([]Domain, error)
	GetByName(ctx context.Context, name string) (*Domain, error)
	GetByID(ctx context.Context, id string) (*Domain, error)
	UpdateStatus(ctx context.Context, id, status string) error
	RevokeOldOwnership(ctx context.Context, name, newOwnerID string) error
	GetAll(ctx context.Context) ([]Domain, error) // For cache reloading

	// DNS Methods
	CreateRecord(ctx context.Context, record DNSRecord) (string, error)
	GetRecords(ctx context.Context, domainID string) ([]DNSRecord, error)
	GetRecordByID(ctx context.Context, id string) (*DNSRecord, error)
	DeleteRecord(ctx context.Context, id string) error
	UpdateRecordProxy(ctx context.Context, id string, proxied bool) error
	UpdateRecordSSL(ctx context.Context, id string, ssl bool) error
	GetAllRecords(ctx context.Context) ([]DNSRecord, error) // For cache reloading
	CheckDuplicateRecord(ctx context.Context, domainID, name, rType, content string) (bool, error)
	UpdateProxyMode(ctx context.Context, id string, enabled bool) error
	// Routing Helper
	GetOriginRecord(ctx context.Context, host string) (*DNSRecord, error)
}

// RuleRepository handles WAF rules and policies
type RuleRepository interface {
	GetAll(ctx context.Context) ([]WAFRule, error)
	Add(ctx context.Context, rule WAFRule) error
	Update(ctx context.Context, rule WAFRule) error
	Delete(ctx context.Context, ruleID, ownerID string) error
	
	// Policies
	GetPolicies(ctx context.Context, userID string) ([]RulePolicy, error)
	GetAllPolicies(ctx context.Context) ([]RulePolicy, error)
	UpsertPolicy(ctx context.Context, policy RulePolicy) error
}

// LogRepository handles storing and retrieving attack logs
type LogRepository interface {
	LogAttack(ctx context.Context, log AttackLog) error
	GetLogs(ctx context.Context, filter LogFilter) (*PaginatedLogs, error)
}