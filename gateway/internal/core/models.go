package core

import (
	"regexp"
	"time"
)

// --- User Models ---

type User struct {
	ID        string    `bson:"_id,omitempty" json:"id"`
	Name      string    `bson:"name" json:"name"`
	Email     string    `bson:"email" json:"email"`
	Password  string    `bson:"password" json:"-"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

type UserInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// --- Domain & DNS Models ---

type Domain struct {
	ID        string    `bson:"_id,omitempty" json:"id"`
	UserID    string    `bson:"user_id" json:"user_id"`
	Name      string    `bson:"name" json:"name"`
	Status    string    `bson:"status" json:"status"` // active, pending, etc.
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

type DNSRecord struct {
	ID        string    `bson:"_id,omitempty" json:"id"`
	DomainID  string    `bson:"domain_id" json:"domain_id"`
	Name      string    `bson:"name" json:"name"`
	Type      string    `bson:"type" json:"type"`
	Content   string    `bson:"content" json:"content"`
	TTL       int       `bson:"ttl" json:"ttl"`
	Proxied   bool      `bson:"proxied" json:"proxied"`
	OriginSSL bool      `bson:"origin_ssl" json:"origin_ssl"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

// --- WAF Rule Models ---

type WAFRule struct {
	ID          string      `bson:"_id,omitempty" json:"id"`
	OwnerID     string      `bson:"owner_id,omitempty" json:"owner_id,omitempty"` // Empty = Global
	Name        string      `bson:"name" json:"name"`
	Description string      `bson:"description" json:"description"`
	Conditions  []Condition `bson:"conditions" json:"conditions"`
	OnMatch     MatchAction `bson:"on_match" json:"on_match"`
	Priority    int         `bson:"priority" json:"priority"`
	Enabled     bool        `bson:"enabled" json:"enabled"`
}

type Condition struct {
	Field         string         `bson:"field" json:"field"`
	Operator      string         `bson:"operator" json:"operator"`
	Value         interface{}    `bson:"value" json:"value"`
	CompiledRegex *regexp.Regexp `bson:"-" json:"-"`
}

type MatchAction struct {
	Action    string   `bson:"action" json:"action"` // block, allow, monitor
	ScoreAdd  int      `bson:"score_add" json:"score_add"`
	Tags      []string `bson:"tags" json:"tags"`
	HardBlock bool     `bson:"hard_block" json:"hard_block"`
}

type RulePolicy struct {
	UserID   string `bson:"user_id"`
	RuleID   string `bson:"rule_id"`
	DomainID string `bson:"domain_id"`
	Enabled  bool   `bson:"enabled"`
}

// --- Log Models ---

type AttackLog struct {
	ID          string                 `bson:"_id,omitempty" json:"id"`
	UserID      string                 `bson:"user_id" json:"user_id"`
	DomainID    string                 `bson:"domain_id" json:"domain_id"`
	Timestamp   time.Time              `bson:"timestamp" json:"timestamp"`
	ClientIP    string                 `bson:"client_ip" json:"client_ip"`
	RequestPath string                 `bson:"request_path" json:"request_path"`
	Reason      string                 `bson:"reason" json:"reason"`
	Action      string                 `bson:"action" json:"action"`
	Source      string                 `bson:"source" json:"source"`
	Tags        []string               `bson:"tags" json:"tags"`
	RuleScore   int                    `bson:"rule_score" json:"rule_score"`
	MLScore     float64                `bson:"ml_score" json:"ml_score"`
	Request     map[string]interface{} `bson:"request" json:"request"` // FullRequest
	Trigger     string                 `bson:"trigger_payload" json:"trigger_payload"`
}

type PaginatedLogs struct {
	Data       []AttackLog `json:"data"`
	Pagination struct {
		CurrentPage int64 `json:"current_page"`
		TotalPages  int64 `json:"total_pages"`
		TotalItems  int64 `json:"total_items"`
		PerPage     int64 `json:"per_page"`
	} `json:"pagination"`
}

type LogFilter struct {
	UserID   string
	DomainID string
	Page     int64
	Limit    int64
}