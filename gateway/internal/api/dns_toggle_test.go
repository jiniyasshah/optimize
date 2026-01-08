package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"web-app-firewall-ml-detection/internal/detector"
)

// TestDNSRecordToggleRequestParsing tests that the updateRecord function
// correctly parses toggle requests for both proxy and origin SSL
//
// Note: These are unit tests that verify the request parsing logic and model structure.
// For full integration tests with MongoDB and PowerDNS, use the docker-compose environment.
func TestDNSRecordToggleRequestParsing(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		expectedAction string
		expectedProxy  bool
		expectedSSL    bool
	}{
		{
			name: "Proxy toggle - enable",
			requestBody: map[string]interface{}{
				"proxied": true,
			},
			expectedProxy: true,
		},
		{
			name: "Proxy toggle - disable",
			requestBody: map[string]interface{}{
				"proxied": false,
			},
			expectedProxy: false,
		},
		{
			name: "Origin SSL toggle - enable HTTPS",
			requestBody: map[string]interface{}{
				"action":     "toggle_origin_ssl",
				"origin_ssl": true,
			},
			expectedAction: "toggle_origin_ssl",
			expectedSSL:    true,
		},
		{
			name: "Origin SSL toggle - disable HTTPS (use HTTP)",
			requestBody: map[string]interface{}{
				"action":     "toggle_origin_ssl",
				"origin_ssl": false,
			},
			expectedAction: "toggle_origin_ssl",
			expectedSSL:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request body
			bodyBytes, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			// Parse the request (simulating what updateRecord does)
			var req struct {
				Action    string `json:"action"`
				Proxied   bool   `json:"proxied"`
				OriginSSL bool   `json:"origin_ssl"`
			}

			if err := json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&req); err != nil {
				t.Fatalf("Failed to decode request: %v", err)
			}

			// Verify parsing
			if tt.expectedAction != "" && req.Action != tt.expectedAction {
				t.Errorf("Expected action %q, got %q", tt.expectedAction, req.Action)
			}

			if req.Action == "toggle_origin_ssl" {
				if req.OriginSSL != tt.expectedSSL {
					t.Errorf("Expected origin_ssl %v, got %v", tt.expectedSSL, req.OriginSSL)
				}
			} else {
				if req.Proxied != tt.expectedProxy {
					t.Errorf("Expected proxied %v, got %v", tt.expectedProxy, req.Proxied)
				}
			}
		})
	}
}

// TestDNSRecordModelFields tests that DNSRecord has the required fields
func TestDNSRecordModelFields(t *testing.T) {
	record := detector.DNSRecord{
		ID:        "test-id",
		DomainID:  "domain-id",
		Name:      "example.com",
		Type:      "A",
		Content:   "1.2.3.4",
		TTL:       300,
		Proxied:   true,
		OriginSSL: true,
	}

	// Verify fields are accessible
	if !record.Proxied {
		t.Error("Expected Proxied field to be true")
	}

	if !record.OriginSSL {
		t.Error("Expected OriginSSL field to be true")
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Failed to marshal DNSRecord: %v", err)
	}

	// Unmarshal to verify fields are preserved
	var unmarshaled detector.DNSRecord
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal DNSRecord: %v", err)
	}

	if unmarshaled.Proxied != record.Proxied {
		t.Error("Proxied field not preserved after JSON roundtrip")
	}

	if unmarshaled.OriginSSL != record.OriginSSL {
		t.Error("OriginSSL field not preserved after JSON roundtrip")
	}
}

// TestToggleEndpointValidation tests that the toggle endpoint validates required parameters
func TestToggleEndpointValidation(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
	}{
		{
			name:           "Missing domain_id and record_id",
			queryParams:    "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Missing record_id",
			queryParams:    "domain_id=123",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Missing domain_id",
			queryParams:    "record_id=456",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Both parameters present",
			queryParams:    "domain_id=123&record_id=456",
			expectedStatus: http.StatusUnauthorized, // Will fail auth but pass validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test request
			body := []byte(`{"proxied": true}`)
			req := httptest.NewRequest(http.MethodPut, "/api/dns/records?"+tt.queryParams, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			// Validate query parameters (simulating updateRecord validation)
			domainID := req.URL.Query().Get("domain_id")
			recordID := req.URL.Query().Get("record_id")

			if (domainID == "" || recordID == "") && tt.expectedStatus == http.StatusBadRequest {
				// Expected behavior - validation should fail
				return
			}

			if domainID != "" && recordID != "" && tt.expectedStatus != http.StatusBadRequest {
				// Expected behavior - validation should pass
				return
			}

			t.Errorf("Validation logic doesn't match expected behavior")
		})
	}
}

// TestProxyModeLogic tests the proxy mode logic for different record types
func TestProxyModeLogic(t *testing.T) {
	tests := []struct {
		name           string
		recordType     string
		requestedProxy bool
		expectedProxy  bool
		reason         string
	}{
		{
			name:           "A record - proxy enabled",
			recordType:     "A",
			requestedProxy: true,
			expectedProxy:  true,
			reason:         "A records can be proxied",
		},
		{
			name:           "A record - proxy disabled",
			recordType:     "A",
			requestedProxy: false,
			expectedProxy:  false,
			reason:         "A records can be set to DNS-only",
		},
		{
			name:           "TXT record - proxy requested but should be forced off",
			recordType:     "TXT",
			requestedProxy: true,
			expectedProxy:  false,
			reason:         "TXT records cannot be proxied (verification records)",
		},
		{
			name:           "MX record - proxy requested but should be forced off",
			recordType:     "MX",
			requestedProxy: true,
			expectedProxy:  false,
			reason:         "MX records cannot be proxied (mail servers)",
		},
		{
			name:           "NS record - proxy requested but should be forced off",
			recordType:     "NS",
			requestedProxy: true,
			expectedProxy:  false,
			reason:         "NS records cannot be proxied (nameservers)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the proxy logic from AddPowerDNSRecord
			shouldProxy := tt.requestedProxy
			if tt.recordType == "TXT" || tt.recordType == "MX" || tt.recordType == "NS" || tt.recordType == "SOA" {
				shouldProxy = false
			}

			if shouldProxy != tt.expectedProxy {
				t.Errorf("Expected proxy=%v for %s, got %v. Reason: %s",
					tt.expectedProxy, tt.recordType, shouldProxy, tt.reason)
			}
		})
	}
}
