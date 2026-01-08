# DNS Record Toggle Features

This document describes the proxy/DNS-only toggle and HTTP/HTTPS toggle features implemented in the WAF system.

## Overview

The WAF system provides two independent toggle features for DNS records:

1. **Proxy Toggle (DNS-only vs WAF Proxy Mode)**
2. **Origin SSL Toggle (HTTP vs HTTPS)**

## Feature 1: Proxy Toggle (DNS-only vs WAF Proxy)

### Purpose
Controls whether traffic is routed through the WAF for inspection and protection, or goes directly to the origin server.

### How It Works

#### Proxied Mode (proxied=true)
- DNS record in PowerDNS points to the WAF IP address
- All traffic flows through the WAF gateway
- Requests are inspected by ML models and WAF rules
- Malicious requests are blocked
- Clean requests are forwarded to the origin server

#### DNS-only Mode (proxied=false)
- DNS record in PowerDNS points directly to the origin server IP
- Traffic bypasses the WAF completely
- No inspection or protection is applied
- Useful for services that don't need WAF protection (e.g., mail servers, verification records)

### API Usage

**Endpoint:** `PUT /api/dns/records?domain_id=<domain_id>&record_id=<record_id>`

**Request Body:**
```json
{
  "proxied": true
}
```

or

```json
{
  "proxied": false
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Proxy status updated",
  "data": {
    "proxied": true
  }
}
```

### Implementation Details

**Files Modified:**
- `gateway/internal/detector/models.go` - Added `Proxied` field to `DNSRecord`
- `gateway/internal/api/dns.go` - Implemented toggle logic in `updateRecord()`
- `gateway/internal/database/mongo.go` - Added `UpdateDNSRecordProxy()` function
- `gateway/internal/database/dns.go` - Modified `AddPowerDNSRecord()` to handle proxied state

**Logic Flow:**
1. Parse request with `proxied` boolean
2. Verify user ownership of the domain
3. Fetch old record state from MongoDB
4. Delete old PowerDNS record (with correct content based on old proxy state)
5. Update MongoDB with new proxy state
6. Add new PowerDNS record (with correct content based on new proxy state)

## Feature 2: Origin SSL Toggle (HTTP vs HTTPS)

### Purpose
Controls the protocol (HTTP or HTTPS) used by the WAF to connect to the origin server, independent of the client's connection to the WAF.

### How It Works

#### HTTPS to Origin (origin_ssl=true)
- Client connects to WAF via HTTPS (always)
- WAF connects to origin server via HTTPS
- Use when origin server has SSL certificate
- End-to-end encryption maintained

#### HTTP to Origin (origin_ssl=false)
- Client connects to WAF via HTTPS (always)
- WAF connects to origin server via HTTP
- Use when origin server doesn't have SSL or is on private network
- Encryption only between client and WAF

### API Usage

**Endpoint:** `PUT /api/dns/records?domain_id=<domain_id>&record_id=<record_id>`

**Request Body:**
```json
{
  "action": "toggle_origin_ssl",
  "origin_ssl": true
}
```

or

```json
{
  "action": "toggle_origin_ssl",
  "origin_ssl": false
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Origin SSL status updated",
  "data": {
    "origin_ssl": true
  }
}
```

### Implementation Details

**Files Modified:**
- `gateway/internal/detector/models.go` - Added `OriginSSL` field to `DNSRecord`
- `gateway/internal/api/dns.go` - Added branch for `toggle_origin_ssl` action
- `gateway/internal/database/mongo.go` - Added `UpdateDNSRecordOriginSSL()` function
- `gateway/cmd/server/main.go` - Modified proxy director to check `OriginSSL` flag

**Logic Flow:**
1. Parse request with `action="toggle_origin_ssl"` and `origin_ssl` boolean
2. Verify user ownership of the domain
3. Update MongoDB `origin_ssl` field for the record
4. No PowerDNS changes needed (this only affects WAF proxy behavior)

**Proxy Director Logic:**
```go
if record.OriginSSL {
    if len(rawTarget) < 4 || rawTarget[:4] != "http" {
        rawTarget = "https://" + rawTarget
    }
} else {
    if len(rawTarget) < 4 || rawTarget[:4] != "http" {
        rawTarget = "http://" + rawTarget
    }
}
```

## Combined Usage Examples

### Example 1: Full WAF Protection with HTTPS Origin
```bash
# Enable proxy mode
curl -X PUT "https://api.example.com/api/dns/records?domain_id=123&record_id=456" \
  -H "Content-Type: application/json" \
  -H "Cookie: token=<jwt_token>" \
  -d '{"proxied": true}'

# Enable HTTPS to origin
curl -X PUT "https://api.example.com/api/dns/records?domain_id=123&record_id=456" \
  -H "Content-Type: application/json" \
  -H "Cookie: token=<jwt_token>" \
  -d '{"action": "toggle_origin_ssl", "origin_ssl": true}'
```

### Example 2: DNS-only Mode (No WAF)
```bash
# Disable proxy mode (DNS-only)
curl -X PUT "https://api.example.com/api/dns/records?domain_id=123&record_id=456" \
  -H "Content-Type: application/json" \
  -H "Cookie: token=<jwt_token>" \
  -d '{"proxied": false}'
```

### Example 3: WAF Protection with HTTP Origin
```bash
# Enable proxy mode
curl -X PUT "https://api.example.com/api/dns/records?domain_id=123&record_id=456" \
  -H "Content-Type: application/json" \
  -H "Cookie: token=<jwt_token>" \
  -d '{"proxied": true}'

# Use HTTP to origin (for backend on private network without SSL)
curl -X PUT "https://api.example.com/api/dns/records?domain_id=123&record_id=456" \
  -H "Content-Type: application/json" \
  -H "Cookie: token=<jwt_token>" \
  -d '{"action": "toggle_origin_ssl", "origin_ssl": false}'
```

## Security Considerations

1. **Proxy Mode Security:**
   - TXT, MX, NS, and SOA records cannot be proxied (they're forced to DNS-only mode)
   - This prevents breaking verification systems that rely on direct DNS lookups

2. **Origin SSL Security:**
   - SSL verification is disabled for backend connections (`InsecureSkipVerify: true`)
   - This allows the WAF to connect to origins with self-signed certificates
   - Consider the security implications before using this in production

3. **Authentication:**
   - Both toggle operations require valid JWT authentication
   - Users can only modify records for domains they own

## Testing

To test the toggle features:

1. Build and run the gateway:
```bash
cd gateway
go build -o bin/gateway ./cmd/server
./bin/gateway
```

2. Create a DNS record with default settings

3. Toggle proxy mode and verify DNS records in PowerDNS

4. Toggle origin SSL and verify proxy behavior in logs

5. Test traffic flow to ensure correct routing

## Troubleshooting

### Proxy Toggle Not Working
- Check PowerDNS connection and permissions
- Verify WAF_PUBLIC_IP environment variable is set
- Check logs for "Failed to update DNS" errors

### Origin SSL Toggle Not Working
- Verify MongoDB connection
- Check if record exists and user has ownership
- Look for "Failed to update Origin SSL" errors in logs

### Traffic Not Routing Correctly
- Verify DNS propagation (may take time)
- Check proxy director logs for routing decisions
- Ensure GetOriginRecord() is fetching correct record state
