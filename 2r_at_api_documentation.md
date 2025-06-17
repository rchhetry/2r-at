# 2R-AT Security Platform API Documentation

## Overview

The 2R-AT Security Platform provides a comprehensive REST API for vulnerability scanning and security assessment. This API enables integration with existing security tools, automated workflows, and custom applications.

**Base URL:** `https://your-domain.com/api`
**Version:** v1
**Authentication:** JWT Bearer Token

## Table of Contents

1. [Authentication](#authentication)
2. [User Management](#user-management)
3. [Scan Management](#scan-management)
4. [Reporting](#reporting)
5. [Statistics](#statistics)
6. [System](#system)
7. [Error Handling](#error-handling)
8. [Rate Limiting](#rate-limiting)
9. [SDK Examples](#sdk-examples)

## Authentication

### Register User
Creates a new user account.

**Endpoint:** `POST /auth/register`

**Request Body:**
```json
{
    "email": "user@example.com",
    "name": "John Doe",
    "password": "SecurePassword123!",
    "company": "Example Corp" // optional
}
```

**Response:**
```json
{
    "message": "User created successfully",
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "user@example.com",
        "name": "John Doe",
        "role": "user"
    }
}
```

**Status Codes:**
- `201` - User created successfully
- `400` - Invalid input data
- `409` - User already exists

### Login
Authenticates a user and returns an access token.

**Endpoint:** `POST /auth/login`

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "SecurePassword123!"
}
```

**Response:**
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "user@example.com",
        "name": "John Doe",
        "role": "user",
        "plan": "basic"
    }
}
```

**Status Codes:**
- `200` - Login successful
- `401` - Invalid credentials
- `400` - Missing required fields

### Token Usage
Include the JWT token in the Authorization header for protected endpoints:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## User Management

### Get User Profile
Retrieves the current user's profile information.

**Endpoint:** `GET /user/profile`
**Authentication:** Required

**Response:**
```json
{
    "user": {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "user@example.com",
        "name": "John Doe",
        "company": "Example Corp",
        "role": "user",
        "plan": "basic",
        "created_at": "2024-01-15T10:30:00Z",
        "last_login": "2024-01-20T14:45:00Z",
        "scan_quota": 10,
        "scans_used": 3
    }
}
```

### Update User Profile
Updates the current user's profile information.

**Endpoint:** `PUT /user/profile`
**Authentication:** Required

**Request Body:**
```json
{
    "name": "John Smith",
    "company": "New Company Ltd"
}
```

**Response:**
```json
{
    "message": "Profile updated successfully",
    "user": {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "user@example.com",
        "name": "John Smith",
        "company": "New Company Ltd"
    }
}
```

## Scan Management

### Create Scan
Initiates a new vulnerability scan.

**Endpoint:** `POST /scans`
**Authentication:** Required

**Request Body:**
```json
{
    "target": "https://example.com",
    "scan_name": "Example Corp Security Assessment",
    "options": {
        "severity": "medium",
        "tags": "cve,sqli,xss",
        "templates": "http,ssl,dns",
        "timeout": 3600,
        "concurrency": 10
    }
}
```

**Response:**
```json
{
    "scan_id": "scan-550e8400-e29b-41d4-a716-446655440000",
    "status": "queued",
    "message": "Scan started successfully",
    "estimated_completion": "2024-01-20T15:30:00Z"
}
```

**Scan Options:**
- `severity`: Filter by severity level (`info`, `low`, `medium`, `high`, `critical`)
- `tags`: Comma-separated list of vulnerability tags to include
- `templates`: Specific Nuclei template categories to use
- `timeout`: Maximum scan duration in seconds (default: 3600)
- `concurrency`: Number of concurrent requests (default: 10)

**Status Codes:**
- `201` - Scan created successfully
- `400` - Invalid target or options
- `429` - Scan quota exceeded

### Get Scans
Retrieves a list of user's scans.

**Endpoint:** `GET /scans`
**Authentication:** Required

**Query Parameters:**
- `limit`: Maximum number of results (default: 50, max: 100)
- `offset`: Number of results to skip (default: 0)
- `status`: Filter by scan status (`queued`, `running`, `completed`, `failed`)
- `sort`: Sort order (`created_at`, `-created_at`, `target`)

**Response:**
```json
{
    "scans": [
        {
            "id": "scan-550e8400-e29b-41d4-a716-446655440000",
            "target": "https://example.com",
            "scan_name": "Example Corp Security Assessment",
            "status": "completed",
            "created_at": "2024-01-20T14:00:00Z",
            "started_at": "2024-01-20T14:01:00Z",
            "completed_at": "2024-01-20T14:15:00Z",
            "scan_duration": 840,
            "vulnerabilities_found": 5,
            "progress": 100
        }
    ],
    "pagination": {
        "total": 25,
        "limit": 50,
        "offset": 0,
        "has_next": false
    }
}
```

### Get Scan Details
Retrieves detailed information about a specific scan.

**Endpoint:** `GET /scans/{scan_id}`
**Authentication:** Required

**Response:**
```json
{
    "scan": {
        "id": "scan-550e8400-e29b-41d4-a716-446655440000",
        "target": "https://example.com",
        "scan_name": "Example Corp Security Assessment",
        "status": "completed",
        "created_at": "2024-01-20T14:00:00Z",
        "started_at": "2024-01-20T14:01:00Z",
        "completed_at": "2024-01-20T14:15:00Z",
        "scan_duration": 840,
        "progress": 100,
        "results": {
            "summary": {
                "total": 5,
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 1,
                "info": 1
            },
            "vulnerabilities": [
                {
                    "template_id": "CVE-2023-12345",
                    "severity": "high",
                    "title": "SQL Injection Vulnerability",
                    "description": "SQL injection vulnerability found in login form",
                    "matched_at": "https://example.com/login",
                    "cvss_score": 8.1,
                    "cve_id": "CVE-2023-12345",
                    "references": [
                        "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
                    ],
                    "fix_recommendation": "Use parameterized queries to prevent SQL injection"
                }
            ]
        }
    }
}
```

### Cancel Scan
Cancels a running or queued scan.

**Endpoint:** `DELETE /scans/{scan_id}`
**Authentication:** Required

**Response:**
```json
{
    "message": "Scan cancelled successfully",
    "scan_id": "scan-550e8400-e29b-41d4-a716-446655440000"
}
```

**Status Codes:**
- `200` - Scan cancelled successfully
- `404` - Scan not found
- `409` - Scan cannot be cancelled (already completed)

## Reporting

### Download Scan Report
Downloads a detailed scan report in various formats.

**Endpoint:** `GET /scans/{scan_id}/report`
**Authentication:** Required

**Query Parameters:**
- `format`: Report format (`html`, `json`, `pdf`, `csv`) - default: `html`
- `template`: Report template (`detailed`, `summary`, `executive`) - default: `detailed`

**Response:**
- `Content-Type`: Varies based on format
- Binary file download

**Status Codes:**
- `200` - Report generated successfully
- `404` - Scan not found or report not available
- `400` - Invalid format or template

### Generate Compliance Report
Generates a compliance report based on selected frameworks.

**Endpoint:** `POST /reports/compliance`
**Authentication:** Required

**Request Body:**
```json
{
    "scan_ids": [
        "scan-550e8400-e29b-41d4-a716-446655440000",
        "scan-662f9511-f3ac-52e5-b827-557766551111"
    ],
    "frameworks": ["owasp-top-10", "pci-dss", "iso-27001"],
    "format": "pdf",
    "include_remediation": true
}
```

**Response:**
```json
{
    "report_id": "report-773g0622-g4bd-63f6-c938-668877662222",
    "download_url": "/reports/compliance/report-773g0622-g4bd-63f6-c938-668877662222.pdf",
    "expires_at": "2024-01-27T14:00:00Z"
}
```

## Statistics

### Get User Statistics
Retrieves statistics for the current user.

**Endpoint:** `GET /stats`
**Authentication:** Required

**Response:**
```json
{
    "scans": {
        "total_scans": 25,
        "completed_scans": 23,
        "failed_scans": 1,
        "running_scans": 1,
        "avg_scan_duration": 742
    },
    "vulnerabilities": {
        "total_found": 156,
        "by_severity": {
            "critical": 5,
            "high": 23,
            "medium": 67,
            "low": 45,
            "info": 16
        }
    },
    "quota": {
        "limit": 100,
        "used": 25,
        "remaining": 75,
        "reset_date": "2024-02-01T00:00:00Z"
    },
    "plan": "premium"
}
```

### Get Platform Statistics (Admin Only)
Retrieves platform-wide statistics.

**Endpoint:** `GET /admin/stats`
**Authentication:** Required (Admin role)

**Response:**
```json
{
    "platform": {
        "total_users": 1250,
        "active_users_30d": 890,
        "total_scans": 15670,
        "scans_last_24h": 245,
        "avg_scan_duration": 653
    },
    "vulnerabilities": {
        "total_found": 89456,
        "most_common": [
            {
                "template_id": "ssl-weak-cipher",
                "count": 2341,
                "severity": "medium"
            }
        ]
    },
    "system": {
        "cpu_usage": 45.2,
        "memory_usage": 67.8,
        "disk_usage": 34.1,
        "uptime": 2592000
    }
}
```

## System

### Health Check
Checks the health of the API and its dependencies.

**Endpoint:** `GET /health`
**Authentication:** Not required

**Response:**
```json
{
    "status": "healthy",
    "timestamp": "2024-01-20T15:30:00Z",
    "version": "1.0.0",
    "services": {
        "database": "online",
        "redis": "online",
        "nuclei": "online",
        "scanner_workers": {
            "total": 3,
            "active": 2,
            "idle": 1
        }
    },
    "performance": {
        "avg_response_time": 125,
        "requests_per_minute": 45
    }
}
```

### API Information
Returns API version and feature information.

**Endpoint:** `GET /info`
**Authentication:** Not required

**Response:**
```json
{
    "api_version": "1.0.0",
    "platform_version": "2.1.0",
    "features": {
        "max_concurrent_scans": 5,
        "supported_formats": ["html", "json", "pdf", "csv"],
        "supported_frameworks": ["owasp-top-10", "pci-dss", "iso-27001"],
        "rate_limits": {
            "authenticated": "100 requests per hour",
            "unauthenticated": "10 requests per hour"
        }
    },
    "nuclei": {
        "version": "3.1.4",
        "templates_count": 4567,
        "last_update": "2024-01-19T10:15:00Z"
    }
}
```

## Error Handling

### Error Response Format
All API errors follow a consistent format:

```json
{
    "error": "Short error description",
    "message": "Detailed error message",
    "code": "ERROR_CODE",
    "timestamp": "2024-01-20T15:30:00Z",
    "request_id": "req-884h1733-h5ce-74g7-d049-779988773333"
}
```

### Common Error Codes

| Status Code | Error Code | Description |
|-------------|------------|-------------|
| 400 | INVALID_REQUEST | Request body or parameters are invalid |
| 401 | UNAUTHORIZED | Authentication required or token invalid |
| 403 | FORBIDDEN | Insufficient permissions |
| 404 | NOT_FOUND | Resource not found |
| 409 | CONFLICT | Resource already exists or conflict |
| 422 | VALIDATION_ERROR | Request validation failed |
| 429 | RATE_LIMITED | Rate limit exceeded |
| 500 | INTERNAL_ERROR | Internal server error |
| 503 | SERVICE_UNAVAILABLE | Service temporarily unavailable |

### Validation Errors
Field-specific validation errors include details:

```json
{
    "error": "Validation failed",
    "message": "The following fields contain errors",
    "code": "VALIDATION_ERROR",
    "fields": {
        "email": ["Email format is invalid"],
        "password": ["Password must be at least 8 characters"]
    }
}
```

## Rate Limiting

### Rate Limit Headers
All responses include rate limiting headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642694400
X-RateLimit-Window: 3600
```

### Rate Limits by Plan

| Plan | Requests/Hour | Scans/Month | Concurrent Scans |
|------|---------------|-------------|------------------|
| Basic | 100 | 10 | 1 |
| Premium | 500 | 100 | 3 |
| Enterprise | 2000 | 1000 | 10 |

## SDK Examples

### cURL Examples

**Register a new user:**
```bash
curl -X POST https://your-domain.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "name": "John Doe",
    "password": "SecurePassword123!"
  }'
```

**Start a scan:**
```bash
curl -X POST https://your-domain.com/api/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "target": "https://example.com",
    "scan_name": "Security Assessment",
    "options": {
      "severity": "medium"
    }
  }'
```

**Get scan results:**
```bash
curl -X GET https://your-domain.com/api/scans/SCAN_ID \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Python Example

```python
import requests
import json

class TwoRATClient:
    def __init__(self, base_url, email=None, password=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.token = None
        
        if email and password:
            self.login(email, password)
    
    def login(self, email, password):
        """Authenticate and store access token"""
        response = self.session.post(
            f"{self.base_url}/api/auth/login",
            json={"email": email, "password": password}
        )
        response.raise_for_status()
        
        data = response.json()
        self.token = data['access_token']
        self.session.headers.update({
            'Authorization': f'Bearer {self.token}'
        })
        return data['user']
    
    def create_scan(self, target, scan_name=None, options=None):
        """Create a new vulnerability scan"""
        payload = {
            "target": target,
            "scan_name": scan_name or f"Scan of {target}",
            "options": options or {}
        }
        
        response = self.session.post(
            f"{self.base_url}/api/scans",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    def get_scan(self, scan_id):
        """Get scan details and results"""
        response = self.session.get(
            f"{self.base_url}/api/scans/{scan_id}"
        )
        response.raise_for_status()
        return response.json()
    
    def wait_for_scan(self, scan_id, timeout=3600, poll_interval=30):
        """Wait for scan to complete"""
        import time
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            scan = self.get_scan(scan_id)
            status = scan['scan']['status']
            
            if status in ['completed', 'failed']:
                return scan
            
            time.sleep(poll_interval)
        
        raise TimeoutError(f"Scan {scan_id} did not complete within {timeout} seconds")

# Usage example
client = TwoRATClient("https://your-domain.com", "user@example.com", "password")

# Start a scan
scan_result = client.create_scan(
    target="https://example.com",
    scan_name="Production Security Assessment",
    options={"severity": "medium", "tags": "cve,sqli,xss"}
)

scan_id = scan_result['scan_id']
print(f"Scan started: {scan_id}")

# Wait for completion
completed_scan = client.wait_for_scan(scan_id)
vulnerabilities = completed_scan['scan']['results']['vulnerabilities']

print(f"Scan completed. Found {len(vulnerabilities)} vulnerabilities.")
for vuln in vulnerabilities:
    print(f"- {vuln['severity'].upper()}: {vuln['title']}")
```

### JavaScript/Node.js Example

```javascript
const axios = require('axios');

class TwoRATClient {
    constructor(baseUrl, email = null, password = null) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.client = axios.create({
            baseURL: `${this.baseUrl}/api`
        });
        this.token = null;
        
        if (email && password) {
            this.login(email, password);
        }
    }
    
    async login(email, password) {
        try {
            const response = await this.client.post('/auth/login', {
                email,
                password
            });
            
            this.token = response.data.access_token;
            this.client.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
            
            return response.data.user;
        } catch (error) {
            throw new Error(`Login failed: ${error.response?.data?.message || error.message}`);
        }
    }
    
    async createScan(target, scanName = null, options = {}) {
        try {
            const response = await this.client.post('/scans', {
                target,
                scan_name: scanName || `Scan of ${target}`,
                options
            });
            
            return response.data;
        } catch (error) {
            throw new Error(`Scan creation failed: ${error.response?.data?.message || error.message}`);
        }
    }
    
    async getScan(scanId) {
        try {
            const response = await this.client.get(`/scans/${scanId}`);
            return response.data;
        } catch (error) {
            throw new Error(`Failed to get scan: ${error.response?.data?.message || error.message}`);
        }
    }
    
    async waitForScan(scanId, timeout = 3600, pollInterval = 30) {
        const startTime = Date.now();
        
        while (Date.now() - startTime < timeout * 1000) {
            const scan = await this.getScan(scanId);
            const status = scan.scan.status;
            
            if (['completed', 'failed'].includes(status)) {
                return scan;
            }
            
            await new Promise(resolve => setTimeout(resolve, pollInterval * 1000));
        }
        
        throw new Error(`Scan ${scanId} did not complete within ${timeout} seconds`);
    }
}

// Usage example
async function example() {
    const client = new TwoRATClient('https://your-domain.com');
    
    try {
        // Login
        await client.login('user@example.com', 'password');
        console.log('Logged in successfully');
        
        // Start scan
        const scanResult = await client.createScan(
            'https://example.com',
            'Production Security Assessment',
            { severity: 'medium', tags: 'cve,sqli,xss' }
        );
        
        console.log(`Scan started: ${scanResult.scan_id}`);
        
        // Wait for completion
        const completedScan = await client.waitForScan(scanResult.scan_id);
        const vulnerabilities = completedScan.scan.results.vulnerabilities;
        
        console.log(`Scan completed. Found ${vulnerabilities.length} vulnerabilities.`);
        vulnerabilities.forEach(vuln => {
            console.log(`- ${vuln.severity.toUpperCase()}: ${vuln.title}`);
        });
        
    } catch (error) {
        console.error('Error:', error.message);
    }
}

example();
```

## Webhooks (Coming Soon)

The 2R-AT platform will support webhooks for real-time notifications:

- Scan completion
- Vulnerability discoveries
- System alerts
- Quota warnings

## API Versioning

The API uses URL versioning. Current version is `v1`. Future versions will be available at:
- `/api/v2/...`
- `/api/v3/...`

Older versions will be supported for 12 months after a new version is released.

## Support

For API support:
- Email: api-support@2r-at.com
- Documentation: https://docs.2r-at.com
- Status Page: https://status.2r-at.com
- GitHub Issues: https://github.com/2r-at/platform/issues

---

**Last Updated:** January 2024
**API Version:** 1.0.0