# API Documentation — Phishing Detection System

Base URL: `http://localhost:5000/api`

---

## Authentication

All endpoints (except `/health`) require a JWT Bearer token:

```
Authorization: Bearer <your_token>
```

Get a token via `POST /api/auth/login`.

---

## Endpoints

### 1. Scan a URL

**POST** `/scan/url`

Request:
```json
{
  "url": "https://example.com/login"
}
```

Response:
```json
{
  "scan_id": "uuid-here",
  "url": "https://example.com/login",
  "is_phishing": false,
  "confidence": 0.12,
  "risk_score": 12,
  "risk_level": "LOW",
  "indicators": [],
  "scanned_at": "2024-01-15T10:30:00Z"
}
```

---

### 2. Analyze an Email

**POST** `/scan/email`

Request:
```json
{
  "sender": "noreply@paypal-secure.xyz",
  "subject": "URGENT: Verify your account now!",
  "body": "Dear customer, click here to verify your account immediately..."
}
```

Response:
```json
{
  "scan_id": "uuid-here",
  "is_phishing": true,
  "confidence": 0.88,
  "risk_score": 88,
  "risk_level": "CRITICAL",
  "indicators": [
    "Suspicious sender domain detected",
    "High urgency language (3 urgency phrases)",
    "Requesting sensitive credential information"
  ],
  "scanned_at": "2024-01-15T10:31:00Z"
}
```

---

### 3. Batch Scan

**POST** `/scan/batch`

Request:
```json
{
  "urls": [
    "https://google.com",
    "http://paypal-verify.xyz/login"
  ]
}
```

Response:
```json
{
  "batch_id": "uuid-here",
  "total": 2,
  "results": [
    { "type": "url", "input": "https://google.com", "risk_level": "LOW" },
    { "type": "url", "input": "http://paypal-verify.xyz/login", "risk_level": "CRITICAL" }
  ],
  "scanned_at": "2024-01-15T10:32:00Z"
}
```

---

### 4. Get Scan History

**GET** `/history?page=1&limit=20&filter=phishing`

---

### 5. Get Statistics

**GET** `/stats`

Response:
```json
{
  "total_scans": 1247,
  "total_threats": 289,
  "detection_rate": 0.232,
  "scans_today": 42,
  "threats_today": 9
}
```

---

## Error Codes

| Code | Meaning |
|------|---------|
| 400  | Invalid request body |
| 401  | Missing or invalid JWT |
| 429  | Rate limit exceeded (100 req/15min) |
| 500  | Internal server error |
