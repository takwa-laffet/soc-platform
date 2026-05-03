# SOC Platform API - Postman Testing Guide

## Base URL
```
https://soc-platform-ekjv.onrender.com
```

## Authentication

### 1. Login (get JWT cookie)
**POST** `https://soc-platform-ekjv.onrender.com/api/auth/login`

**Body (raw JSON):**
```json
{
  "email": "soc-manager@example.com",
  "password": "your-password"
}
```

**Response:** Sets `access_token_cookie` automatically (HTTP-only). Postman will store it.

---

## 2. Test Alert Prediction (with API Key)

### Get API Key (SOC Manager only)
**POST** `https://soc-platform-ekjv.onrender.com/api/auth/api-keys/generate`

**Body:**
```json
{
  "name": "postman-test",
  "expires_days": 30
}
```

Save the returned `api_key` value.

### Predict Alerts
**POST** `https://soc-platform-ekjv.onrender.com/api/predict/auto`

**Headers:**
- `Content-Type: application/json`
- `X-API-Key: sk_your_api_key_here`

**Body:**
```json
{
  "rule": {
    "id": "5715",
    "level": 10,
    "description": "SSH brute force detected"
  },
  "agent": {
    "name": "webserver01"
  },
  "decoder": {
    "name": "sshd"
  },
  "full_log": "Failed password for root from 192.168.1.100"
}
```

---

## 3. Test Dashboard Endpoints

### Get Stats
**GET** `https://soc-platform-ekjv.onrender.com/api/dashboard/stats`

### Get Alerts
**GET** `https://soc-platform-ekjv.onrender.com/api/dashboard/alerts?limit=10`

### Get Vulnerabilities
**GET** `https://soc-platform-ekjv.onrender.com/api/dashboard/vulnerabilities?limit=10`

---

## 4. Test SOC Report

**POST** `https://soc-platform-ekjv.onrender.com/api/dashboard/report`

**Headers:** Include JWT cookie from login OR X-API-Key

**Body:**
```json
{
  "limit": 100
}
```

---

## 5. Test Chat

**POST** `https://soc-platform-ekjv.onrender.com/api/chat`

**Body:**
```json
{
  "messages": [
    {"role": "user", "content": "What alerts need attention?"}
  ]
}
```

---

## Quick Reference

| Endpoint | Method | Auth |
|----------|--------|------|
| `/api/health` | GET | None |
| `/api/auth/login` | POST | None |
| `/api/auth/api-keys/generate` | POST | JWT (Manager) |
| `/api/predict/auto` | POST | API Key |
| `/api/dashboard/stats` | GET | JWT |
| `/api/dashboard/report` | POST | JWT/API Key |
| `/api/chat` | POST | Optional |