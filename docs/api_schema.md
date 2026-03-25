# NIDS — API JSON Schema Reference

> All endpoints are served by the Flask controller on `https://<controller-ip>:5000`.
> Authenticated endpoints require the header: `X-NIDS-Auth: <API_KEY>`.

---

## 1. Sensor Endpoints (Authenticated)

### `POST /alert`

Receives an anomaly alert from a sensor node.

**Request Headers**

| Header | Required | Description |
|---|---|---|
| `X-NIDS-Auth` | Yes | Sensor/admin API key |
| `Content-Type` | Yes | `application/json` |

**Request Body**

```json
{
  "sensor_id": "node1",
  "ip": "192.168.1.50",
  "score": 85.0
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `sensor_id` | `string` | Yes | Unique identifier of the reporting sensor |
| `ip` | `string` | Yes | Source IP flagged as suspicious (IPv4/IPv6) |
| `score` | `float` | Yes | Anomaly score from the ML detector |

**Response — 200 OK**

```json
{
  "status": "processing",
  "message": "Alert received"
}
```

---

### `POST /heartbeat`

Sensors send periodic heartbeat to register themselves and confirm availability.

**Request Headers**

| Header | Required | Description |
|---|---|---|
| `X-NIDS-Auth` | Yes | Sensor API key |
| `Content-Type` | Yes | `application/json` |

**Request Body**

```json
{
  "sensor_id": "node1"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `sensor_id` | `string` | Yes | Sensor node identifier |

**Response — 200 OK**

```json
{
  "status": "ok"
}
```

---

## 2. Query Endpoints (Public)

### `GET /api/nodes`

Returns all registered sensor nodes and their current status.

**Response — 200 OK**

```json
[
  {
    "id": "node1",
    "ip": "192.168.1.10",
    "trust": 75.0,
    "status": "online",
    "last_seen": "2026-03-23T08:30:00"
  }
]
```

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Sensor node identifier |
| `ip` | `string` | IP address of the sensor |
| `trust` | `float` | Current trust score (0–100) |
| `status` | `string` | `"online"` or `"offline"` |
| `last_seen` | `string\|null` | ISO 8601 datetime of last heartbeat |

---

### `GET /api/alerts`

Returns the most recent alerts. Accepts optional query param `?limit=N` (default: 50).

**Response — 200 OK**

```json
[
  {
    "id": 1,
    "sensor": "node1",
    "ip": "10.0.0.5",
    "score": 72.5,
    "time": "2026-03-23T08:25:00"
  }
]
```

| Field | Type | Description |
|---|---|---|
| `id` | `int` | Alert record ID |
| `sensor` | `string` | Reporting sensor ID |
| `ip` | `string` | Flagged source IP |
| `score` | `float` | Raw anomaly score |
| `time` | `string` | ISO 8601 timestamp |

---

### `GET /api/status`

Returns aggregate system counts.

**Response — 200 OK**

```json
{
  "active_sensors": 3,
  "total_alerts": 128,
  "active_blocks": 5
}
```

---

### `GET /api/blocks`

Returns all active block events, newest first.

**Response — 200 OK**

```json
[
  {
    "id": 1,
    "ip": "10.0.0.5",
    "reason": "Threat Score: 72.50",
    "blocked_at": "2026-03-23T08:26:00",
    "expires_at": "2026-03-23T08:31:00"
  }
]
```

| Field | Type | Description |
|---|---|---|
| `id` | `int` | Block event ID |
| `ip` | `string` | Blocked IP |
| `reason` | `string` | Human-readable reason |
| `blocked_at` | `string\|null` | ISO 8601 datetime |
| `expires_at` | `string\|null` | ISO 8601 expiry (null = permanent) |

---

### `GET /api/verdicts`

Returns verification verdicts. Optional params: `?limit=N&verdict=BLOCK|BORDERLINE|UNVERIFIED`.

**Response — 200 OK**

```json
[
  {
    "id": 1,
    "ip": "10.0.0.5",
    "score": 45.5,
    "confidence": 87.3,
    "verdict": "BLOCK",
    "sensor_trust": 80.0,
    "sensors": 2,
    "timestamp": "2026-03-23T08:26:00"
  }
]
```

| Field | Type | Description |
|---|---|---|
| `id` | `int` | Verdict record ID |
| `ip` | `string` | Evaluated IP |
| `score` | `float` | Final cumulative threat score |
| `confidence` | `float` | Confidence percentage (0–100) |
| `verdict` | `string` | `"BLOCK"`, `"BORDERLINE"`, or `"UNVERIFIED"` |
| `sensor_trust` | `float` | Trust score of the reporting sensor |
| `sensors` | `int` | Number of distinct sensors reporting this IP |
| `timestamp` | `string` | ISO 8601 timestamp |

---

### `GET /api/honeypot`

Returns unprocessed BORDERLINE IPs queued for honeypot verification.

**Response — 200 OK**

```json
[
  {
    "id": 1,
    "ip": "10.0.0.5",
    "score": 39.0,
    "queued_at": "2026-03-23T08:27:00"
  }
]
```

---

### `GET /api/logs`

Returns the last N lines from `audit.log`. Optional param: `?limit=N` (default: 40).

**Response — 200 OK**

```json
[
  "2026-03-23 08:25:00 - [SYSTEM] [BLOCK] 10.0.0.5 blocked (Score: 72.50)",
  "2026-03-23 08:26:00 - [TRUST] Sensor node1 trust score updated to 85.00"
]
```

---

## 3. Action Endpoints (Authenticated)

All action endpoints require `X-NIDS-Auth` header.

### `POST /api/action/unban`

Removes a firewall block and deletes the BlockEvent record.

**Request Body**

```json
{
  "ip": "10.0.0.5"
}
```

**Response — 200 OK**

```json
{
  "status": "unbanned",
  "ip": "10.0.0.5"
}
```

---

### `POST /api/action/block`

Manually blocks an IP via the firewall and records it.

**Request Body**

```json
{
  "ip": "10.0.0.5"
}
```

**Response — 200 OK**

```json
{
  "status": "blocked",
  "ip": "10.0.0.5"
}
```

---

### `POST /api/action/whitelist`

Whitelists an IP: removes any existing block and adds to the runtime whitelist.

**Request Body**

```json
{
  "ip": "10.0.0.5"
}
```

**Response — 200 OK**

```json
{
  "status": "whitelisted",
  "ip": "10.0.0.5",
  "whitelist": ["127.0.0.1", "10.0.0.5"]
}
```

---

## 4. Config & Trust Endpoints

### `GET /config`

Returns the current runtime configuration (authenticated).

**Response — 200 OK**

```json
{
  "TRUST_THRESHOLD": 50,
  "BLOCK_THRESHOLD": 35,
  "WHITELIST": ["127.0.0.1", "192.168.1.8"],
  "HISTORY_TTL_SECONDS": 3600
}
```

### `POST /config`

Updates allowed configuration keys (currently only `WHITELIST`). Authenticated.

**Request Body**

```json
{
  "WHITELIST": ["127.0.0.1", "10.0.0.1"]
}
```

**Response — 200 OK**

```json
{
  "status": "updated",
  "current_config": { "..." }
}
```

---

### `GET /trust`

Returns trust scores for all registered sensors (public).

**Response — 200 OK**

```json
{
  "node1": 80.0,
  "node2": 55.0
}
```

---

## 5. Error Responses

All endpoints return errors in this standard format:

| HTTP Code | Condition | Response Body |
|---|---|---|
| 400 | Invalid/missing payload | `{"error": "Missing fields. Required: ['sensor_id', 'ip', 'score']"}` |
| 401 | Missing or invalid `X-NIDS-Auth` | `{"error": "Unauthorized"}` |

```json
{
  "error": "<human-readable message>"
}
```
