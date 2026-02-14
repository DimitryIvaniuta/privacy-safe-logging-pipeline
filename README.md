# Privacy-safe Logging Pipeline (PII redaction)

**GitHub repo name:** `privacy-safe-logging-pipeline`  
**Description:** Structured JSON logs with correlationId and automatic PII redaction (email/phone/card), plus a separate secure audit store for sensitive events (stored in Postgres `audit` schema).

## Run locally

```bash
docker compose up -d
gradle bootRun
```

If you prefer, use your Gradle wrapper from your environment (recommended Gradle 8.7+).

## Endpoints

- `POST /api/demo/log` — logs PII-like payload; logs must be redacted
- `POST /api/demo/sensitive-event` — stores payload in audit DB; logs only a safe reference id
- `GET /api/audit/events?limit=20` — lists recent audit events (**demo; secure this in real deployments**)
- `GET /actuator/health`

## Notes

- Correlation id header is `X-Correlation-Id` (configurable via `app.logging.correlation-header`).
- PII redaction is enforced at the Logback pipeline level via custom converters, so accidental `log.info(...)`
  still cannot persist emails/phones/cards.
- Card masking uses Luhn validation to reduce false positives.

## Security hardening (recommended if extending)
- Protect `/api/audit/**` with auth + RBAC.
- Encrypt audit payload fields.
- Add retention policy and export tooling for auditors.


## Improvements added (production-grade hardening)

- **Async logging** for lower request-thread overhead (disabled in tests for deterministic assertions).
- **Redacting MDC provider** to prevent accidental PII leaks from MDC into structured logs.
- **Audit store hardening**: added a **hash chain** (prevHash + hash) computed with SHA-256 to detect tampering.
- **Audit endpoint RBAC**: `/api/audit/**` protected with **Basic Auth** for local demo:
  - `auditor / auditor` (role AUDITOR)
  - `admin / admin` (roles AUDITOR, ADMIN)
- **Metrics**: Micrometer gauges for redaction counters:
  - `pii.redactions.email.total`
  - `pii.redactions.phone.total`
  - `pii.redactions.card.total`

Prometheus endpoint: `/actuator/prometheus`.

## Next step: real auth locally (OIDC/JWT via Keycloak)

Default mode now is **OAuth2 Resource Server (JWT)** validating tokens from local **Keycloak**.

### Start locally

```bash
docker compose up -d
gradle bootRun
```

Keycloak: `http://localhost:8081` (admin/admin)

Realm/import:
- realm: `privacy-logs`
- clientId: `local-dev` (password grant enabled for local dev)
- users:
  - `auditor / auditor` (role `AUDITOR`)
  - `admin / admin` (roles `AUDITOR`, `ADMIN`)

### Get token (curl)

```bash
curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=local-dev&username=auditor&password=auditor" \
  "http://localhost:8081/realms/privacy-logs/protocol/openid-connect/token"
```

Use `access_token` as `Authorization: Bearer <token>` for `/api/audit/**`.

### Basic Auth fallback (optional)

```bash
gradle bootRun --args='--spring.profiles.active=basic'
```

## Encrypting audit payloads at rest (envelope encryption)

Audit event payloads are **never stored in plaintext**. The column `audit.audit_events.payload` now contains an
encrypted **envelope JSON**:

```json
{"v":1,"alg":"A256GCM","kid":"k1","iv":"...","ct":"..."}
```

- `kid` enables **key rotation**
- AES-GCM uses AAD bound to `(eventId, createdAt, eventType)` to prevent swapping ciphertext between rows.

### Key rotation workflow (local)

1) Add a new key to `app.audit.crypto.keys` and set `active-kid` to it.
2) Restart the app.
3) Re-encrypt old rows (admin role required):

```bash
POST /api/admin/crypto/reencrypt?fromKid=k0&toKid=k1&limit=200
```

Admin utilities:
- `GET /api/admin/crypto/keys`
- `POST /api/admin/crypto/generate?kid=k2`

## Key rotation workflow (promote + re-encrypt + health)

### 1) Generate a new key (admin)
`POST /api/admin/crypto/generate?kid=k2`

Add the returned Base64 key to `app.audit.crypto.keys` (secret store in production).

### 2) Promote active key (no redeploy required)
`POST /api/admin/crypto/promote?kid=k2`

This updates `audit.crypto_keyring_state.active_kid`. New audit events will be encrypted with `k2`.

### 3) Re-encrypt historical data (background, throttled)
Start a job:
`POST /api/admin/crypto/reencrypt/start?fromKid=k1&toKid=k2&batchSize=200&throttleMs=25`

Check status:
`GET /api/admin/crypto/reencrypt/{jobId}`

Cancel:
`POST /api/admin/crypto/reencrypt/{jobId}/cancel`

Worker frequency is configurable:
`app.audit.crypto.reencrypt.poll-delay-ms` (default 1000ms)

### 4) Ring health
`GET /api/admin/crypto/health`

Shows configured kids, DB active kid, counts of events by kid, and unknown kids found in DB.

## Safe promote runbook + key deprecation

### Safe promote (one-call workflow)

- `POST /api/admin/crypto/runbook/safe-promote?kid=k2&graceDays=30`

Performs:
1) generate AES-256 key
2) validate ring health
3) prints a config snippet for secret store
4) promotes new `kid` for new encryptions
5) deprecates previous active key with grace period

**Local/dev note:** generated key is installed into an in-memory overlay keyring to enable immediate promotion without restart.
Store the key in secrets and restart for durability.

### Deprecate a key-id (grace period)

- `POST /api/admin/crypto/deprecate?kid=k1&graceDays=30`

Ring health returns `deprecatedExpiredKids` when grace periods elapsed.
