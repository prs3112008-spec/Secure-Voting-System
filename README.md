# Secure Voting System — Backend API

REST API for the Secure Voting Android client, built with **Node.js, Express, and PostgreSQL (Supabase)**.

**Android Client Repository:** [Secure-Voting-System- (Android Java Client)](https://github.com/prs3112008-spec/Secure-Voting-System-)

---

## Architecture & Security Controls

- **Hash-Chained Ballot Ledger (`votes`):** Each cast ballot stores a SHA-256 `current_hash` computed over its payload and the preceding row's `previous_hash`, returning a 64-character receipt hash to the voter. The admin verification endpoint recomputes the chain from the genesis record to flag modified payloads, broken links, or missing sequence links.
- **Turnout & Ballot Separation (`voter_turnout` vs. `votes`):** Voter participation is recorded in `voter_turnout` with a composite primary key `(poll_id, voter_id)` inside serialized database transactions, while the `votes` table omits `voter_id` to separate identity from ballot choice. Concurrent duplicate requests trigger unique constraint violations mapped to HTTP `409 Conflict`.
- **Server-Verified Biometric Tokens:** The Android client extracts 192-float MobileFaceNet embeddings and sends them over HTTPS to the backend, which compares them against stored embeddings and issues a short-lived, single-use, user-bound `verification_token` required by `POST /api/votes` (preventing client-side boolean bypasses and cross-user token replay).
- **RBAC & Application Audit Logging:** Supports `super_admin` and delegated `sub_admin` permissions (`can_manage_polls`, `can_manage_candidates`, `can_approve_voters`). Privileged API actions (role changes, voter approvals, password resets, candidate edits) are written to `audit_logs`.
- **API Hardening:** Strict **Zod** schema validation (`middleware/validate.js`), tiered rate limiting, exponential account login backoff, **Helmet** security headers, and Cloudinary image uploads.

---

## Threat Model & Known Limitations

To keep security claims accurate, the following boundaries apply to the current architecture:

- **Database-Resident Hash Chain:** Because hashes are stored in PostgreSQL without an external timestamping authority, append-only WORM storage, or HMAC/asymmetric signing key outside the database, a privileged attacker with full write access to PostgreSQL could recompute downstream hashes after modifying or deleting rows. Voters can independently verify their own receipt hash against the chain, but full tamper-resistance requires external hash anchoring.
- **Pseudonymity vs. Strict Anonymity:** Omitting `voter_id` from `votes` prevents direct foreign-key lookups, but the system does not provide cryptographic unlinkability (such as blind signatures or mixnets). Server access logs, request timestamps, or low-turnout timing correlation could still narrow down ballot attribution.
- **Biometric Liveness & Storage:** Facial embeddings are transmitted over HTTPS and verified server-side, but the current flow does not enforce active challenge-response liveness detection (e.g., blink/head-turn challenges) or hardware attestation against high-resolution replay attacks.
- **Audit Log Scope:** Application-level audit logs capture API-driven admin actions, not direct out-of-band SQL edits executed via the Supabase dashboard.

---

## Automated Security Test Suite (`node --test`)

All **37 tests** live in [`nodejs-backend-api/test.js`](nodejs-backend-api/test.js) and [`nodejs-backend-api/tests/`](nodejs-backend-api/tests/) and run via Node's built-in test runner (`node --test`) without requiring a live production database:

- **Startup & Secret Validation (3 tests):** Verifies the server exits non-zero when `DATABASE_URL` or `JWT_SECRET` is missing, never logs secret values, and attaches Helmet headers without breaking CORS.
- **Authentication, RBAC & IDOR Protection (11 tests):** Tests `super_admin` / `sub_admin` delegation, self-revocation blocking, account login backoff, wrong-secret JWT rejection, mass-assignment rejection on registration, and user-scoped vote status.
- **Biometric & Token Replay Controls (5 tests):** Verifies enrollment tokens cannot access protected routes, verification tokens are single-use and bound to the authenticated `user_id`, and password resets require matching account + face verification.
- **Vote Concurrency, Anonymity & Ledger Integrity (11 tests):** Tests parallel vote bursts (1 accepted, duplicates rejected with `409 Conflict`), `voter_turnout` repeat-vote blocking, ballot schema isolation from `voter_id`, cross-poll chain isolation, and tampered ballot payload detection.
- **Validation, Rate Limiting & Media Uploads (7 tests):** Tests Zod schema enforcement, tiered rate-limit thresholds, environment overrides, and Cloudinary failure rollback (`502` without orphaned candidate inserts).

---

## Local Setup & Prerequisites

- **Runtime:** Node.js `v20+` (required for native `node --test` runner)
- **Database:** PostgreSQL `15+` (or a Supabase project)

### 1. Configure Environment Variables
Copy `nodejs-backend-api/.env.example` to `nodejs-backend-api/.env` and set:
```env
DATABASE_URL=postgresql://user:password@host:5432/dbname
JWT_SECRET=your-64-char-random-hex-secret
PORT=5000
# Optional (required only if testing Cloudinary photo uploads)
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
2. Initialize Schema & Run
cd nodejs-backend-api
npm install

# Apply database schema to your PostgreSQL instance
psql "$DATABASE_URL" -f schema.sql

# Run the 37 automated security tests
node --test

# Start the API server
npm start
##Tech Stack
Runtime & Framework: Node.js, Express.js

Database: PostgreSQL (Supabase)

Security & Validation: jsonwebtoken, zod, helmet, express-rate-limit, Node crypto (SHA-256)

Media & Hosting: Cloudinary, Render
