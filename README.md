# Secure Voting System — Backend API

REST API for the Secure Voting Android client, built with **Node.js, Express, and PostgreSQL (Supabase)**.

- **Android Client Repository:** [Secure-Voting-System- (Android Java Client)](https://github.com/prs3112008-spec/Secure-Voting-System-)
- **Supported Android API Target:** Android 8.0+ (API 26+) / Target SDK 34 (check the Android repository's `build.gradle` for exact SDK versions)

---

## Table of Contents

- [Architecture & Security Controls](#architecture--security-controls)
- [Threat Model & Known Limitations](#threat-model--known-limitations)
- [API Endpoint Summary](#api-endpoint-summary)
- [Example Responses](#example-responses)
- [Automated Test Suite](#automated-test-suite)
- [Local Setup & Prerequisites](#local-setup--prerequisites)
- [Deployment](#deployment)
- [Tech Stack](#tech-stack)
- [License](#license)

---

## Architecture & Security Controls

- **Internal Hash-Chained Ballot Audit Ledger (`votes`):** Each cast ballot stores a SHA-256 `current_hash` computed over its ballot payload and the preceding ballot's `previous_hash`, returning a 64-character receipt hash to the voter. The admin verification endpoint (`GET /api/admin/verify-chain`) recomputes the chain sequentially from the first record to detect payload modifications or broken links within the database.
- **Database-Enforced Duplicate-Vote Prevention (`voter_turnout` vs. `votes`):**
  - Ballot casting runs inside an explicit PostgreSQL transaction (`BEGIN` / `COMMIT`).
  - Voter participation is inserted into `voter_turnout` under a composite primary/unique constraint `(poll_id, voter_id)` before inserting the ballot row into `votes` (which omits the `voter_id` column).
  - Concurrent duplicate requests hit the database unique constraint (`23505`) and return HTTP `409 Conflict`, rolling back the transaction.
- **Biometric Enrollment & Verification Tokens:**
  - **Consent & Storage:** During registration, users explicitly opt into biometric enrollment. Facial images are converted on-device into 192-float MobileFaceNet numerical embeddings and transmitted over HTTPS to PostgreSQL (`users` / biometric profile storage) rather than storing raw face photos for matching.
  - **Retention & Deletion:** Embeddings remain stored only while the voter account is active and are removed when a voter record is deleted.
  - **Token Formats & Lifetimes:** Authentication uses signed HS256 JWTs (`Authorization: Bearer <token>`), while `POST /api/biometric/verify` issues a short-lived, single-use verification token bound to the authenticated `user_id`. Once consumed by `POST /api/votes` (or expired), the token cannot be reused or replayed across accounts.
- **Media Upload Ordering & Rollback (`Cloudinary`):** Candidate photo uploads to Cloudinary are executed **before** committing the candidate row to PostgreSQL (`POST /api/admin/candidates`). If Cloudinary fails, the API aborts with HTTP `502 Bad Gateway` before writing any database record; if a post-upload database write fails, orphaned assets require cleanup via their Cloudinary `public_id`.
- **RBAC, Validation & Rate Limiting:**
  - Enforces `super_admin` and delegated `sub_admin` permission flags (`can_manage_polls`, `can_manage_candidates`, `can_approve_voters`) and writes privileged API operations to `audit_logs`.
  - Validates request bodies and route parameters with **Zod** (`middleware/validate.js`), applies tiered `express-rate-limit` rules, enforces login failure backoff, and attaches **Helmet** HTTP security headers.

---

## Threat Model & Known Limitations

- **Database-Resident Hash Chain (Not External Immutability):** SHA-256 chaining detects uncoordinated row edits or broken sequence links, but hashes are stored inside PostgreSQL without an external timestamping authority, append-only WORM storage, or external signing key. An attacker with full PostgreSQL write privileges could rewrite rows and recompute downstream hashes.
- **Pseudonymity vs. Cryptographic Unlinkability:** Omitting `voter_id` from `votes` prevents direct foreign-key joins between voters and choices
