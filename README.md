# Secure Voting System - Backend API

Backend REST API for my Secure Voting Android app, built with **Node.js, Express, and PostgreSQL (Supabase)**.

I built this to solve the core problems in digital voting: keeping ballots anonymous, stopping double-voting under simultaneous requests, catching manual database tampering, and preventing users from bypassing face verification on the phone.

**Android App Repo:** [Secure-Voting-System- (Android Java Client)](https://github.com/prs3112008-spec/Secure-Voting-System-)

---

## How the Security Works

- **Tamper-Evident Vote Ledger (SHA-256):** Every vote stores a SHA-256 hash built from its own data plus the previous vote's hash. If someone alters or deletes a row directly in the database, the chain breaks and the admin verification endpoint flags it immediately.
- **Anonymous Ballots + No Double-Voting:** Instead of storing `voter_id` on the vote itself, turnout is tracked separately in a `voter_turnout` table with a composite primary key `(poll_id, voter_id)` inside serialized transactions. The `votes` table holds zero voter info, and parallel duplicate requests get blocked with a `409 Conflict`.
- **Server-Side Biometric Checks:** The Android app sends 192-float MobileFaceNet face embeddings to the backend rather than doing a local pass/fail check. The server compares them and issues a short-lived, single-use token tied to that specific user, blocking client-side bypasses and token replay.
- **Admin Roles & Audit Logs:** Supports a main `super_admin` and delegated `sub_admin` accounts with specific permissions (`can_manage_polls`, `can_manage_candidates`, `can_approve_voters`). Every sensitive admin action writes to an audit log.
- **API Hardening:** Uses **Zod** to strictly validate incoming params and request bodies, tiered rate limiting, exponential backoff on failed logins, **Helmet** headers, and Cloudinary for candidate photos.

---

## Automated Security Tests (`node --test`)

Includes **37 integration and security tests** written with Node's built-in test runner to test common attack scenarios:
- Firing parallel vote bursts to test double-voting race conditions (`409 Conflict`)
- Modifying vote rows in the database to verify SHA-256 chain tamper detection
- Replaying another user's biometric token or accessing other users' resources (IDOR)
- Sending extra fields during registration to test mass assignment protection
- Trying restricted admin endpoints as a sub-admin without permissions
- Rate-limit abuse, malformed JSON payloads, and missing environment secrets at startup

### Run Locally

```bash
cd nodejs-backend-api
npm install
npm start

# Run all 37 automated security tests
node --test
