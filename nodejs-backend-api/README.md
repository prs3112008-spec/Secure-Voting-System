# Node.js backend

## Rate limiting

Rate limiting is in-memory per backend process. Configure it with these environment variables; defaults are shown in parentheses:

| Variable | Default | Applies to |
| --- | ---: | --- |
| `RATE_LIMIT_AUTH_WINDOW_MS` | `900000` | Login and registration IP window |
| `RATE_LIMIT_LOGIN_IP_MAX` | `30` | Login attempts per IP |
| `RATE_LIMIT_REGISTER_IP_MAX` | `5` | Registrations per IP |
| `RATE_LIMIT_ACCOUNT_FAILURE_THRESHOLD` | `5` | Failed logins before account backoff |
| `RATE_LIMIT_ACCOUNT_FAILURE_WINDOW_MS` | `900000` | Account failure counter window |
| `RATE_LIMIT_ACCOUNT_BACKOFF_BASE_MS` | `1000` | Initial account retry delay |
| `RATE_LIMIT_ACCOUNT_BACKOFF_MULTIPLIER` | `2` | Exponential account delay multiplier |
| `RATE_LIMIT_ACCOUNT_BACKOFF_MAX_MS` | `900000` | Maximum account retry delay |
| `RATE_LIMIT_PUBLIC_WINDOW_MS` | `60000` | Public endpoint window |
| `RATE_LIMIT_PUBLIC_MAX` | `120` | Public requests per IP per window |
| `RATE_LIMIT_VOTER_WINDOW_MS` | `60000` | Authenticated voter action window |
| `RATE_LIMIT_VOTER_MAX` | `120` | Voter requests per account per window |
| `RATE_LIMIT_ADMIN_WINDOW_MS` | `60000` | Admin action window |
| `RATE_LIMIT_ADMIN_MAX` | `300` | Admin requests per account per window |

Failed login backoff is keyed by normalized email. A correct password clears that account's failure state. All rate-limit responses use HTTP 429 with `RateLimit-*` headers, `Retry-After`, and a JSON retry duration. Express trusts the single reverse proxy hop used by the production load balancer.

The in-memory counters reset when the process restarts and are not shared across multiple backend instances.

## Required environment

Set `DATABASE_URL` and `JWT_SECRET` in the deployment environment. The server exits at startup with the missing variable names if either is unset or blank. Copy `.env.example` for local setup and replace its placeholders; `.env` and other local credential files are ignored by Git.

Initialize the database by applying `schema.sql` before starting the API with `npm start`.

## Request validation

Request bodies and path parameters that carry input are validated with strict Zod schemas. Invalid requests receive HTTP 400 as `{ error: "Validation failed", details: [...] }`; unknown body fields are rejected. Login accepts `identifier` (email or 10-digit mobile) and continues to accept the existing `email` field. Vote casting accepts `election_id` and the existing `poll_id` alias and requires a `verification_token` from `POST /api/auth/verify-face`. Face verification accepts a 192-number embedding and returns a two-minute, single-use token; the token is tracked in process memory and therefore is not shared across backend instances. Face embeddings are never returned by an API route. Numeric IDs accept positive integer strings or numbers. Candidate creation accepts `name` and the existing `candidate_name` alias; empty or null `party` uses the existing `Independent` default. A non-empty `photo_url` is required and must be an HTTP(S) URL or a Base64 image data URI up to 4,000,000 characters. Receipt verification requires a 64-character hexadecimal hash. Voter identity for vote casting is taken from the verified token, not a client-supplied `voter_id`.

Registration leaves new voters unapproved and returns a ten-minute `enroll_token` scoped only to `POST /api/auth/register-face`. Only voters may cast ballots, and candidate deletion is rejected when ledger votes reference that candidate. Full vote-chain verification is restricted to administrators.
