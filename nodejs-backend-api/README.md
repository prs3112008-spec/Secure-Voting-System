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
