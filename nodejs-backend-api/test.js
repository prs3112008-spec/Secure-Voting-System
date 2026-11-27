const assert = require('node:assert/strict');
const { test } = require('node:test');
const bcrypt = require('bcryptjs');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const cors = require('cors');
const cloudinarySdk = require('cloudinary').v2;
const express = require('express');
const fs = require('node:fs');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const os = require('node:os');
const path = require('node:path');
const adminRouter = require('./routes/admin');
const authRouter = require('./routes/auth');
const candidatesRouter = require('./routes/candidates');
const pollsRouter = require('./routes/polls');
const votesRouter = require('./routes/votes');
const verifyAdmin = require('./middleware/verifyAdmin');
const { createRateLimiters, getRateLimitConfig } = require('./middleware/rateLimits');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const { isCloudinaryConfigured, uploadCandidatePhoto } = require('./utils/cloudinary');
const getRequiredEnvironment = require('./utils/requiredEnv');
const verifyToken = require('./middleware/verifyToken');
const {
    consumeVerificationToken,
    issueVerificationToken
} = require('./utils/verificationToken');
const {
    buildVoteHashInput,
    generateHash,
    verifyVoteChain
} = require('./utils/voteChain');
const validate = require('./middleware/validate');
const {
    candidateIdParamsSchema,
    candidateSchema,
    receiptHashParamsSchema,
    voterIdParamsSchema,
    voteSchema
} = require('./middleware/schemas');

async function listen(t, app) {
    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, () => resolve(listeningServer));
    });
    t.after(() => new Promise((resolve, reject) => {
        server.close(err => err ? reject(err) : resolve());
    }));
    return `http://127.0.0.1:${server.address().port}`;
}

function config(overrides = {}) {
    return getRateLimitConfig(overrides);
}

test('API responses include Helmet security headers without disrupting CORS or JSON', async t => {
    const app = express();
    app.use(helmet());
    app.use(cors());
    app.get('/api/security-headers', (req, res) => res.json({ ok: true }));
    const baseUrl = await listen(t, app);

    const response = await fetch(`${baseUrl}/api/security-headers`, {
        headers: { Origin: 'https://android.example' }
    });

    assert.equal(response.status, 200);
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(response.headers.get('x-frame-options'), 'SAMEORIGIN');
    assert.equal(response.headers.get('x-powered-by'), null);
    assert.equal(response.headers.get('access-control-allow-origin'), '*');
    assert.deepEqual(await response.json(), { ok: true });
});

test('startup requires database and JWT secrets without exposing their values', () => {
    assert.throws(
        () => getRequiredEnvironment({}),
        { message: 'Missing required environment variables: DATABASE_URL, JWT_SECRET' }
    );

    const provided = {
        DATABASE_URL: 'postgresql://localhost:5432/test',
        JWT_SECRET: crypto.randomBytes(32).toString('hex')
    };
    assert.deepEqual(getRequiredEnvironment(provided), provided);
});

test('server exits before startup when required secrets are absent', () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-voting-env-test-'));
    const env = { ...process.env };
    delete env.DATABASE_URL;
    delete env.JWT_SECRET;
    try {
        const result = childProcess.spawnSync(
            process.execPath,
            [path.join(__dirname, 'server.js')],
            { cwd, env, encoding: 'utf8' }
        );
        assert.equal(result.status, 1);
        assert.match(result.stderr, /Missing required environment variables: DATABASE_URL, JWT_SECRET/);
    } finally {
        fs.rmSync(cwd, { recursive: true, force: true });
    }
});

test('super admins can delegate and revoke sub-admin roles', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const calls = [];
    let voterListSql;
    const app = express();
    app.use(express.json());
    app.use('/api/admin', adminRouter.createAdminRouter({
        async query(sql, values) {
            if (sql.includes("role IN ('voter', 'sub_admin')")) {
                voterListSql = sql;
                return {
                    rows: [
                        {
                            user_id: 12,
                            full_name: 'Delegated User',
                            email: 'delegated@example.com',
                            is_approved: true,
                            role: 'sub_admin',
                            permissions: {
                                can_approve_voters: true,
                                can_view_results: false,
                                can_export_csv: true
                            }
                        },
                        {
                            user_id: 13,
                            full_name: 'Regular User',
                            email: 'regular@example.com',
                            is_approved: false,
                            role: 'voter',
                            permissions: {}
                        }
                    ]
                };
            }
            calls.push({ sql, values });
            return {
                rows: [{
                    user_id: values[2],
                    full_name: 'Delegated User',
                    email: 'delegated@example.com',
                    role: values[0],
                    permissions: JSON.parse(values[1])
                }]
            };
        }
    }, async (...args) => calls.push({ audit: args })));
    const baseUrl = await listen(t, app);
    const superAdminToken = jwt.sign(
        { user_id: 99, role: 'super_admin', permissions: {} },
        process.env.JWT_SECRET
    );
    const subAdminToken = jwt.sign(
        { user_id: 7, role: 'sub_admin', permissions: { can_approve_voters: true } },
        process.env.JWT_SECRET
    );
    const permissions = {
        can_approve_voters: true,
        can_view_results: false,
        can_export_csv: true
    };

    const voters = await fetch(`${baseUrl}/api/admin/voters`, {
        headers: { Authorization: `Bearer ${superAdminToken}` }
    });
    assert.equal(voters.status, 200);
    assert.deepEqual(await voters.json(), [
        {
            user_id: 12,
            full_name: 'Delegated User',
            email: 'delegated@example.com',
            is_approved: true,
            role: 'sub_admin',
            permissions
        },
        {
            user_id: 13,
            full_name: 'Regular User',
            email: 'regular@example.com',
            is_approved: false,
            role: 'voter',
            permissions: {}
        }
    ]);
    assert.match(voterListSql, /role IN \('voter', 'sub_admin'\)/);
    assert.match(voterListSql, /role, permissions/);

    const delegated = await fetch(`${baseUrl}/api/admin/delegate-role`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${superAdminToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ user_id: 12, role: 'sub_admin', permissions })
    });

    assert.equal(delegated.status, 200);
    assert.deepEqual((await delegated.json()).user.permissions, permissions);
    assert.equal(calls[0].values[0], 'sub_admin');
    assert.deepEqual(JSON.parse(calls[0].values[1]), permissions);
    assert.equal(calls[1].audit[1], 'DELEGATE_SUB_ADMIN');

    const revoked = await fetch(`${baseUrl}/api/admin/delegate-role`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${superAdminToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ user_id: 12, role: 'voter', permissions })
    });
    assert.equal(revoked.status, 200);
    assert.equal(calls[2].values[0], 'voter');
    assert.deepEqual(JSON.parse(calls[2].values[1]), {
        can_approve_voters: false,
        can_view_results: false,
        can_export_csv: false
    });
    assert.equal(calls[3].audit[1], 'REVOKE_SUB_ADMIN');

    const unauthorized = await fetch(`${baseUrl}/api/admin/delegate-role`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${subAdminToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ user_id: 12, role: 'voter', permissions: {} })
    });
    assert.equal(unauthorized.status, 403);
    assert.deepEqual(await unauthorized.json(), { error: 'Insufficient delegated permissions' });
});

test('super admins can revoke sub-admin approval but cannot revoke their own', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const queries = [];
    const auditEntries = [];
    const app = express();
    app.use(express.json());
    app.use('/api/admin', adminRouter.createAdminRouter({
        async query(sql, values) {
            queries.push({ sql, values });
            if (values[1] === 12) {
                return {
                    rows: [{ user_id: 12, full_name: 'Sub Admin', is_approved: values[0] }]
                };
            }
            return { rows: [] };
        }
    }, async (...entry) => auditEntries.push(entry)));
    const baseUrl = await listen(t, app);
    const superAdminToken = jwt.sign(
        { user_id: 99, role: 'super_admin', permissions: {} },
        process.env.JWT_SECRET
    );
    const headers = {
        Authorization: `Bearer ${superAdminToken}`,
        'Content-Type': 'application/json'
    };

    const revoked = await fetch(`${baseUrl}/api/admin/voters/12/approve`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({ is_approved: false })
    });
    assert.equal(revoked.status, 200);
    assert.deepEqual((await revoked.json()).voter, {
        user_id: 12,
        full_name: 'Sub Admin',
        is_approved: false
    });
    assert.match(queries[0].sql, /AND role != 'super_admin'/);
    assert.deepEqual(queries[0].values, [false, 12]);
    assert.equal(auditEntries[0][1], 'REVOKE_VOTER');
    assert.deepEqual(JSON.parse(auditEntries[0][2]), {
        user_id: 12,
        is_approved: false
    });

    const selfRevocation = await fetch(`${baseUrl}/api/admin/voters/99/approve`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({ is_approved: false })
    });
    assert.equal(selfRevocation.status, 404);
    assert.equal(auditEntries.length, 1);
    assert.deepEqual(queries[1].values, [false, 99]);
});

test('sub-admin permissions allow delegated actions and block unauthorized admin routes', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const app = express();
    app.use(express.json());
    app.put('/api/admin/voters/:id/approve', verifyToken, verifyAdmin('can_approve_voters'), (req, res) => {
        res.sendStatus(204);
    });
    app.get('/api/admin/export-results', verifyToken, verifyAdmin('can_export_csv'), (req, res) => {
        res.sendStatus(204);
    });
    app.use('/api/polls', pollsRouter.createPollsRouter({
        async query(sql) {
            if (sql.includes('SELECT c.candidate_id')) return { rows: [] };
            return { rows: [{ total_votes_cast: '0', approved_voters: '0' }] };
        }
    }, async () => {}));
    app.use('/api/candidates', candidatesRouter.createCandidatesRouter({
        async query(sql) {
            if (sql.includes('CAST(COUNT(v.vote_id) AS INTEGER)')) return { rows: [] };
            throw new Error('Database should not be reached for unauthorized routes.');
        }
    }));
    const baseUrl = await listen(t, app);
    const subAdminToken = jwt.sign({
        user_id: 7,
        role: 'sub_admin',
        permissions: {
            can_approve_voters: true,
            can_view_results: true,
            can_export_csv: false
        }
    }, process.env.JWT_SECRET);
    const headers = { Authorization: `Bearer ${subAdminToken}` };

    const approval = await fetch(`${baseUrl}/api/admin/voters/12/approve`, {
        method: 'PUT',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_approved: true })
    });
    assert.equal(approval.status, 204);

    const results = await fetch(`${baseUrl}/api/polls/1/results`, { headers });
    assert.equal(results.status, 200);

    const candidates = await fetch(`${baseUrl}/api/candidates/1`, { headers });
    assert.equal(candidates.status, 200);

    const exportResults = await fetch(`${baseUrl}/api/admin/export-results`, { headers });
    assert.equal(exportResults.status, 403);
    assert.deepEqual(await exportResults.json(), { error: 'Insufficient delegated permissions' });

    const exportAllowedToken = jwt.sign({
        user_id: 8,
        role: 'sub_admin',
        permissions: { can_export_csv: true }
    }, process.env.JWT_SECRET);
    const exportAllowed = await fetch(`${baseUrl}/api/admin/export-results`, {
        headers: { Authorization: `Bearer ${exportAllowedToken}` }
    });
    assert.equal(exportAllowed.status, 204);

    const pollCreation = await fetch(`${baseUrl}/api/polls/create`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
            title: 'Forbidden Poll',
            start_time: new Date(Date.now() - 60_000).toISOString(),
            end_time: new Date(Date.now() + 60_000).toISOString()
        })
    });
    assert.equal(pollCreation.status, 403);
    assert.deepEqual(await pollCreation.json(), { error: 'Insufficient delegated permissions' });

    const candidateAddition = await fetch(`${baseUrl}/api/candidates/add`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: 'Blocked Candidate',
            photo_url: 'https://images.example.com/candidate.png'
        })
    });
    assert.equal(candidateAddition.status, 403);
    assert.deepEqual(await candidateAddition.json(), { error: 'Insufficient delegated permissions' });

    const candidateDeletion = await fetch(`${baseUrl}/api/candidates/1`, {
        method: 'DELETE',
        headers
    });
    assert.equal(candidateDeletion.status, 403);
    assert.deepEqual(await candidateDeletion.json(), { error: 'Insufficient delegated permissions' });

    const forbiddenResults = await fetch(`${baseUrl}/api/polls/1/results`, {
        headers: {
            Authorization: `Bearer ${jwt.sign({
                user_id: 8,
                role: 'sub_admin',
                permissions: {}
            }, process.env.JWT_SECRET)}`
        }
    });
    assert.equal(forbiddenResults.status, 403);
    assert.deepEqual(await forbiddenResults.json(), { error: 'Insufficient delegated permissions' });

    const forbiddenCandidates = await fetch(`${baseUrl}/api/candidates/1`, {
        headers: {
            Authorization: `Bearer ${jwt.sign({
                user_id: 8,
                role: 'sub_admin',
                permissions: {}
            }, process.env.JWT_SECRET)}`
        }
    });
    assert.equal(forbiddenCandidates.status, 403);
    assert.deepEqual(await forbiddenCandidates.json(), { error: 'Insufficient delegated permissions' });
});

test('unexpected errors, malformed JSON, and unknown routes return safe JSON', async t => {
    const loggedErrors = [];
    const originalConsoleError = console.error;
    console.error = entry => loggedErrors.push(entry);
    t.after(() => {
        console.error = originalConsoleError;
    });

    const app = express();
    app.use(express.json());
    app.get('/unexpected-error', (req, res, next) => {
        const error = new Error(
            'password=never-log-this JWT_SECRET=never-log-this DATABASE_URL=never-log-this Authorization: never-log-this'
        );
        error.code = 'XX000';
        error.detail = 'raw database detail';
        error.query = 'SELECT secret FROM users';
        next(error);
    });
    app.use(notFound);
    app.use(errorHandler);
    const baseUrl = await listen(t, app);

    const missingRoute = await fetch(`${baseUrl}/unknown-route`);
    assert.equal(missingRoute.status, 404);
    const missingBody = await missingRoute.json();
    assert.deepEqual(missingBody, { error: 'Not found' });

    const unexpectedError = await fetch(`${baseUrl}/unexpected-error`);
    assert.equal(unexpectedError.status, 500);
    const unexpectedBody = await unexpectedError.json();
    assert.deepEqual(unexpectedBody, { error: 'Internal server error' });

    const malformedJson = await fetch(`${baseUrl}/unexpected-error`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"invalid":'
    });
    assert.equal(malformedJson.status, 400);
    const malformedBody = await malformedJson.json();
    assert.deepEqual(malformedBody, { error: 'Invalid JSON payload' });

    for (const body of [missingBody, unexpectedBody, malformedBody]) {
        assert.doesNotMatch(JSON.stringify(body), /never-log-this|raw database detail|SELECT secret|node_modules|\.js:\d+/i);
    }

    assert.equal(loggedErrors.length, 2);
    const loggedError = JSON.parse(loggedErrors[0]);
    assert.equal(loggedError.error.code, 'XX000');
    const logOutput = loggedErrors.join('\n');
    assert.doesNotMatch(logOutput, /never-log-this|raw database detail|SELECT secret/i);
});

test('failed logins back off by account and successful login resets the backoff', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const passwordHash = await bcrypt.hash('correct-password', 4);
    const fakePool = {
        async query() {
            return {
                rows: [{
                    user_id: 7,
                    email: 'voter@example.com',
                    password_hash: passwordHash,
                    role: 'voter',
                    permissions: {
                        can_approve_voters: false,
                        can_view_results: false,
                        can_export_csv: false
                    },
                    is_approved: true
                }]
            };
        }
    };
    const limits = createRateLimiters(config({
        RATE_LIMIT_LOGIN_IP_MAX: '50',
        RATE_LIMIT_ACCOUNT_FAILURE_THRESHOLD: '2',
        RATE_LIMIT_ACCOUNT_FAILURE_WINDOW_MS: '60000',
        RATE_LIMIT_ACCOUNT_BACKOFF_BASE_MS: '1000',
        RATE_LIMIT_ACCOUNT_BACKOFF_MULTIPLIER: '2',
        RATE_LIMIT_ACCOUNT_BACKOFF_MAX_MS: '4000'
    }));
    const app = express();
    app.set('trust proxy', 1);
    app.use(express.json());
    app.use('/api/auth', authRouter.createAuthRouter(fakePool, limits));
    const baseUrl = await listen(t, app);
    const login = (password, identifier = 'Voter@example.com') => fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier, password })
    });

    const invalidPayload = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: 'Voter@example.com', password: 'wrongpass', unexpected: true })
    });
    assert.equal(invalidPayload.status, 400);
    assert.equal((await invalidPayload.json()).error, 'Validation failed');

    assert.equal((await login('wrongpass')).status, 401);
    assert.equal((await login('wrongpass', '1234567890')).status, 401);

    const blocked = await login('wrongpass');
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get('retry-after'), '1');
    assert.equal(blocked.headers.get('ratelimit-limit'), '2');
    assert.deepEqual(await blocked.json(), {
        error: 'Too many requests. Please try again later.',
        retryAfterSeconds: 1
    });

    await new Promise(resolve => setTimeout(resolve, 1050));
    assert.equal((await login('wrongpass')).status, 401);
    const exponentialBackoff = await login('wrongpass');
    assert.equal(exponentialBackoff.status, 429);
    assert.equal(exponentialBackoff.headers.get('retry-after'), '2');

    await new Promise(resolve => setTimeout(resolve, 2050));
    const successfulLogin = await login('correct-password');
    assert.equal(successfulLogin.status, 200);
    const loginBody = await successfulLogin.json();
    assert.equal(loginBody.role, 'voter');
    assert.deepEqual(loginBody.permissions, {
        can_approve_voters: false,
        can_view_results: false,
        can_export_csv: false
    });
    assert.equal(jwt.verify(loginBody.token, process.env.JWT_SECRET).role, 'voter');
    assert.deepEqual(jwt.verify(loginBody.token, process.env.JWT_SECRET).permissions, loginBody.permissions);

    assert.equal((await login('wrongpass')).status, 401);
    assert.equal((await login('wrongpass')).status, 401);
    const afterReset = await login('wrongpass');
    assert.equal(afterReset.status, 429);
    assert.equal(afterReset.headers.get('retry-after'), '1');
});

test('legacy admin logins are represented as super_admin with permissions in the token', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const permissions = { can_approve_voters: true, can_view_results: true, can_export_csv: true };
    const passwordHash = await bcrypt.hash('correct-password', 4);
    const app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter.createAuthRouter({
        async query() {
            return {
                rows: [{
                    user_id: 99,
                    email: 'admin@example.com',
                    password_hash: passwordHash,
                    role: 'admin',
                    permissions,
                    is_approved: false
                }]
            };
        }
    }, createRateLimiters(config())));
    const baseUrl = await listen(t, app);
    const response = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'admin@example.com', password: 'correct-password' })
    });

    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.role, 'super_admin');
    assert.deepEqual(body.permissions, permissions);
    const tokenPayload = jwt.verify(body.token, process.env.JWT_SECRET);
    assert.equal(tokenPayload.role, 'super_admin');
    assert.deepEqual(tokenPayload.permissions, permissions);
});

test('face-enrollment tokens are rejected by normal protected routes', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const app = express();
    app.get('/protected', verifyToken, (req, res) => res.sendStatus(204));
    app.get('/register-face', verifyToken.allowFaceEnroll, (req, res) => res.sendStatus(204));
    const baseUrl = await listen(t, app);
    const enrollToken = jwt.sign(
        { user_id: 7, role: 'voter', scope: 'face_enroll' },
        process.env.JWT_SECRET,
        { expiresIn: '10m' }
    );
    const headers = { Authorization: `Bearer ${enrollToken}` };

    assert.equal((await fetch(`${baseUrl}/protected`, { headers })).status, 403);
    assert.equal((await fetch(`${baseUrl}/register-face`, { headers })).status, 204);
});

test('face verification returns a short-lived single-use token without exposing embeddings', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const embedding = Array(192).fill(0);
    const fakePool = {
        async query() {
            return { rowCount: 1, rows: [{ face_embedding: embedding }] };
        }
    };
    const app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter.createAuthRouter(fakePool, createRateLimiters(config())));
    app.use(notFound);
    const baseUrl = await listen(t, app);
    const accessToken = jwt.sign(
        { user_id: 7, role: 'voter' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );
    const headers = {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
    };
    const response = await fetch(`${baseUrl}/api/auth/verify-face`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ face_embedding: embedding })
    });

    assert.equal(response.status, 200);
    const { verification_token } = await response.json();
    const payload = jwt.verify(verification_token, process.env.JWT_SECRET);
    assert.equal(payload.scope, 'vote_verify');
    assert.equal(payload.userId, 7);
    assert.ok(payload.jti);
    assert.ok(payload.exp - payload.iat <= 120);
    assert.equal(consumeVerificationToken(verification_token, 7), true);
    assert.equal(consumeVerificationToken(verification_token, 7), false);

    const exposedEmbedding = await fetch(`${baseUrl}/api/auth/face-embedding`, { headers });
    assert.equal(exposedEmbedding.status, 404);
});

test('password reset requires matching account details and face before updating and auditing', async t => {
    const storedEmbedding = Array(192).fill(0);
    let account = {
        user_id: 7,
        email: 'voter@example.com',
        face_embedding: storedEmbedding
    };
    const calls = [];
    const fakePool = {
        async query(sql, params) {
            calls.push({ sql, params });
            if (sql.startsWith('SELECT user_id, email, face_embedding')) {
                return { rows: account ? [{ ...account }] : [], rowCount: account ? 1 : 0 };
            }
            if (sql.startsWith('UPDATE public.users')) {
                account.password_hash = params[0];
                return { rows: [], rowCount: 1 };
            }
            if (sql.startsWith('INSERT INTO public.audit_logs')) {
                return { rows: [], rowCount: 1 };
            }
            throw new Error(`Unexpected query: ${sql}`);
        }
    };
    const app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter.createAuthRouter(fakePool, createRateLimiters(config())));
    app.use(notFound);
    const baseUrl = await listen(t, app);
    const reset = body => fetch(`${baseUrl}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    const body = {
        email: 'voter@example.com',
        mobile_no: '1234567890',
        face_embedding: storedEmbedding,
        new_password: 'new-password'
    };

    const missingField = await reset({ ...body, new_password: undefined });
    assert.equal(missingField.status, 400);
    assert.equal(calls.length, 0);

    account = null;
    const accountNotFound = await reset(body);
    assert.equal(accountNotFound.status, 404);
    assert.deepEqual(await accountNotFound.json(), {
        error: 'No account matches that email and mobile number'
    });

    account = { user_id: 7, email: 'voter@example.com', face_embedding: null };
    const unregisteredFace = await reset(body);
    assert.equal(unregisteredFace.status, 401);
    assert.deepEqual(await unregisteredFace.json(), { error: 'Biometric face verification failed' });

    account = { user_id: 7, email: 'voter@example.com', face_embedding: storedEmbedding };
    const faceMismatch = await reset({ ...body, face_embedding: Array(192).fill(1) });
    assert.equal(faceMismatch.status, 401);
    assert.deepEqual(await faceMismatch.json(), { error: 'Biometric face verification failed' });

    const successfulReset = await reset(body);
    assert.equal(successfulReset.status, 200);
    assert.deepEqual(await successfulReset.json(), { message: 'Password reset successfully' });
    assert.match(account.password_hash, /^\$2[aby]\$10\$/);
    assert.equal(await bcrypt.compare(body.new_password, account.password_hash), true);

    const selectCall = calls.find(call => call.sql.startsWith('SELECT user_id, email, face_embedding'));
    assert.equal(selectCall.sql.includes('email = $1 AND mobile_no = $2'), true);
    assert.deepEqual(selectCall.params, [body.email, body.mobile_no]);
    const auditCall = calls.find(call => call.sql.startsWith('INSERT INTO public.audit_logs'));
    assert.equal(auditCall.params[2], 'PASSWORD_RESET_BIOMETRIC');
});

test('strict schemas validate candidate, vote, and receipt inputs', async t => {
    assert.deepEqual(voteSchema.parse({
        candidate_id: 3,
        election_id: 9,
        verification_token: 'signed-token'
    }), {
        candidate_id: 3,
        poll_id: 9,
        verification_token: 'signed-token'
    });
    assert.deepEqual(voteSchema.parse({
        candidate_id: '3',
        election_id: '9',
        verification_token: 'signed-token'
    }), {
        candidate_id: 3,
        poll_id: 9,
        verification_token: 'signed-token'
    });
    assert.deepEqual(candidateSchema.parse({
        name: 'Jordan Lee',
        party: 'Civic Party',
        photo_url: 'https://images.example.com/jordan.jpg'
    }), {
        name: 'Jordan Lee',
        party: 'Civic Party',
        photo_url: 'https://images.example.com/jordan.jpg'
    });
    assert.deepEqual(candidateSchema.parse({
        name: 'Jordan Lee',
        party: null,
        photo_url: 'data:image/png;base64,AAAA'
    }), {
        name: 'Jordan Lee',
        party: 'Independent',
        photo_url: 'data:image/png;base64,AAAA'
    });
    assert.deepEqual(candidateSchema.parse({
        name: 'Jordan Lee',
        party: '',
        poll_id: '12',
        photo_url: 'https://images.example.com/jordan.jpg'
    }), {
        name: 'Jordan Lee',
        party: 'Independent',
        poll_id: 12,
        photo_url: 'https://images.example.com/jordan.jpg'
    });
    assert.equal(candidateSchema.safeParse({
        name: 'Jordan Lee',
        party: null,
        photo_url: `data:image/png;base64,${'A'.repeat(3_900_000)}`
    }).success, true);
    assert.equal(candidateSchema.safeParse({
        name: 'Jordan Lee',
        party: 'Civic Party',
        photo_url: 'A'.repeat(4_000_001)
    }).success, false);
    assert.equal(candidateSchema.safeParse({
        name: 'Jordan Lee',
        party: 'Civic Party',
        photo_url: null
    }).success, false);
    assert.equal(candidateSchema.safeParse({
        name: 'Jordan Lee',
        party: 'Civic Party',
        photo_url: ''
    }).success, false);
    assert.deepEqual(candidateIdParamsSchema.parse({ candidate_id: '15' }), { candidate_id: 15 });
    assert.deepEqual(voterIdParamsSchema.parse({ id: '23' }), { id: 23 });
    assert.equal(candidateSchema.safeParse({
        name: 'Invalid <Name>',
        party: 'Civic Party'
    }).success, false);
    assert.equal(voteSchema.safeParse({
        candidate_id: '3',
        election_id: 9,
        verification_token: 'signed-token'
    }).success, true);
    assert.equal(voteSchema.safeParse({
        candidate_id: 3,
        election_id: 9
    }).success, false);
    assert.equal(receiptHashParamsSchema.safeParse({ hash: 'g'.repeat(64) }).success, false);

    const app = express();
    app.use(express.json());
    app.post('/api/admin/candidates', validate(candidateSchema), (req, res) => {
        res.status(201).json(req.body);
    });
    app.post('/api/votes/cast', validate(voteSchema), (req, res) => res.json(req.body));
    app.get('/api/votes/verify/:hash', validate(receiptHashParamsSchema, 'params'), (req, res) => {
        res.sendStatus(204);
    });
    const baseUrl = await listen(t, app);

    const candidateWithoutPhoto = await fetch(`${baseUrl}/api/admin/candidates`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Jordan Lee', party: 'Civic Party' })
    });
    assert.equal(candidateWithoutPhoto.status, 400);
    const missingPhotoBody = await candidateWithoutPhoto.json();
    assert.equal(missingPhotoBody.error, 'Validation failed');
    assert.ok(Array.isArray(missingPhotoBody.details));

    for (const photoUrl of [null, '']) {
        const invalidCandidate = await fetch(`${baseUrl}/api/admin/candidates`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: 'Jordan Lee',
                party: 'Civic Party',
                photo_url: photoUrl
            })
        });
        assert.equal(invalidCandidate.status, 400);
        assert.equal((await invalidCandidate.json()).error, 'Validation failed');
    }

    const validCandidate = await fetch(`${baseUrl}/api/admin/candidates`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: 'Jordan Lee',
            party: 'Civic Party',
            photo_url: 'data:image/png;base64,AAAA'
        })
    });
    assert.equal(validCandidate.status, 201);
    assert.equal((await validCandidate.json()).photo_url, 'data:image/png;base64,AAAA');

    const validVote = await fetch(`${baseUrl}/api/votes/cast`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            candidate_id: 3,
            election_id: 9,
            verification_token: 'signed-token'
        })
    });
    assert.equal(validVote.status, 200);
    assert.deepEqual(await validVote.json(), {
        candidate_id: 3,
        poll_id: 9,
        verification_token: 'signed-token'
    });

    const invalidVote = await fetch(`${baseUrl}/api/votes/cast`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            candidate_id: 3,
            election_id: 9,
            verification_token: 'signed-token',
            extra: true
        })
    });
    assert.equal(invalidVote.status, 400);
    const invalidVoteBody = await invalidVote.json();
    assert.deepEqual(Object.keys(invalidVoteBody).sort(), ['details', 'error']);
    assert.equal(invalidVoteBody.error, 'Validation failed');
    assert.ok(Array.isArray(invalidVoteBody.details));

    const malformedHash = await fetch(`${baseUrl}/api/votes/verify/${'a'.repeat(63)}`);
    assert.equal(malformedHash.status, 400);
    assert.equal((await malformedHash.json()).error, 'Validation failed');
    assert.equal((await fetch(`${baseUrl}/api/votes/verify/${'a'.repeat(65)}`)).status, 400);
    assert.equal((await fetch(`${baseUrl}/api/votes/verify/${'a'.repeat(1024)}`)).status, 400);
    assert.equal((await fetch(`${baseUrl}/api/votes/verify/${'a'.repeat(64)}`)).status, 204);
});

test('vote casting requires a verification token before accessing the database', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const app = express();
    app.use(express.json());
    app.use('/api/votes', votesRouter.createVotesRouter({
        async connect() {
            throw new Error('Database should not be reached for invalid input.');
        }
    }));
    const baseUrl = await listen(t, app);
    const accessToken = jwt.sign(
        { user_id: 7, role: 'voter' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );
    const response = await fetch(`${baseUrl}/api/votes/cast`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ candidate_id: 3, poll_id: 9 })
    });

    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, 'Validation failed');
});

test('admins and other non-voter roles are forbidden from casting votes', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const app = express();
    app.use(express.json());
    app.use('/api/votes', votesRouter.createVotesRouter({
        async connect() {
            throw new Error('Database should not be reached for non-voters.');
        }
    }));
    const baseUrl = await listen(t, app);
    for (const role of ['admin', 'auditor']) {
        const accessToken = jwt.sign(
            { user_id: 7, role },
            process.env.JWT_SECRET,
            { expiresIn: '2h' }
        );
        const response = await fetch(`${baseUrl}/api/votes/cast`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})
        });

        assert.equal(response.status, 403);
        assert.deepEqual(await response.json(), {
            error: 'Administrators are not permitted to cast votes'
        });
    }
});

test('vote casting serializes ledger writes and maps unique conflicts to 409', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const queries = [];
    let released = 0;
    let failInsert = false;
    const voteInserts = [];
    const fakePool = {
        async connect() {
            return {
                async query(query, params) {
                    queries.push(query);
                    if (query === 'SELECT start_time, end_time, is_active FROM polls WHERE poll_id = $1') {
                        return {
                            rows: [{
                                start_time: new Date(Date.now() - 60_000),
                                end_time: new Date(Date.now() + 60_000),
                                is_active: true
                            }]
                        };
                    }
                    if (query === 'SELECT 1 FROM candidates WHERE candidate_id = $1 AND poll_id = $2') {
                        return { rows: [{}] };
                    }
                    if (query === 'SELECT role, is_approved FROM users WHERE user_id = $1') {
                        return { rows: [{ role: 'voter', is_approved: true }] };
                    }
                    if (query === 'SELECT 1 FROM voter_turnout WHERE poll_id = $1 AND voter_id = $2') {
                        return { rows: [] };
                    }
                    if (query === 'SELECT current_hash FROM votes ORDER BY vote_id DESC LIMIT 1') {
                        return { rows: [] };
                    }
                    if (query.startsWith('INSERT INTO votes')) {
                        voteInserts.push({ query, params });
                        if (failInsert) {
                            const error = new Error('duplicate vote');
                            error.code = '23505';
                            throw error;
                        }
                    }
                    return { rows: [] };
                },
                release() {
                    released += 1;
                }
            };
        }
    };
    const app = express();
    app.use(express.json());
    app.use('/api/votes', votesRouter.createVotesRouter(fakePool));
    const baseUrl = await listen(t, app);
    const accessToken = jwt.sign(
        { user_id: 7, role: 'voter' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );
    const castVote = verificationToken => fetch(`${baseUrl}/api/votes/cast`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ candidate_id: 3, poll_id: 9, verification_token: verificationToken })
    });
    const success = await castVote(issueVerificationToken(7));

    assert.equal(success.status, 201);
    const successBody = await success.json();
    assert.deepEqual(Object.keys(successBody).sort(), [
        'current_hash',
        'hash',
        'message',
        'receipt_hash'
    ]);
    assert.equal(successBody.receipt_hash, successBody.current_hash);
    assert.equal(voteInserts.length, 1);
    assert.match(voteInserts[0].query, /^INSERT INTO votes \(poll_id, candidate_id, ballot_nonce, previous_hash, current_hash\)/);
    assert.doesNotMatch(voteInserts[0].query, /\bvoter_id\b/);
    assert.equal(voteInserts[0].params.length, 5);
    assert.match(voteInserts[0].params[2], /^[a-f0-9]{64}$/);
    assert.equal(successBody.current_hash, generateHash(buildVoteHashInput({
        poll_id: 9,
        candidate_id: 3,
        ballot_nonce: voteInserts[0].params[2],
        previous_hash: '0'
    })));

    const lockIndex = queries.indexOf('SELECT pg_advisory_xact_lock(1247112202)');
    const duplicateCheckIndex = queries.indexOf('SELECT 1 FROM voter_turnout WHERE poll_id = $1 AND voter_id = $2');
    const latestHashIndex = queries.indexOf('SELECT current_hash FROM votes ORDER BY vote_id DESC LIMIT 1');
    const turnoutInsertIndex = queries.indexOf('INSERT INTO voter_turnout (poll_id, voter_id) VALUES ($1, $2)');
    const insertIndex = queries.findIndex(query => query.startsWith('INSERT INTO votes'));
    assert.ok(queries.indexOf('BEGIN') < lockIndex);
    assert.ok(lockIndex < duplicateCheckIndex);
    assert.ok(duplicateCheckIndex < latestHashIndex);
    assert.ok(latestHashIndex < turnoutInsertIndex);
    assert.ok(turnoutInsertIndex < insertIndex);
    assert.ok(insertIndex < queries.indexOf('COMMIT'));

    failInsert = true;
    const conflict = await castVote(issueVerificationToken(7));
    assert.equal(conflict.status, 409);
    assert.deepEqual(await conflict.json(), { error: 'You have already voted in this poll' });
    assert.equal(queries.includes('ROLLBACK'), true);
    assert.equal(released, 2);
});

test('vote status reveals only whether the authenticated voter has voted', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const results = [{ rows: [] }, { rows: [{ '?column?': 1 }] }];
    const queries = [];
    const app = express();
    app.set('trust proxy', 1);
    app.use('/api/votes', votesRouter.createVotesRouter({
        async query(query) {
            queries.push(query);
            return results.shift();
        }
    }));
    const baseUrl = await listen(t, app);
    const accessToken = jwt.sign(
        { user_id: 7, role: 'voter' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );
    const headers = { Authorization: `Bearer ${accessToken}` };

    const notVoted = await fetch(`${baseUrl}/api/votes/status/9`, { headers });
    assert.deepEqual(await notVoted.json(), { hasVoted: false });
    const hasVoted = await fetch(`${baseUrl}/api/votes/status/9`, { headers });
    assert.deepEqual(await hasVoted.json(), { hasVoted: true });
    assert.deepEqual(queries, [
        'SELECT 1 FROM voter_turnout WHERE poll_id = $1 AND voter_id = $2',
        'SELECT 1 FROM voter_turnout WHERE poll_id = $1 AND voter_id = $2'
    ]);
});

test('repeat voting is blocked using voter turnout', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const queries = [];
    const app = express();
    app.use(express.json());
    app.use('/api/votes', votesRouter.createVotesRouter({
        async connect() {
            return {
                async query(query) {
                    queries.push(query);
                    if (query === 'SELECT start_time, end_time, is_active FROM polls WHERE poll_id = $1') {
                        return {
                            rows: [{
                                start_time: new Date(Date.now() - 60_000),
                                end_time: new Date(Date.now() + 60_000),
                                is_active: true
                            }]
                        };
                    }
                    if (query === 'SELECT 1 FROM candidates WHERE candidate_id = $1 AND poll_id = $2') {
                        return { rows: [{}] };
                    }
                    if (query === 'SELECT role, is_approved FROM users WHERE user_id = $1') {
                        return { rows: [{ role: 'voter', is_approved: true }] };
                    }
                    if (query === 'SELECT 1 FROM voter_turnout WHERE poll_id = $1 AND voter_id = $2') {
                        return { rows: [{}] };
                    }
                    return { rows: [] };
                },
                release() {}
            };
        }
    }));
    const baseUrl = await listen(t, app);
    const accessToken = jwt.sign(
        { user_id: 7, role: 'voter' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );
    const response = await fetch(`${baseUrl}/api/votes/cast`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            candidate_id: 3,
            poll_id: 9,
            verification_token: issueVerificationToken(7)
        })
    });

    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), { error: 'You have already voted in this poll' });
    assert.ok(queries.includes('SELECT 1 FROM voter_turnout WHERE poll_id = $1 AND voter_id = $2'));
    assert.equal(queries.some(query => query.startsWith('INSERT INTO votes')), false);
});

test('anonymous ballot schema and vote-chain receipt verification do not use voter IDs', async t => {
    const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    const voteTable = schema.match(/CREATE TABLE IF NOT EXISTS votes \([\s\S]*?\n\);/);
    assert.ok(voteTable);
    assert.doesNotMatch(voteTable[0], /\bvoter_id\b/);
    assert.match(voteTable[0], /ballot_nonce VARCHAR\(64\) NOT NULL/);

    const ballot = {
        vote_id: 1,
        poll_id: 9,
        candidate_id: 3,
        ballot_nonce: crypto.randomBytes(32).toString('hex'),
        previous_hash: '0',
        vote_timestamp: new Date('2026-01-02T03:04:05.000Z').toISOString()
    };
    ballot.current_hash = generateHash(buildVoteHashInput(ballot));
    assert.equal(Object.prototype.hasOwnProperty.call(ballot, 'voter_id'), false);

    let chainQuery;
    const chainStatus = await verifyVoteChain({
        async query(query) {
            chainQuery = query;
            return { rows: [ballot] };
        }
    });
    assert.equal(chainStatus.valid, true);
    assert.equal(chainStatus.verified_blocks, 1);
    assert.equal(
        chainQuery,
        'SELECT vote_id, poll_id, candidate_id, ballot_nonce, previous_hash, current_hash FROM votes ORDER BY vote_id ASC'
    );
    assert.doesNotMatch(chainQuery, /\bvoter_id\b/);

    const app = express();
    app.use('/api/votes', votesRouter.createVotesRouter({
        async query(query) {
            if (query === 'SELECT vote_id, poll_id, candidate_id, ballot_nonce, previous_hash, current_hash, vote_timestamp FROM votes WHERE current_hash = $1') {
                return { rows: [ballot] };
            }
            if (query === 'SELECT * FROM votes WHERE vote_id < $1 ORDER BY vote_id DESC LIMIT 1') {
                return { rows: [] };
            }
            throw new Error(`Unexpected query: ${query}`);
        }
    }));
    const baseUrl = await listen(t, app);
    const response = await fetch(`${baseUrl}/api/votes/verify/${ballot.current_hash}`);

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
        verified: true,
        intact: true,
        timestamp: ballot.vote_timestamp,
        block_index: ballot.vote_id
    });
});

test('vote-chain verification rejects unauthenticated and non-admin requests', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    let chainScans = 0;
    const app = express();
    app.set('trust proxy', 1);
    app.use('/api/votes', votesRouter.createVotesRouter({
        async query() {
            chainScans += 1;
            return { rows: [] };
        }
    }));
    const baseUrl = await listen(t, app);

    const unauthenticated = await fetch(`${baseUrl}/api/votes/verify-chain`);
    assert.equal(unauthenticated.status, 401);

    const voterToken = jwt.sign(
        { user_id: 7, role: 'voter' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );
    const nonAdmin = await fetch(`${baseUrl}/api/votes/verify-chain`, {
        headers: { Authorization: `Bearer ${voterToken}` }
    });
    assert.equal(nonAdmin.status, 403);
    assert.equal(chainScans, 0);

    const adminToken = jwt.sign(
        { user_id: 99, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );
    const adminResponse = await fetch(`${baseUrl}/api/votes/verify-chain`, {
        headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(adminResponse.status, 200);
    assert.equal(chainScans, 1);
});

test('candidate deletion returns conflict when votes exist', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const queries = [];
    let released = false;
    const fakePool = {
        async connect() {
            return {
                async query(query) {
                    queries.push(query);
                    if (query === 'SELECT candidate_id FROM candidates WHERE candidate_id = $1 FOR UPDATE') {
                        return { rowCount: 1, rows: [{ candidate_id: 3 }] };
                    }
                    if (query === 'SELECT COUNT(*) AS vote_count FROM votes WHERE candidate_id = $1') {
                        return { rowCount: 1, rows: [{ vote_count: '1' }] };
                    }
                    return { rowCount: 0, rows: [] };
                },
                release() {
                    released = true;
                }
            };
        }
    };
    const app = express();
    app.use('/api/candidates', candidatesRouter.createCandidatesRouter(fakePool));
    const baseUrl = await listen(t, app);
    const adminToken = jwt.sign(
        { user_id: 99, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );

    const response = await fetch(`${baseUrl}/api/candidates/3`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${adminToken}` }
    });

    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), {
        error: 'Cannot delete candidate with existing votes'
    });
    assert.equal(queries.includes('DELETE FROM votes WHERE candidate_id = $1'), false);
    assert.equal(queries.includes('ROLLBACK'), true);
    assert.equal(released, true);
});

test('Cloudinary photo helper passes through URLs and uploads configured image data', async () => {
    const envNames = ['CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET'];
    const originalEnv = Object.fromEntries(envNames.map(name => [name, process.env[name]]));
    const originalUpload = cloudinarySdk.uploader.upload;
    const photoDataUri = 'data:image/png;base64,dGVzdA==';
    const cloudinaryUrl = 'https://res.cloudinary.com/example/image/upload/candidate.png';
    let uploadArguments;

    try {
        envNames.forEach(name => delete process.env[name]);
        assert.equal(isCloudinaryConfigured(), false);
        assert.equal(await uploadCandidatePhoto(photoDataUri), photoDataUri);
        assert.equal(await uploadCandidatePhoto('https://images.example.com/photo.png'), 'https://images.example.com/photo.png');

        process.env.CLOUDINARY_CLOUD_NAME = 'test-cloud';
        process.env.CLOUDINARY_API_KEY = 'test-key';
        process.env.CLOUDINARY_API_SECRET = 'test-secret';
        cloudinarySdk.uploader.upload = async (...args) => {
            uploadArguments = args;
            return { secure_url: cloudinaryUrl };
        };

        assert.equal(isCloudinaryConfigured(), true);
        assert.equal(await uploadCandidatePhoto(photoDataUri), cloudinaryUrl);
        assert.deepEqual(uploadArguments, [
            photoDataUri,
            {
                folder: 'secure-voting/candidates',
                resource_type: 'image',
                transformation: [{
                    width: 400,
                    height: 400,
                    crop: 'fill',
                    gravity: 'face',
                    quality: 'auto',
                    fetch_format: 'auto'
                }]
            }
        ]);
    } finally {
        cloudinarySdk.uploader.upload = originalUpload;
        envNames.forEach(name => {
            if (originalEnv[name] === undefined) delete process.env[name];
            else process.env[name] = originalEnv[name];
        });
    }
});

test('adding a candidate stores the Cloudinary URL returned for its Base64 photo', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const photoDataUri = 'data:image/png;base64,dGVzdA==';
    const cloudinaryUrl = 'https://res.cloudinary.com/example/image/upload/candidate.png';
    let insertedValues;
    let uploadedPhoto;
    const fakePool = {
        async query(sql, values) {
            assert.match(sql, /^INSERT INTO candidates/);
            insertedValues = values;
            return {
                rows: [{
                    candidate_id: 8,
                    poll_id: values[0],
                    candidate_name: values[1],
                    party: values[2],
                    photo_url: values[3]
                }]
            };
        }
    };
    const app = express();
    app.use(express.json());
    app.use('/api/candidates', candidatesRouter.createCandidatesRouter(
        fakePool,
        async () => {},
        async photoUrl => {
            uploadedPhoto = photoUrl;
            return cloudinaryUrl;
        }
    ));
    const baseUrl = await listen(t, app);
    const adminToken = jwt.sign(
        { user_id: 99, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );

    const response = await fetch(`${baseUrl}/api/candidates/add`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            name: 'Cloud Candidate',
            party: 'Civic Party',
            photo_url: photoDataUri
        })
    });

    assert.equal(response.status, 201);
    assert.equal(uploadedPhoto, photoDataUri);
    assert.equal(insertedValues[3], cloudinaryUrl);
    assert.equal((await response.json()).photo_url, cloudinaryUrl);
});

test('candidate photo upload failures return 502 without inserting a candidate', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    const originalConsoleError = console.error;
    console.error = () => {};
    t.after(() => {
        console.error = originalConsoleError;
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    let insertAttempted = false;
    const app = express();
    app.use(express.json());
    app.use('/api/candidates', candidatesRouter.createCandidatesRouter(
        {
            async query() {
                insertAttempted = true;
                return { rows: [] };
            }
        },
        async () => {},
        async () => {
            throw new Error('Cloudinary unavailable');
        }
    ));
    const baseUrl = await listen(t, app);
    const adminToken = jwt.sign(
        { user_id: 99, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );

    const response = await fetch(`${baseUrl}/api/candidates/add`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            name: 'Cloud Candidate',
            party: 'Civic Party',
            photo_url: 'data:image/png;base64,dGVzdA=='
        })
    });

    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), {
        error: 'Failed to upload candidate photo to cloud storage.'
    });
    assert.equal(insertAttempted, false);
});

test('poll APIs keep candidate counts, turnout, and the global chain independent across polls', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const now = Date.now();
    const poolQueries = [];
    const state = {
        polls: [{
            poll_id: 1,
            title: 'First Poll',
            description: 'Existing poll',
            start_time: new Date(now - 60_000),
            end_time: new Date(now + 30 * 60_000),
            is_active: true,
            is_private: false,
            security_code: 'first-secret',
            created_by: 99
        }],
        candidates: [{
            candidate_id: 1,
            poll_id: 1,
            candidate_name: 'First Candidate',
            party: 'Independent',
            photo_url: 'https://images.example.com/first.jpg'
        }],
        turnout: [],
        votes: [],
        users: [
            { user_id: 7, role: 'voter', is_approved: true },
            { user_id: 99, role: 'admin', is_approved: true }
        ],
        nextPollId: 2,
        nextCandidateId: 2,
        nextVoteId: 1
    };

    const database = {
        async query(query, params = []) {
            poolQueries.push(query);
            const sql = query.replace(/\s+/g, ' ').trim();

            if (sql.startsWith('SELECT p.poll_id,')) {
                const userId = params[0];
                return {
                    rows: state.polls.map(poll => ({
                        poll_id: poll.poll_id,
                        title: poll.title,
                        description: poll.description,
                        start_time: poll.start_time,
                        end_time: poll.end_time,
                        is_active: poll.is_active === null ? true : poll.is_active,
                        is_private: poll.is_private === null ? false : poll.is_private,
                        candidate_count: state.candidates.filter(candidate => candidate.poll_id === poll.poll_id).length,
                        has_voted: state.turnout.some(turnout =>
                            turnout.poll_id === poll.poll_id && turnout.voter_id === userId
                        )
                    })).sort((left, right) => right.poll_id - left.poll_id)
                };
            }

            if (sql.startsWith('INSERT INTO polls ')) {
                const [title, description, startTime, endTime, isPrivate, securityCode, createdBy] = params;
                const poll = {
                    poll_id: state.nextPollId++,
                    title,
                    description,
                    start_time: startTime,
                    end_time: endTime,
                    is_active: true,
                    is_private: isPrivate === null || isPrivate === undefined ? false : isPrivate,
                    security_code: securityCode,
                    created_by: createdBy
                };
                state.polls.push(poll);
                return {
                    rows: [{
                        poll_id: poll.poll_id,
                        title: poll.title,
                        description: poll.description,
                        start_time: poll.start_time,
                        end_time: poll.end_time,
                        is_private: poll.is_private,
                        created_by: poll.created_by,
                        is_active: poll.is_active
                    }]
                };
            }

            if (sql.startsWith('INSERT INTO candidates ')) {
                const [pollId, name, party, photoUrl] = params;
                const candidate = {
                    candidate_id: state.nextCandidateId++,
                    poll_id: pollId,
                    candidate_name: name,
                    party,
                    photo_url: photoUrl
                };
                state.candidates.push(candidate);
                return { rows: [candidate] };
            }

            if (sql.startsWith('SELECT c.candidate_id, c.candidate_name, c.party, c.photo_url, COUNT(v.vote_id)')) {
                const pollId = Number(params[0]);
                return {
                    rows: state.candidates
                        .filter(candidate => candidate.poll_id === pollId)
                        .map(candidate => ({
                            candidate_id: candidate.candidate_id,
                            candidate_name: candidate.candidate_name,
                            party: candidate.party,
                            photo_url: candidate.photo_url,
                            vote_count: String(state.votes.filter(vote =>
                                vote.candidate_id === candidate.candidate_id &&
                                vote.poll_id === candidate.poll_id
                            ).length)
                        }))
                };
            }

            if (sql.includes('(SELECT COUNT(*) FROM voter_turnout WHERE poll_id = $1)')) {
                const pollId = Number(params[0]);
                return {
                    rows: [{
                        total_votes_cast: String(state.turnout.filter(row => row.poll_id === pollId).length),
                        approved_voters: String(state.users.filter(user =>
                            user.role === 'voter' && user.is_approved === true
                        ).length)
                    }]
                };
            }

            if (sql === 'SELECT vote_id, poll_id, candidate_id, ballot_nonce, previous_hash, current_hash FROM votes ORDER BY vote_id ASC') {
                return { rows: [...state.votes].sort((left, right) => left.vote_id - right.vote_id) };
            }

            throw new Error(`Unexpected pool query: ${sql}`);
        },
        async connect() {
            return {
                async query(query, params = []) {
                    poolQueries.push(query);
                    const sql = query.replace(/\s+/g, ' ').trim();

                    if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK' ||
                        sql === 'SELECT pg_advisory_xact_lock(1247112202)') {
                        return { rows: [] };
                    }
                    if (sql === 'SELECT start_time, end_time, is_active FROM polls WHERE poll_id = $1') {
                        const poll = state.polls.find(item => item.poll_id === params[0]);
                        return { rows: poll ? [poll] : [] };
                    }
                    if (sql === 'SELECT 1 FROM candidates WHERE candidate_id = $1 AND poll_id = $2') {
                        return {
                            rows: state.candidates.some(candidate =>
                                candidate.candidate_id === params[0] && candidate.poll_id === params[1]
                            ) ? [{}] : []
                        };
                    }
                    if (sql === 'SELECT role, is_approved FROM users WHERE user_id = $1') {
                        const user = state.users.find(item => item.user_id === params[0]);
                        return { rows: user ? [user] : [] };
                    }
                    if (sql === 'SELECT 1 FROM voter_turnout WHERE poll_id = $1 AND voter_id = $2') {
                        return {
                            rows: state.turnout.some(row => row.poll_id === params[0] && row.voter_id === params[1])
                                ? [{}]
                                : []
                        };
                    }
                    if (sql === 'SELECT current_hash FROM votes ORDER BY vote_id DESC LIMIT 1') {
                        const latestVote = state.votes[state.votes.length - 1];
                        return { rows: latestVote ? [{ current_hash: latestVote.current_hash }] : [] };
                    }
                    if (sql === 'INSERT INTO voter_turnout (poll_id, voter_id) VALUES ($1, $2)') {
                        state.turnout.push({ poll_id: params[0], voter_id: params[1] });
                        return { rows: [] };
                    }
                    if (sql.startsWith('INSERT INTO votes ')) {
                        const [pollId, candidateId, ballotNonce, previousHash, currentHash] = params;
                        state.votes.push({
                            vote_id: state.nextVoteId++,
                            poll_id: pollId,
                            candidate_id: candidateId,
                            ballot_nonce: ballotNonce,
                            previous_hash: previousHash,
                            current_hash: currentHash,
                            vote_timestamp: new Date()
                        });
                        return { rows: [] };
                    }

                    throw new Error(`Unexpected client query: ${sql}`);
                },
                release() {}
            };
        }
    };

    const app = express();
    app.set('trust proxy', 1);
    app.use(express.json());
    app.use('/api/polls', pollsRouter.createPollsRouter(database, async () => {}));
    app.use('/api/candidates', candidatesRouter.createCandidatesRouter(database, async () => {}));
    app.use('/api/votes', votesRouter.createVotesRouter(database));
    const baseUrl = await listen(t, app);
    const adminToken = jwt.sign(
        { user_id: 99, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );
    const voterToken = jwt.sign(
        { user_id: 7, role: 'voter' },
        process.env.JWT_SECRET,
        { expiresIn: '2h' }
    );

    const createPollQuery = {
        title: 'Second Poll',
        description: 'Independent second election',
        start_time: new Date(Date.now() - 60_000).toISOString(),
        end_time: new Date(Date.now() + 30 * 60_000).toISOString(),
        is_private: false,
        security_code: 'second-secret'
    };
    const createPollResponse = await fetch(`${baseUrl}/api/polls/create`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(createPollQuery)
    });
    assert.equal(createPollResponse.status, 201);
    const createdPoll = await createPollResponse.json();
    assert.equal(createdPoll.poll.poll_id, 2);
    assert.equal(createdPoll.poll.is_active, true);
    assert.equal(Object.prototype.hasOwnProperty.call(createdPoll.poll, 'security_code'), false);

    const candidateResponse = await fetch(`${baseUrl}/api/candidates/add`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            name: 'Second Poll Candidate',
            party: 'Civic Party',
            poll_id: createdPoll.poll.poll_id,
            photo_url: 'https://images.example.com/second.jpg'
        })
    });
    assert.equal(candidateResponse.status, 201);
    const createdCandidate = await candidateResponse.json();
    assert.equal(createdCandidate.poll_id, createdPoll.poll.poll_id);

    const castVote = (pollId, candidateId) => fetch(`${baseUrl}/api/votes/cast`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${voterToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            poll_id: pollId,
            candidate_id: candidateId,
            verification_token: issueVerificationToken(7)
        })
    });
    assert.equal((await castVote(1, 1)).status, 201);
    assert.equal((await castVote(createdPoll.poll.poll_id, createdCandidate.candidate_id)).status, 201);

    const pollListResponse = await fetch(`${baseUrl}/api/polls`, {
        headers: { Authorization: `Bearer ${voterToken}` }
    });
    assert.equal(pollListResponse.status, 200);
    const pollList = await pollListResponse.json();
    assert.equal(pollList[0].poll_id, 2);
    assert.equal(pollList[0].status, 'LIVE');
    assert.equal(pollList[0].candidate_count, 1);
    assert.equal(pollList[0].has_voted, true);
    assert.equal(Object.prototype.hasOwnProperty.call(pollList[0], 'security_code'), false);
    assert.equal(pollList[1].candidate_count, 1);
    assert.equal(pollList[1].has_voted, true);
    assert.equal(Object.prototype.hasOwnProperty.call(pollList[1], 'security_code'), false);

    const pollListSql = poolQueries.find(query => query.includes('FROM polls p'));
    assert.doesNotMatch(pollListSql, /security_code/i);
    const insertPollSql = poolQueries.find(query => query.startsWith('INSERT INTO polls'));
    assert.match(insertPollSql, /TRUE, COALESCE\(\$5, FALSE\)/);
    assert.match(insertPollSql, /RETURNING poll_id, title, description, start_time, end_time, is_private, created_by, is_active$/);
    assert.doesNotMatch(insertPollSql.split('RETURNING')[1], /security_code/i);

    for (const pollId of [1, createdPoll.poll.poll_id]) {
        const resultsResponse = await fetch(`${baseUrl}/api/polls/${pollId}/results`);
        assert.equal(resultsResponse.status, 200);
        const results = await resultsResponse.json();
        assert.equal(results.turnout.total_votes_cast, 1);
        assert.equal(results.results.length, 1);
        assert.equal(Number(results.results[0].vote_count), 1);
    }

    const chainStatus = await verifyVoteChain(database);
    assert.equal(chainStatus.valid, true);
    assert.equal(chainStatus.total_votes, 2);
    assert.equal(state.votes[0].previous_hash, '0');
    assert.equal(state.votes[1].previous_hash, state.votes[0].current_hash);
    assert.equal(state.votes.every(vote =>
        !Object.prototype.hasOwnProperty.call(vote, 'voter_id')
    ), true);
});

test('public endpoints are rate limited using configured moderate thresholds', async t => {
    const limits = createRateLimiters(config({
        RATE_LIMIT_PUBLIC_MAX: '2',
        RATE_LIMIT_PUBLIC_WINDOW_MS: '60000'
    }));
    const app = express();
    app.set('trust proxy', 1);
    app.get('/api/polls/1/results', limits.public, (req, res) => res.json({ ok: true }));
    const baseUrl = await listen(t, app);

    assert.equal((await fetch(`${baseUrl}/api/polls/1/results`)).status, 200);
    assert.equal((await fetch(`${baseUrl}/api/polls/1/results`)).status, 200);
    const blocked = await fetch(`${baseUrl}/api/polls/1/results`);
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get('retry-after') !== null, true);
    assert.deepEqual(await blocked.json(), {
        error: 'Too many requests. Please try again later.',
        retryAfterSeconds: Number(blocked.headers.get('retry-after'))
    });
});

test('authenticated voter and admin policies allow normal traffic under their limits', async t => {
    const limits = createRateLimiters(config({
        RATE_LIMIT_VOTER_MAX: '5',
        RATE_LIMIT_ADMIN_MAX: '5'
    }));
    const app = express();
    app.set('trust proxy', 1);
    app.use('/api/voter', (req, res, next) => {
        req.user = { user_id: 12, role: 'voter' };
        next();
    });
    app.use('/api/admin', (req, res, next) => {
        req.user = { user_id: 99, role: 'admin' };
        next();
    });
    app.get('/api/voter/status', limits.voter, (req, res) => res.json({ ok: true }));
    app.get('/api/admin/audit-logs', limits.admin, (req, res) => res.json({ ok: true }));
    const baseUrl = await listen(t, app);

    for (let i = 0; i < 5; i += 1) {
        assert.equal((await fetch(`${baseUrl}/api/voter/status`)).status, 200);
        assert.equal((await fetch(`${baseUrl}/api/admin/audit-logs`)).status, 200);
    }
});

test('environment overrides change the active threshold', async t => {
    const originalMax = process.env.RATE_LIMIT_PUBLIC_MAX;
    const originalWindow = process.env.RATE_LIMIT_PUBLIC_WINDOW_MS;
    process.env.RATE_LIMIT_PUBLIC_MAX = '1';
    process.env.RATE_LIMIT_PUBLIC_WINDOW_MS = '60000';
    t.after(() => {
        if (originalMax === undefined) delete process.env.RATE_LIMIT_PUBLIC_MAX;
        else process.env.RATE_LIMIT_PUBLIC_MAX = originalMax;
        if (originalWindow === undefined) delete process.env.RATE_LIMIT_PUBLIC_WINDOW_MS;
        else process.env.RATE_LIMIT_PUBLIC_WINDOW_MS = originalWindow;
    });

    const limits = createRateLimiters();
    const app = express();
    app.set('trust proxy', 1);
    app.get('/api/polls/1/results', limits.public, (req, res) => res.sendStatus(204));
    const baseUrl = await listen(t, app);

    assert.equal((await fetch(`${baseUrl}/api/polls/1/results`)).status, 204);
    const blocked = await fetch(`${baseUrl}/api/polls/1/results`);
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get('ratelimit-limit'), '1');
});
