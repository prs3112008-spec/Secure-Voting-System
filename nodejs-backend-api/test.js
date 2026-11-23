const assert = require('node:assert/strict');
const { test } = require('node:test');
const bcrypt = require('bcryptjs');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const cors = require('cors');
const express = require('express');
const fs = require('node:fs');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const os = require('node:os');
const path = require('node:path');
const authRouter = require('./routes/auth');
const candidatesRouter = require('./routes/candidates');
const votesRouter = require('./routes/votes');
const { createRateLimiters, getRateLimitConfig } = require('./middleware/rateLimits');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const getRequiredEnvironment = require('./utils/requiredEnv');
const verifyToken = require('./middleware/verifyToken');
const {
    consumeVerificationToken,
    issueVerificationToken
} = require('./utils/verificationToken');
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
    assert.equal((await login('correct-password')).status, 200);

    assert.equal((await login('wrongpass')).status, 401);
    assert.equal((await login('wrongpass')).status, 401);
    const afterReset = await login('wrongpass');
    assert.equal(afterReset.status, 429);
    assert.equal(afterReset.headers.get('retry-after'), '1');
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
    const fakePool = {
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
                    if (query === 'SELECT * FROM votes WHERE poll_id = $1 AND voter_id = $2') {
                        return { rows: [] };
                    }
                    if (query === 'SELECT current_hash FROM votes ORDER BY vote_id DESC LIMIT 1') {
                        return { rows: [] };
                    }
                    if (query.startsWith('INSERT INTO votes') && failInsert) {
                        const error = new Error('duplicate vote');
                        error.code = '23505';
                        throw error;
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
    const lockIndex = queries.indexOf('SELECT pg_advisory_xact_lock(1247112202)');
    const duplicateCheckIndex = queries.indexOf('SELECT * FROM votes WHERE poll_id = $1 AND voter_id = $2');
    const latestHashIndex = queries.indexOf('SELECT current_hash FROM votes ORDER BY vote_id DESC LIMIT 1');
    const insertIndex = queries.findIndex(query => query.startsWith('INSERT INTO votes'));
    assert.ok(queries.indexOf('BEGIN') < lockIndex);
    assert.ok(lockIndex < duplicateCheckIndex);
    assert.ok(duplicateCheckIndex < latestHashIndex);
    assert.ok(latestHashIndex < insertIndex);
    assert.ok(insertIndex < queries.indexOf('COMMIT'));

    failInsert = true;
    const conflict = await castVote(issueVerificationToken(7));
    assert.equal(conflict.status, 409);
    assert.deepEqual(await conflict.json(), { error: 'You have already voted in this poll' });
    assert.equal(queries.includes('ROLLBACK'), true);
    assert.equal(released, 2);
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
    app.get('/api/votes/verify-chain', limits.public, (req, res) => res.sendStatus(204));
    const baseUrl = await listen(t, app);

    assert.equal((await fetch(`${baseUrl}/api/votes/verify-chain`)).status, 204);
    const blocked = await fetch(`${baseUrl}/api/votes/verify-chain`);
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get('ratelimit-limit'), '1');
});
