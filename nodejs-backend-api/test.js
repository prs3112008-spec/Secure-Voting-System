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
const pollsRouter = require('./routes/polls');
const votesRouter = require('./routes/votes');
const { createRateLimiters, getRateLimitConfig } = require('./middleware/rateLimits');
const { errorHandler, notFound } = require('./middleware/errorHandler');
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
                            user.role !== 'admin' && user.is_approved === true
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
