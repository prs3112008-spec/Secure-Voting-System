const assert = require('node:assert/strict');
const { test } = require('node:test');
const bcrypt = require('bcryptjs');
const express = require('express');
const authRouter = require('./routes/auth');
const { createRateLimiters, getRateLimitConfig } = require('./middleware/rateLimits');
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

test('failed logins back off by account and successful login resets the backoff', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = 'test-secret';
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

test('strict schemas validate candidate, vote, and receipt inputs', async t => {
    assert.deepEqual(voteSchema.parse({ candidate_id: 3, election_id: 9 }), {
        candidate_id: 3,
        poll_id: 9
    });
    assert.deepEqual(voteSchema.parse({ candidate_id: '3', election_id: '9' }), {
        candidate_id: 3,
        poll_id: 9
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
        election_id: 9
    }).success, true);
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
        body: JSON.stringify({ candidate_id: 3, election_id: 9 })
    });
    assert.equal(validVote.status, 200);
    assert.deepEqual(await validVote.json(), { candidate_id: 3, poll_id: 9 });

    const invalidVote = await fetch(`${baseUrl}/api/votes/cast`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ candidate_id: 3, election_id: 9, extra: true })
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
