const assert = require('node:assert/strict');
const { test } = require('node:test');
const bcrypt = require('bcryptjs');
const express = require('express');
const authRouter = require('./routes/auth');
const { createRateLimiters, getRateLimitConfig } = require('./middleware/rateLimits');

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
    const login = password => fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'Voter@example.com', password })
    });

    assert.equal((await login('wrong')).status, 401);
    assert.equal((await login('wrong')).status, 401);

    const blocked = await login('wrong');
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get('retry-after'), '1');
    assert.equal(blocked.headers.get('ratelimit-limit'), '2');
    assert.deepEqual(await blocked.json(), {
        error: 'Too many requests. Please try again later.',
        retryAfterSeconds: 1
    });

    await new Promise(resolve => setTimeout(resolve, 1050));
    assert.equal((await login('wrong')).status, 401);
    const exponentialBackoff = await login('wrong');
    assert.equal(exponentialBackoff.status, 429);
    assert.equal(exponentialBackoff.headers.get('retry-after'), '2');

    await new Promise(resolve => setTimeout(resolve, 2050));
    assert.equal((await login('correct-password')).status, 200);

    assert.equal((await login('wrong')).status, 401);
    assert.equal((await login('wrong')).status, 401);
    const afterReset = await login('wrong');
    assert.equal(afterReset.status, 429);
    assert.equal(afterReset.headers.get('retry-after'), '1');
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
