const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const authRouter = require('../routes/auth');
const pollsRouter = require('../routes/polls');

async function listen(t, app) {
    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
    });
    t.after(() => new Promise((resolve, reject) => {
        server.close(err => err ? reject(err) : resolve());
    }));
    return `http://127.0.0.1:${server.address().port}`;
}

function useTestSecret(t) {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });
}

test('registration rejects privileged and biometric fields', async t => {
    useTestSecret(t);
    const databaseCalls = [];
    const fakePool = {
        async query(sql, params) {
            databaseCalls.push({ sql, params });
            throw new Error('Registration with unexpected fields must not reach the database.');
        }
    };

    const app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter.createAuthRouter(fakePool));
    const baseUrl = await listen(t, app);

    const response = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            full_name: 'Attacker',
            email: 'attacker@test.com',
            mobile_no: '1234567890',
            password: 'StrongPassword123!',
            face_embedding: Array(192).fill(0.05),
            role: 'admin',
            is_approved: true
        })
    });

    assert.equal(response.status, 400);
    assert.equal(databaseCalls.length, 0, 'Invalid registration fields must be rejected before database access');
});

test('authenticated public poll responses do not expose sensitive user fields', async t => {
    useTestSecret(t);
    let pollQuery = '';
    let pollParams;
    const fakePool = {
        async query(sql, params) {
            pollQuery = sql;
            pollParams = params;
            return {
                rows: [{
                    poll_id: 8,
                    title: 'Student Council',
                    description: 'Election',
                    start_time: new Date(Date.now() - 60_000),
                    end_time: new Date(Date.now() + 60_000),
                    is_active: true,
                    is_private: false,
                    candidate_count: 2,
                    has_voted: false
                }]
            };
        }
    };

    const app = express();
    app.use(express.json());
    app.use('/api/polls', pollsRouter.createPollsRouter(fakePool, async () => {}));
    const baseUrl = await listen(t, app);
    const voterJwt = jwt.sign(
        { user_id: 101, role: 'voter' },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    const response = await fetch(`${baseUrl}/api/polls`, {
        headers: { Authorization: `Bearer ${voterJwt}` }
    });
    const body = await response.json();
    const rawBody = JSON.stringify(body);

    assert.equal(response.status, 200);
    assert.deepEqual(pollParams, [101]);
    assert.doesNotMatch(pollQuery, /\b(password_hash|face_embedding)\b/i);
    assert.doesNotMatch(rawBody, /\b(password_hash|face_embedding)\b/i);
});
