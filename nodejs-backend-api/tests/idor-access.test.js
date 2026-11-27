const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const authRouter = require('../routes/auth');
const votesRouter = require('../routes/votes');

function useTestSecret(t) {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });
}

async function listen(t, app) {
    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
    });
    t.after(() => new Promise((resolve, reject) => {
        server.close(err => err ? reject(err) : resolve());
    }));
    return `http://127.0.0.1:${server.address().port}`;
}

test('vote status is scoped to the authenticated voter, not a supplied user ID', async t => {
    useTestSecret(t);
    const queries = [];
    const fakePool = {
        async query(sql, params) {
            queries.push({ sql, params });
            return { rows: params[1] === 101 ? [{}] : [] };
        }
    };

    const app = express();
    app.use('/api/votes', votesRouter.createVotesRouter(fakePool));
    const baseUrl = await listen(t, app);
    const voterAJwt = jwt.sign(
        { user_id: 101, role: 'voter' },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    const response = await fetch(`${baseUrl}/api/votes/status/9?user_id=102`, {
        headers: { Authorization: `Bearer ${voterAJwt}` }
    });

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { hasVoted: true });
    assert.equal(queries.length, 1);
    assert.deepEqual(queries[0].params, [9, 101]);
    assert.equal(queries[0].sql, 'SELECT 1 FROM voter_turnout WHERE poll_id = $1 AND voter_id = $2');
});

test('face enrollment updates only the user authenticated by the enrollment token', async t => {
    useTestSecret(t);
    const updateCalls = [];
    const fakePool = {
        async connect() {
            return {
                async query(sql, params) {
                    if (sql === 'SELECT face_embedding FROM users WHERE user_id != $1 AND face_embedding IS NOT NULL') {
                        return { rows: [] };
                    }
                    if (sql === 'UPDATE users SET face_embedding = $1 WHERE user_id = $2') {
                        updateCalls.push({ sql, params });
                        return { rowCount: 1, rows: [] };
                    }
                    if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK' ||
                        sql === 'SELECT pg_advisory_xact_lock(1247112201)') {
                        return { rows: [] };
                    }
                    throw new Error(`Unexpected mock query: ${sql}`);
                },
                release() {}
            };
        }
    };

    const app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter.createAuthRouter(fakePool));
    const baseUrl = await listen(t, app);
    const voterAEnrollmentJwt = jwt.sign(
        { user_id: 101, role: 'voter', scope: 'face_enroll' },
        process.env.JWT_SECRET,
        { expiresIn: '10m' }
    );

    const response = await fetch(`${baseUrl}/api/auth/register-face?user_id=102`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${voterAEnrollmentJwt}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ face_embedding: Array(192).fill(0) })
    });

    assert.equal(response.status, 200);
    assert.equal(updateCalls.length, 1);
    assert.equal(updateCalls[0].params[1], 101);
});
