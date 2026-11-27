const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const votesRouter = require('../routes/votes');
const { issueVerificationToken } = require('../utils/verificationToken');

function useTestSecret(t) {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });
}

async function startTestServer(t) {
    let databaseCalls = 0;
    const fakePool = {
        async connect() {
            databaseCalls += 1;
            throw new Error('Database must not be accessed by an invalid token.');
        },
        async query() {
            databaseCalls += 1;
            throw new Error('Database must not be accessed by an invalid token.');
        }
    };

    const app = express();
    app.use(express.json());
    app.use('/api/votes', votesRouter.createVotesRouter(fakePool));
    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
    });
    t.after(() => new Promise((resolve, reject) => {
        server.close(err => err ? reject(err) : resolve());
    }));

    return {
        databaseCalls: () => databaseCalls,
        url: `http://127.0.0.1:${server.address().port}/api/votes/cast`
    };
}

test('a verification token issued to another voter cannot be replayed', async t => {
    useTestSecret(t);
    const server = await startTestServer(t);
    const voterBJwt = jwt.sign(
        { user_id: 102, role: 'voter' },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
    const voterAVerificationToken = issueVerificationToken(101);

    const response = await fetch(server.url, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${voterBJwt}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            poll_id: 999,
            candidate_id: 999,
            verification_token: voterAVerificationToken
        })
    });

    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), {
        error: 'A valid face verification token is required.'
    });
    assert.equal(server.databaseCalls(), 0);
});

test('a JWT signed with the wrong secret is rejected', async t => {
    useTestSecret(t);
    const server = await startTestServer(t);
    const forgedJwt = jwt.sign(
        { user_id: 101, role: 'admin' },
        'attacker_wrong_secret',
        { expiresIn: '1h' }
    );

    const response = await fetch(server.url, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${forgedJwt}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            poll_id: 999,
            candidate_id: 999,
            verification_token: 'fake.token.value'
        })
    });

    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: 'Invalid Token.' });
    assert.equal(server.databaseCalls(), 0);
});
