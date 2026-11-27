const assert = require('node:assert/strict');
const { test } = require('node:test');
const express = require('express');
const jwt = require('jsonwebtoken');
const votesRouter = require('../routes/votes');
const { issueVerificationToken } = require('../utils/verificationToken');

test('parallel vote requests accept one vote and reject the duplicates', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = 'isolated-vote-race-test-secret';
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    let voteCommitted = false;
    let committedVoteCount = 0;
    let transactionTail = Promise.resolve();

    const fakePool = {
        async connect() {
            let releaseLock;
            let pendingVote = false;
            return {
                async query(sql) {
                    if (sql === 'BEGIN') return { rows: [] };
                    if (sql === 'SELECT pg_advisory_xact_lock(1247112202)') {
                        const previousTransaction = transactionTail;
                        transactionTail = new Promise(resolve => {
                            releaseLock = resolve;
                        });
                        await previousTransaction;
                        return { rows: [] };
                    }
                    if (sql === 'SELECT start_time, end_time, is_active FROM polls WHERE poll_id = $1') {
                        return {
                            rows: [{
                                start_time: new Date(Date.now() - 60_000),
                                end_time: new Date(Date.now() + 60_000),
                                is_active: true
                            }]
                        };
                    }
                    if (sql === 'SELECT 1 FROM candidates WHERE candidate_id = $1 AND poll_id = $2') {
                        return { rows: [{}] };
                    }
                    if (sql === 'SELECT role, is_approved FROM users WHERE user_id = $1') {
                        return { rows: [{ role: 'voter', is_approved: true }] };
                    }
                    if (sql === 'SELECT 1 FROM voter_turnout WHERE poll_id = $1 AND voter_id = $2') {
                        return { rows: voteCommitted ? [{}] : [] };
                    }
                    if (sql === 'SELECT current_hash FROM votes ORDER BY vote_id DESC LIMIT 1') {
                        return { rows: [] };
                    }
                    if (sql === 'INSERT INTO voter_turnout (poll_id, voter_id) VALUES ($1, $2)') {
                        pendingVote = true;
                        return { rows: [] };
                    }
                    if (sql.startsWith('INSERT INTO votes ')) {
                        return { rows: [] };
                    }
                    if (sql === 'COMMIT') {
                        if (pendingVote) {
                            voteCommitted = true;
                            committedVoteCount += 1;
                        }
                        if (releaseLock) {
                            releaseLock();
                            releaseLock = null;
                        }
                        return { rows: [] };
                    }
                    if (sql === 'ROLLBACK') {
                        if (releaseLock) {
                            releaseLock();
                            releaseLock = null;
                        }
                        return { rows: [] };
                    }
                    throw new Error(`Unexpected mock query: ${sql}`);
                },
                release() {
                    if (releaseLock) {
                        releaseLock();
                        releaseLock = null;
                    }
                }
            };
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

    const accessToken = jwt.sign(
        { user_id: 999, role: 'voter' },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
    const verificationToken = issueVerificationToken(999);
    const url = `http://127.0.0.1:${server.address().port}/api/votes/cast`;
    const responses = await Promise.all(
        Array.from({ length: 5 }, () => fetch(url, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                poll_id: 999,
                candidate_id: 999,
                verification_token: verificationToken
            })
        }))
    );

    const statuses = responses.map(response => response.status);
    const accepted = statuses.filter(status => status === 201);
    const rejected = statuses.filter(status => status >= 400 && status < 500);

    assert.equal(accepted.length, 1, `Expected 1 accepted vote, got ${accepted.length}`);
    assert.equal(rejected.length, 4, `Expected 4 rejected requests, got ${rejected.length}`);
    assert.equal(committedVoteCount, 1, 'Expected exactly one vote to be committed');
});
