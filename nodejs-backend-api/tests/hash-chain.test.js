const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const votesRouter = require('../routes/votes');
const { buildVoteHashInput, generateHash } = require('../utils/voteChain');

async function listen(t, app) {
    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
    });
    t.after(() => new Promise((resolve, reject) => {
        server.close(err => err ? reject(err) : resolve());
    }));
    return `http://127.0.0.1:${server.address().port}`;
}

test('admin chain verification detects a modified ballot payload', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    const firstVote = {
        vote_id: 1,
        poll_id: 2,
        candidate_id: 10,
        ballot_nonce: 'nonce-1',
        previous_hash: '0'
    };
    firstVote.current_hash = generateHash(buildVoteHashInput(firstVote));

    const secondVote = {
        vote_id: 2,
        poll_id: 2,
        candidate_id: 10,
        ballot_nonce: 'nonce-2',
        previous_hash: firstVote.current_hash
    };
    secondVote.current_hash = generateHash(buildVoteHashInput(secondVote));

    const thirdVote = {
        vote_id: 3,
        poll_id: 2,
        candidate_id: 11,
        ballot_nonce: 'nonce-3',
        previous_hash: secondVote.current_hash
    };
    thirdVote.current_hash = generateHash(buildVoteHashInput(thirdVote));

    const tamperedLedger = [
        firstVote,
        { ...secondVote, candidate_id: 99 },
        thirdVote
    ];
    let chainQuery;
    const fakePool = {
        async query(sql) {
            chainQuery = sql;
            return { rows: tamperedLedger };
        }
    };

    const app = express();
    app.use('/api/votes', votesRouter.createVotesRouter(fakePool));
    const baseUrl = await listen(t, app);
    const adminJwt = jwt.sign(
        { user_id: 1, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    const response = await fetch(`${baseUrl}/api/votes/verify-chain`, {
        headers: { Authorization: `Bearer ${adminJwt}` }
    });
    const result = await response.json();

    assert.equal(response.status, 200);
    assert.equal(result.valid, false);
    assert.equal(result.tampered_vote_id, 2);
    assert.match(result.message, /Data tampered at Vote ID #2/);
    assert.equal(chainQuery, 'SELECT vote_id, poll_id, candidate_id, ballot_nonce, previous_hash, current_hash FROM votes ORDER BY vote_id ASC');
});
