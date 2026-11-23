const express = require('express');
const crypto = require('crypto');
const sharedPool = require('../db/pool');
const verifyToken = require('../middleware/verifyToken');
const verifyAdmin = require('../middleware/verifyAdmin');
const rateLimiters = require('../middleware/rateLimits');
const { logAdminAction } = require('../utils/auditLog');
const { buildVoteHashInput, generateHash, verifyVoteChain } = require('../utils/voteChain');
const validate = require('../middleware/validate');
const {
    pollIdParamsSchema,
    receiptHashParamsSchema,
    scheduleSchema,
    voteSchema
} = require('../middleware/schemas');
const logError = require('../utils/logError');
const {
    consumeVerificationToken,
    verifyVerificationToken
} = require('../utils/verificationToken');

function requireVoter(req, res, next) {
    if (req.user.role !== 'voter') {
        return res.status(403).json({ error: 'Administrators are not permitted to cast votes' });
    }
    next();
}

function createVotesRouter(pool = sharedPool) {
const router = express.Router();

// ROUTE: Cast a vote (Protected - Voters Only)
router.post('/cast', verifyToken, requireVoter, rateLimiters.voter, validate(voteSchema), async (req, res, next) => {
    let client;
    let transactionOpen = false;

    try {
        const { poll_id, candidate_id, verification_token } = req.body;
        const user_id = req.user.user_id;
        if (!verifyVerificationToken(verification_token, user_id)) {
            return res.status(403).json({ error: 'A valid face verification token is required.' });
        }

        client = await pool.connect();
        await client.query('BEGIN');
        transactionOpen = true;
        await client.query('SELECT pg_advisory_xact_lock(1247112202)');

        const pollCheck = await client.query(
            'SELECT start_time, end_time, is_active FROM polls WHERE poll_id = $1',
            [poll_id]
        );

        if (pollCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Poll not found.' });
        }

        const candidateCheck = await client.query(
            'SELECT 1 FROM candidates WHERE candidate_id = $1 AND poll_id = $2',
            [candidate_id, poll_id]
        );
        if (candidateCheck.rows.length === 0) {
            return res.status(400).json({ error: 'Candidate does not belong to this poll.' });
        }

        const poll = pollCheck.rows[0];
        const now = new Date();
        const start = new Date(poll.start_time);
        const end = new Date(poll.end_time);
        if (
            !poll.is_active ||
            Number.isNaN(start.getTime()) ||
            Number.isNaN(end.getTime()) ||
            now < start ||
            now > end
        ) {
            return res.status(403).json({ error: 'Voting is currently closed for this election.' });
        }

        const userCheck = await client.query(
            'SELECT role, is_approved FROM users WHERE user_id = $1',
            [user_id]
        );

        if (userCheck.rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const { role, is_approved } = userCheck.rows[0];

        if (role !== 'voter') {
            return res.status(403).json({ error: 'Administrators are not permitted to cast votes' });
        }

        if (!is_approved) {
            return res.status(403).json({ error: 'Your account is pending admin approval.' });
        }

        // 1. THE DOUBLE-VOTE GUARD
        const existingTurnout = await client.query(
            'SELECT 1 FROM voter_turnout WHERE poll_id = $1 AND voter_id = $2',
            [poll_id, user_id]
        );

        if (existingTurnout.rows.length > 0) {
            return res.status(409).json({ error: 'You have already voted in this poll' });
        }

        // 2. BLOCKCHAIN LOGIC: Fetch the previous hash
        const lastVote = await client.query(
            'SELECT current_hash FROM votes ORDER BY vote_id DESC LIMIT 1'
        );
        
        // If this is the very first vote ever, we use '0' as the Genesis Hash
        const previous_hash = lastVote.rows.length > 0 ? lastVote.rows[0].current_hash : '0';

        // 3. BLOCKCHAIN LOGIC: Hash the persisted vote data so it can be verified later
        const ballot_nonce = crypto.randomBytes(32).toString('hex');
        const current_hash = generateHash(buildVoteHashInput({
            poll_id,
            candidate_id,
            ballot_nonce,
            previous_hash
        }));

        if (!consumeVerificationToken(verification_token, user_id)) {
            return res.status(403).json({ error: 'A valid face verification token is required.' });
        }

        // 4. Record participation separately from the anonymous ballot.
        await client.query(
            'INSERT INTO voter_turnout (poll_id, voter_id) VALUES ($1, $2)',
            [poll_id, user_id]
        );
        await client.query(
            'INSERT INTO votes (poll_id, candidate_id, ballot_nonce, previous_hash, current_hash) VALUES ($1, $2, $3, $4, $5)',
            [poll_id, candidate_id, ballot_nonce, previous_hash, current_hash]
        );
        await client.query('COMMIT');
        transactionOpen = false;

        res.status(201).json({ 
            message: 'Vote cast successfully with blockchain security!',
            hash: current_hash,
            current_hash: current_hash,
            receipt_hash: current_hash
        });
    } catch (err) {
        if (transactionOpen) {
            try {
                await client.query('ROLLBACK');
                transactionOpen = false;
            } catch (rollbackErr) {
                logError('Vote casting rollback failed', rollbackErr);
            }
        }

        if (err.code === '23505') {
            return res.status(409).json({ error: 'You have already voted in this poll' });
        }
        next(err);
    } finally {
        if (transactionOpen) {
            try {
                await client.query('ROLLBACK');
            } catch (rollbackErr) {
                logError('Vote casting rollback failed', rollbackErr);
            }
        }
        if (client) client.release();
    }
});

// ROUTE: Publicly verify a vote receipt without disclosing ballot details
router.get('/verify/:hash', rateLimiters.public, validate(receiptHashParamsSchema, 'params'), async (req, res, next) => {
    try {
        const result = await pool.query(
            'SELECT vote_id, poll_id, candidate_id, ballot_nonce, previous_hash, current_hash, vote_timestamp FROM votes WHERE current_hash = $1',
            [req.params.hash]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                verified: false,
                message: 'Receipt hash not found in the ledger.'
            });
        }

        const vote = result.rows[0];
        const previousVote = await pool.query(
            'SELECT * FROM votes WHERE vote_id < $1 ORDER BY vote_id DESC LIMIT 1',
            [vote.vote_id]
        );
        const expectedPreviousHash = previousVote.rows.length > 0
            ? previousVote.rows[0].current_hash
            : '0';
        const recalculatedHash = generateHash(buildVoteHashInput(vote));
        const intact = vote.previous_hash === expectedPreviousHash &&
            recalculatedHash === vote.current_hash;

        res.json({
            verified: true,
            intact,
            timestamp: vote.vote_timestamp,
            block_index: vote.vote_id
        });
    } catch (err) {
        next(err);
    }
});

// ROUTE: Get the scheduled status of a poll
router.get('/election-status/:poll_id', rateLimiters.public, validate(pollIdParamsSchema, 'params'), async (req, res, next) => {
    try {
        const { poll_id } = req.params;
        const result = await pool.query(
            'SELECT poll_id, start_time, end_time, is_active FROM polls WHERE poll_id = $1',
            [poll_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Poll not found' });
        }

        const poll = result.rows[0];
        const now = new Date();
        const start = new Date(poll.start_time);
        const end = new Date(poll.end_time);

        let status = 'LIVE';
        if (!poll.is_active) {
            status = 'CLOSED';
        } else if (now < start) {
            status = 'UPCOMING';
        } else if (now > end) {
            status = 'CLOSED';
        }

        res.json({
            poll_id: poll.poll_id,
            status,
            is_active: poll.is_active,
            start_time: poll.start_time,
            end_time: poll.end_time,
            server_time_utc: now.toISOString()
        });
    } catch (err) {
        next(err);
    }
});

// ROUTE: Update an election schedule (Admin only)
router.post('/update-schedule', verifyToken, verifyAdmin, rateLimiters.admin, validate(scheduleSchema), async (req, res, next) => {
    try {
        const { poll_id, start_time, end_time, is_active } = req.body;

        const pollStatus = await pool.query(
            'SELECT is_active FROM polls WHERE poll_id = $1',
            [poll_id]
        );
        if (pollStatus.rows.length === 0) {
            return res.status(404).json({ error: 'Poll not found' });
        }

        const result = await pool.query(
            'UPDATE polls SET start_time = $1, end_time = $2, is_active = $3 WHERE poll_id = $4 RETURNING poll_id',
            [start_time, end_time, is_active, poll_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Poll not found' });
        }

        if (pollStatus.rows[0].is_active !== is_active) {
            await logAdminAction(req.user, 'TOGGLE_ELECTION', JSON.stringify({
                poll_id,
                is_active
            }));
        }
        await logAdminAction(req.user, 'UPDATE_SCHEDULE', JSON.stringify({
            poll_id,
            start_time,
            end_time,
            is_active
        }));

        res.json({ message: 'Election schedule updated successfully!' });
    } catch (err) {
        next(err);
    }
});

// ROUTE: Verify the integrity of the vote chain
router.get('/verify-chain', verifyToken, verifyAdmin, rateLimiters.admin, async (req, res, next) => {
    try {
        const chainStatus = await verifyVoteChain(pool);
        delete chainStatus.verified_blocks;
        res.json(chainStatus);
    } catch (err) {
        next(err);
    }
});

// ROUTE: Check if the logged-in user has already voted in a poll
router.get('/status/:poll_id', verifyToken, rateLimiters.voter, validate(pollIdParamsSchema, 'params'), async (req, res, next) => {
    try {
        const { poll_id } = req.params;
        const user_id = req.user.user_id; // Extracted securely from JWT

        // Update the query to also grab the current_hash
        const existingTurnout = await pool.query(
            'SELECT 1 FROM voter_turnout WHERE poll_id = $1 AND voter_id = $2',
            [poll_id, user_id]
        );

        res.json({ hasVoted: existingTurnout.rows.length > 0 });
    } catch (err) {
        next(err);
    }
});

return router;
}

const router = createVotesRouter();
router.createVotesRouter = createVotesRouter;

module.exports = router;