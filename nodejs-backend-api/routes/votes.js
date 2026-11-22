const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const verifyToken = require('../middleware/verifyToken');
const verifyAdmin = require('../middleware/verifyAdmin');
const rateLimiters = require('../middleware/rateLimits');
const { logAdminAction } = require('../utils/auditLog');
const { generateHash, verifyVoteChain } = require('../utils/voteChain');
const validate = require('../middleware/validate');
const {
    pollIdParamsSchema,
    receiptHashParamsSchema,
    scheduleSchema,
    voteSchema
} = require('../middleware/schemas');
const logError = require('../utils/logError');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ROUTE: Cast a vote (Protected - Any Logged-in User)
router.post('/cast', verifyToken, rateLimiters.voter, validate(voteSchema), async (req, res) => {
    try {
        const { poll_id, candidate_id } = req.body;
        const pollCheck = await pool.query(
            'SELECT start_time, end_time, is_active FROM polls WHERE poll_id = $1',
            [poll_id]
        );

        if (pollCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Poll not found.' });
        }

        const candidateCheck = await pool.query(
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

        const user_id = req.user.user_id;
        const userCheck = await pool.query(
            'SELECT role, is_approved FROM users WHERE user_id = $1',
            [user_id]
        );

        if (userCheck.rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const { role, is_approved } = userCheck.rows[0];

        if (role === 'admin') {
            return res.status(403).json({ error: 'Admins are not permitted to cast votes.' });
        }

        if (!is_approved) {
            return res.status(403).json({ error: 'Your account is pending admin approval.' });
        }

        // 1. THE DOUBLE-VOTE GUARD
        const existingVote = await pool.query(
            'SELECT * FROM votes WHERE poll_id = $1 AND voter_id = $2',
            [poll_id, user_id]
        );

        if (existingVote.rows.length > 0) {
            return res.status(403).json({ error: 'Access Denied. You have already voted in this poll!' });
        }

        // 2. BLOCKCHAIN LOGIC: Fetch the previous hash
        const lastVote = await pool.query(
            'SELECT current_hash FROM votes ORDER BY vote_id DESC LIMIT 1'
        );
        
        // If this is the very first vote ever, we use '0' as the Genesis Hash
        const previous_hash = lastVote.rows.length > 0 ? lastVote.rows[0].current_hash : '0';

        // 3. BLOCKCHAIN LOGIC: Hash the persisted vote data so it can be verified later
        const voteDataString = `${poll_id}-${candidate_id}-${user_id}-${previous_hash}`;
        const current_hash = generateHash(voteDataString);

        // 4. RECORD THE SECURE VOTE
        await pool.query(
            'INSERT INTO votes (poll_id, candidate_id, voter_id, previous_hash, current_hash) VALUES ($1, $2, $3, $4, $5)',
            [poll_id, candidate_id, user_id, previous_hash, current_hash]
        );

        res.status(201).json({ 
            message: 'Vote cast successfully with blockchain security!',
            hash: current_hash,
            current_hash: current_hash
        });
    } catch (err) {
        logError('Vote casting failed', err);
        res.status(500).json({ error: 'Server error casting vote.' });
    }
});

// ROUTE: Publicly verify a vote receipt without disclosing ballot details
router.get('/verify/:hash', rateLimiters.public, validate(receiptHashParamsSchema, 'params'), async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT vote_id, poll_id, candidate_id, voter_id, previous_hash, current_hash, vote_timestamp FROM votes WHERE current_hash = $1',
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
        const voteDataString = `${vote.poll_id}-${vote.candidate_id}-${vote.voter_id}-${vote.previous_hash}`;
        const recalculatedHash = generateHash(voteDataString);
        const intact = vote.previous_hash === expectedPreviousHash &&
            recalculatedHash === vote.current_hash;

        res.json({
            verified: true,
            intact,
            timestamp: vote.vote_timestamp,
            block_index: vote.vote_id
        });
    } catch (err) {
        logError('Vote receipt verification failed', err);
        res.status(500).json({ error: 'Failed to verify vote receipt.' });
    }
});

// ROUTE: Get the scheduled status of a poll
router.get('/election-status/:poll_id', rateLimiters.public, validate(pollIdParamsSchema, 'params'), async (req, res) => {
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
        logError('Election status lookup failed', err);
        res.status(500).json({ error: 'Failed to fetch election status' });
    }
});

// ROUTE: Update an election schedule (Admin only)
router.post('/update-schedule', verifyToken, verifyAdmin, rateLimiters.admin, validate(scheduleSchema), async (req, res) => {
    try {
        const { poll_id, start_time, end_time, is_active } = req.body;
        const start = new Date(start_time);
        const end = new Date(end_time);

        if (
            poll_id === undefined || poll_id === null || poll_id === '' ||
            start_time === undefined || start_time === null || start_time === '' ||
            end_time === undefined || end_time === null || end_time === '' ||
            typeof is_active !== 'boolean' ||
            Number.isNaN(start.getTime()) ||
            Number.isNaN(end.getTime()) ||
            end <= start
        ) {
            return res.status(400).json({
                error: 'poll_id, valid start_time and end_time, and boolean is_active are required.'
            });
        }

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
        logError('Election schedule update failed', err);
        res.status(500).json({ error: 'Failed to update schedule' });
    }
});

// ROUTE: Verify the integrity of the vote chain
router.get('/verify-chain', rateLimiters.public, async (req, res) => {
    try {
        const chainStatus = await verifyVoteChain(pool);
        delete chainStatus.verified_blocks;
        res.json(chainStatus);
    } catch (err) {
        logError('Vote chain verification failed', err);
        res.status(500).json({ error: 'Failed to verify chain integrity.' });
    }
});

// ROUTE: Check if the logged-in user has already voted in a poll
router.get('/status/:poll_id', verifyToken, rateLimiters.voter, validate(pollIdParamsSchema, 'params'), async (req, res) => {
    try {
        const { poll_id } = req.params;
        const user_id = req.user.user_id; // Extracted securely from JWT

        // Update the query to also grab the current_hash
        const existingVote = await pool.query(
            'SELECT candidate_id, current_hash FROM votes WHERE poll_id = $1 AND voter_id = $2',
            [poll_id, user_id]
        );

        if (existingVote.rows.length > 0) {
            // Include the hash in the response!
            res.json({ 
                hasVoted: true, 
                candidate_id: existingVote.rows[0].candidate_id,
                receipt_hash: existingVote.rows[0].current_hash 
            });
        } else {
            res.json({ hasVoted: false });
        }
    } catch (err) {
        logError('Voter status lookup failed', err);
        res.status(500).json({ error: 'Server error checking vote status.' });
    }
});

module.exports = router;