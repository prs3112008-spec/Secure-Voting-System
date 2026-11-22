const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const verifyToken = require('../middleware/verifyToken');
const verifyAdmin = require('../middleware/verifyAdmin');
const rateLimiters = require('../middleware/rateLimits');
const { logAdminAction } = require('../utils/auditLog');
const validate = require('../middleware/validate');
const { pollCreateSchema, pollIdParamsSchema } = require('../middleware/schemas');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ROUTE 1: Get all polls (Protected Route - Requires Token)
router.get('/', verifyToken, rateLimiters.voter, async (req, res) => {
    try {
        const allPolls = await pool.query('SELECT * FROM polls ORDER BY start_time DESC');
        res.json(allPolls.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error fetching polls.' });
    }
});

// ROUTE 2: Create a new poll (Protected - Requires Token)
router.post('/create', verifyToken, verifyAdmin, rateLimiters.admin, validate(pollCreateSchema), async (req, res) => {
    try {
        const { title, description, start_time, end_time, is_private, security_code } = req.body;
        
        const newPoll = await pool.query(
            'INSERT INTO polls (title, description, start_time, end_time, is_private, security_code, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
            [title, description, start_time, end_time, is_private, security_code, req.user.user_id] // Notice req.user.user_id comes securely from the token!
        );

        await logAdminAction(req.user, 'CREATE_POLL', JSON.stringify({
            poll_id: newPoll.rows[0].poll_id,
            title: newPoll.rows[0].title
        }));
        res.status(201).json({ message: 'Poll created successfully!', poll: newPoll.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error creating poll.' });
    }
});

// ROUTE: Get live results for a specific poll (Public or Protected)
router.get('/:poll_id/results', rateLimiters.public, validate(pollIdParamsSchema, 'params'), async (req, res) => {
    try {
        const { poll_id } = req.params;

        const [results, turnoutResult] = await Promise.all([
            pool.query(`
                SELECT c.candidate_id, c.candidate_name, c.party, c.photo_url, COUNT(v.vote_id) as vote_count
                FROM candidates c
                LEFT JOIN votes v ON c.candidate_id = v.candidate_id
                WHERE c.poll_id = $1
                GROUP BY c.candidate_id, c.candidate_name, c.party, c.photo_url
                ORDER BY vote_count DESC;
            `, [poll_id]),
            pool.query(`
                SELECT
                    (SELECT COUNT(*) FROM votes WHERE poll_id = $1) AS total_votes_cast,
                    (SELECT COUNT(*) FROM users WHERE role IS DISTINCT FROM 'admin' AND is_approved IS TRUE) AS approved_voters
            `, [poll_id])
        ]);
        const totalVotesCast = Number(turnoutResult.rows[0].total_votes_cast);
        const approvedVoters = Number(turnoutResult.rows[0].approved_voters);
        const turnoutPercentage = approvedVoters === 0
            ? 0
            : Math.round((totalVotesCast / approvedVoters) * 1000) / 10;

        res.json({
            poll_id: poll_id,
            results: results.rows,
            turnout: {
                total_votes_cast: totalVotesCast,
                approved_voters: approvedVoters,
                turnout_percentage: turnoutPercentage
            }
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error fetching results.' });
    }
});

module.exports = router;