const express = require('express');
const sharedPool = require('../db/pool');
const verifyToken = require('../middleware/verifyToken');
const verifyAdmin = require('../middleware/verifyAdmin');
const rateLimiters = require('../middleware/rateLimits');
const { logAdminAction } = require('../utils/auditLog');
const validate = require('../middleware/validate');
const { pollCreateSchema, pollIdParamsSchema } = require('../middleware/schemas');

function createPollsRouter(pool = sharedPool, logAction = logAdminAction) {
const router = express.Router();

// ROUTE 1: Get all polls (Protected Route - Requires Token)
router.get('/', verifyToken, rateLimiters.voter, async (req, res, next) => {
    try {
        const allPolls = await pool.query(`
            SELECT
                p.poll_id,
                p.title,
                p.description,
                p.start_time,
                p.end_time,
                COALESCE(p.is_active, TRUE) AS is_active,
                COALESCE(p.is_private, FALSE) AS is_private,
                COUNT(DISTINCT c.candidate_id)::int AS candidate_count,
                EXISTS (
                    SELECT 1 FROM voter_turnout vt
                    WHERE vt.poll_id = p.poll_id AND vt.voter_id = $1
                ) AS has_voted
            FROM polls p
            LEFT JOIN candidates c ON c.poll_id = p.poll_id
            GROUP BY p.poll_id
            ORDER BY p.poll_id DESC
        `, [req.user.user_id]);
        const now = new Date();
        res.json(allPolls.rows.map(poll => {
            const startTime = new Date(poll.start_time);
            const endTime = new Date(poll.end_time);
            const status = !poll.is_active || now > endTime
                ? 'CLOSED'
                : now < startTime
                    ? 'UPCOMING'
                    : 'LIVE';
            return { ...poll, status };
        }));
    } catch (err) {
        next(err);
    }
});

// ROUTE 2: Create a new poll (Protected - Requires Token)
router.post('/create', verifyToken, verifyAdmin, rateLimiters.admin, validate(pollCreateSchema), async (req, res, next) => {
    try {
        const { title, description, start_time, end_time, is_private, security_code } = req.body;
        
        const newPoll = await pool.query(
            'INSERT INTO polls (title, description, start_time, end_time, is_active, is_private, security_code, created_by) VALUES ($1, $2, $3, $4, TRUE, COALESCE($5, FALSE), $6, $7) RETURNING poll_id, title, description, start_time, end_time, is_private, created_by, is_active',
            [title, description, start_time, end_time, is_private, security_code, req.user.user_id] // Notice req.user.user_id comes securely from the token!
        );

        await logAction(req.user, 'CREATE_POLL', JSON.stringify({
            poll_id: newPoll.rows[0].poll_id,
            title: newPoll.rows[0].title
        }));
        res.status(201).json({ message: 'Poll created successfully!', poll: newPoll.rows[0] });
    } catch (err) {
        next(err);
    }
});

// ROUTE: Get live results for a specific poll (Public or Protected)
router.get('/:poll_id/results', rateLimiters.public, validate(pollIdParamsSchema, 'params'), async (req, res, next) => {
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
                    (SELECT COUNT(*) FROM voter_turnout WHERE poll_id = $1) AS total_votes_cast,
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
        next(err);
    }
});

return router;
}

const router = createPollsRouter();
router.createPollsRouter = createPollsRouter;

module.exports = router;
