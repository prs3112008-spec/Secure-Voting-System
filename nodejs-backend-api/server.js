require('dotenv').config();
require('./utils/requiredEnv')();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const pool = require('./db/pool');
const { initializeAuditLogs, logAdminAction, getLatestAuditLogs } = require('./utils/auditLog');
const { verifyVoteChain } = require('./utils/voteChain');
const logError = require('./utils/logError');
const { errorHandler, notFound } = require('./middleware/errorHandler');

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use((req, res, next) => {
    console.log(`${req.method} request`);
    next();
});
app.use('/api/auth', require('./routes/auth'));
app.use('/api/polls', require('./routes/polls'));
app.use('/api/candidates', require('./routes/candidates'));
app.use('/api/votes', require('./routes/votes'));

// Test the connection
pool.connect((err, client, release) => {
    if (err) {
        return logError('Initial database connection failed', err);
    }
    console.log('Successfully connected to the Secure Voting Database!');
    release();
});

const verifyToken = require('./middleware/verifyToken');
const verifyAdmin = require('./middleware/verifyAdmin');
const rateLimiters = require('./middleware/rateLimits');
const validate = require('./middleware/validate');
const {
    optionalPollIdParamsSchema,
    voterApprovalSchema,
    voterIdParamsSchema
} = require('./middleware/schemas');

// GET all voters for the Admin Dashboard
app.get('/api/admin/voters', verifyToken, verifyAdmin, rateLimiters.admin, async (req, res, next) => {
    try {
        const result = await pool.query(
            "SELECT user_id, full_name, email, is_approved FROM users WHERE role IS DISTINCT FROM 'admin' ORDER BY created_at DESC"
        );
        res.json(result.rows);
    } catch (err) {
        next(err);
    }
});

// PUT toggle a voter's approval status
app.put('/api/admin/voters/:id/approve', verifyToken, verifyAdmin, rateLimiters.admin, validate(voterIdParamsSchema, 'params'), validate(voterApprovalSchema), async (req, res, next) => {
    const { id } = req.params;
    const { is_approved } = req.body;

    try {
        const result = await pool.query(
            'UPDATE users SET is_approved = $1 WHERE user_id = $2 RETURNING user_id, full_name, is_approved',
            [is_approved, id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Voter not found.' });
        }
        await logAdminAction(
            req.user,
            is_approved ? 'APPROVE_VOTER' : 'REVOKE_VOTER',
            JSON.stringify({ voter_id: result.rows[0].user_id, is_approved })
        );
        res.json({ message: 'Voter approval updated.', voter: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

app.get('/api/admin/audit-logs', verifyToken, verifyAdmin, rateLimiters.admin, async (req, res, next) => {
    try {
        const result = await getLatestAuditLogs();
        res.json(result.rows);
    } catch (err) {
        next(err);
    }
});

app.get(['/api/admin/export-results', '/api/admin/export-results/:poll_id'], verifyToken, verifyAdmin, rateLimiters.admin, validate(optionalPollIdParamsSchema, 'params'), async (req, res, next) => {
    try {
        const pollId = req.params.poll_id || '1';
        const pollResult = await pool.query(
            'SELECT poll_id, title, is_active, start_time, end_time FROM polls WHERE poll_id = $1',
            [pollId]
        );
        if (pollResult.rows.length === 0) {
            return res.status(404).json({ error: 'Poll not found.' });
        }

        const poll = pollResult.rows[0];
        const [turnoutResult, candidateResult, chainStatus] = await Promise.all([
            pool.query(`
                SELECT
                    (SELECT COUNT(*) FROM votes WHERE poll_id = $1) AS total_votes_cast,
                    (SELECT COUNT(*) FROM users WHERE role IS DISTINCT FROM 'admin' AND is_approved IS TRUE) AS approved_voters
            `, [pollId]),
            pool.query(`
                SELECT c.candidate_name, c.party, COUNT(v.vote_id) AS votes
                FROM candidates c
                LEFT JOIN votes v ON v.candidate_id = c.candidate_id AND v.poll_id = c.poll_id
                WHERE c.poll_id = $1
                GROUP BY c.candidate_id, c.candidate_name, c.party
                ORDER BY COUNT(v.vote_id) DESC, c.candidate_id ASC
            `, [pollId]),
            verifyVoteChain(pool)
        ]);

        const totalVotesCast = Number(turnoutResult.rows[0].total_votes_cast);
        const approvedVoters = Number(turnoutResult.rows[0].approved_voters);
        const turnoutPercentage = approvedVoters === 0
            ? 0
            : Math.round((totalVotesCast / approvedVoters) * 1000) / 10;
        const exportTimestamp = new Date().toISOString();
        const csvRows = [
            ['Election Metadata'],
            ['Poll ID', poll.poll_id],
            ['Poll Title', poll.title],
            ['Active', poll.is_active],
            ['Start Time', poll.start_time],
            ['End Time', poll.end_time],
            ['Export Timestamp (UTC)', exportTimestamp],
            [],
            ['Voter Turnout'],
            ['Total Votes Cast', totalVotesCast],
            ['Approved Voters', approvedVoters],
            ['Turnout Percentage', turnoutPercentage],
            [],
            ['Chain Verification'],
            ['Status', chainStatus.valid ? 'INTACT' : 'COMPROMISED'],
            ['Total Blocks', chainStatus.total_votes],
            ['Total Blocks Verified', chainStatus.verified_blocks],
            [],
            ['Candidate Name', 'Party', 'Votes', 'Vote Share %']
        ];

        for (const candidate of candidateResult.rows) {
            const votes = Number(candidate.votes);
            const voteShare = totalVotesCast === 0
                ? 0
                : Math.round((votes / totalVotesCast) * 1000) / 10;
            csvRows.push([candidate.candidate_name, candidate.party, votes, voteShare]);
        }

        const csvEscape = value => `"${String(value === null || value === undefined ? '' : value).replace(/"/g, '""')}"`;
        const csv = csvRows.map(row => row.map(csvEscape).join(',')).join('\r\n');
        const filenamePollId = String(poll.poll_id).replace(/[^a-zA-Z0-9_-]/g, '_');

        await logAdminAction(req.user, 'EXPORT_RESULTS', JSON.stringify({
            poll_id: poll.poll_id,
            title: poll.title
        }));

        res.set('Content-Type', 'text/csv; charset=utf-8');
        res.set('Content-Disposition', `attachment; filename="election-report-poll-${filenamePollId}.csv"`);
        res.send(csv);
    } catch (err) {
        next(err);
    }
});

app.get('/', (req, res) => {
    res.send('Secure Voting API is running!');
});

const PORT = process.env.PORT || 5000;

app.use(notFound);
app.use(errorHandler);

initializeAuditLogs()
    .then(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)))
    .catch(err => {
        logError('Audit log table initialization failed', err);
        process.exit(1);
    });