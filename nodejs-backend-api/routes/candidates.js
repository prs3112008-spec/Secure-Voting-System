const express = require('express');
const sharedPool = require('../db/pool');
const verifyToken = require('../middleware/verifyToken');
const verifyAdmin = require('../middleware/verifyAdmin');
const rateLimiters = require('../middleware/rateLimits');
const { logAdminAction } = require('../utils/auditLog');
const validate = require('../middleware/validate');
const { candidateIdParamsSchema, candidateSchema, pollIdParamsSchema } = require('../middleware/schemas');
const logError = require('../utils/logError');
const { uploadCandidatePhoto } = require('../utils/cloudinary');

function createCandidatesRouter(pool = sharedPool, logAction = logAdminAction, uploadPhoto = uploadCandidatePhoto) {
const router = express.Router();

// ROUTE 1: Add a new candidate to a poll (Protected - Admins Only)
router.post(['/add', '/add-candidate'], verifyToken, verifyAdmin(), rateLimiters.admin, validate(candidateSchema), async (req, res, next) => {
    try {
        const { poll_id, name, party, photo_url } = req.body;
        let storedPhotoUrl;
        try {
            storedPhotoUrl = await uploadPhoto(photo_url);
        } catch (err) {
            logError('Candidate photo upload failed', err);
            return res.status(502).json({ error: 'Failed to upload candidate photo to cloud storage.' });
        }

        const newCandidate = await pool.query(
            'INSERT INTO candidates (poll_id, candidate_name, party, photo_url) VALUES ($1, $2, $3, $4) RETURNING *',
            [poll_id || 1, name, party, storedPhotoUrl]
        );

        const candidate = newCandidate.rows[0];
        await logAction(req.user, 'ADD_CANDIDATE', JSON.stringify({
            candidate_id: candidate.candidate_id,
            candidate_name: candidate.candidate_name,
            poll_id: candidate.poll_id
        }));
        res.status(201).json(candidate);
    } catch (err) {
        next(err);
    }
});

// ROUTE 2: Delete a candidate only when it has no votes (Protected - Admins Only)
router.delete('/:candidate_id', verifyToken, verifyAdmin(), rateLimiters.admin, validate(candidateIdParamsSchema, 'params'), async (req, res, next) => {
    let client;
    let transactionOpen = false;

    try {
        const { candidate_id } = req.params;
        client = await pool.connect();
        await client.query('BEGIN');
        transactionOpen = true;
        const candidate = await client.query(
            'SELECT candidate_id FROM candidates WHERE candidate_id = $1 FOR UPDATE',
            [candidate_id]
        );
        if (candidate.rowCount === 0) {
            await client.query('ROLLBACK');
            transactionOpen = false;
            return res.status(404).json({ error: 'Candidate not found.' });
        }

        const votes = await client.query(
            'SELECT COUNT(*) AS vote_count FROM votes WHERE candidate_id = $1',
            [candidate_id]
        );
        if (Number(votes.rows[0].vote_count) > 0) {
            await client.query('ROLLBACK');
            transactionOpen = false;
            return res.status(409).json({ error: 'Cannot delete candidate with existing votes' });
        }

        await client.query('DELETE FROM candidates WHERE candidate_id = $1', [candidate_id]);
        await client.query('COMMIT');
        transactionOpen = false;

        await logAction(req.user, 'DELETE_CANDIDATE', JSON.stringify({ candidate_id }));
        res.json({ message: 'Candidate deleted successfully!' });
    } catch (err) {
        if (client && transactionOpen) {
            try {
                await client.query('ROLLBACK');
                transactionOpen = false;
            } catch (rollbackErr) {
                logError('Candidate deletion rollback failed', rollbackErr);
            }
        }
        next(err);
    } finally {
        if (client) {
            if (transactionOpen) {
                try {
                    await client.query('ROLLBACK');
                } catch (rollbackErr) {
                    logError('Candidate deletion rollback failed', rollbackErr);
                }
            }
            client.release();
        }
    }
});

// ROUTE 3: Get all candidates for a specific poll (Protected - Any Logged-in Voter)
router.get(
    '/:poll_id',
    verifyToken,
    verifyAdmin.checkSubAdminPermission('can_view_results'),
    rateLimiters.voter,
    validate(pollIdParamsSchema, 'params'),
    async (req, res, next) => {
    try {
        const { poll_id } = req.params;

        // Updated SQL query: Joins the votes table and counts them!
        const query = `
            SELECT c.*, CAST(COUNT(v.vote_id) AS INTEGER) AS votes
            FROM candidates c
            LEFT JOIN votes v ON c.candidate_id = v.candidate_id
            WHERE c.poll_id = $1
            GROUP BY c.candidate_id
            ORDER BY c.candidate_id ASC
        `;

        const candidates = await pool.query(query, [poll_id]);
        res.json(candidates.rows);
    } catch (err) {
        next(err);
    }
    }
);

return router;
}

const router = createCandidatesRouter();
router.createCandidatesRouter = createCandidatesRouter;

module.exports = router;