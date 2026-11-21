const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const verifyToken = require('../middleware/verifyToken');
const verifyAdmin = require('../middleware/verifyAdmin');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ROUTE 1: Add a new candidate to a poll (Protected - Admins Only)
router.post(['/add', '/add-candidate'], verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { poll_id, name, candidate_name, party, photo_url } = req.body;
        const finalName = candidate_name || name;
        
        const newCandidate = await pool.query(
            'INSERT INTO candidates (poll_id, candidate_name, party, photo_url) VALUES ($1, $2, $3, $4) RETURNING *',
            [poll_id || 1, finalName, party || 'Independent', photo_url || '']
        );

        res.status(201).json(newCandidate.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error adding candidate.' });
    }
});

// ROUTE 2: Delete a candidate and their votes (Protected - Admins Only)
router.delete('/:candidate_id', verifyToken, verifyAdmin, async (req, res) => {
    let client;

    try {
        const { candidate_id } = req.params;
        client = await pool.connect();
        await client.query('BEGIN');
        await client.query('DELETE FROM votes WHERE candidate_id = $1', [candidate_id]);
        await client.query('DELETE FROM candidates WHERE candidate_id = $1', [candidate_id]);
        await client.query('COMMIT');

        res.json({ message: 'Candidate deleted successfully!' });
    } catch (err) {
        if (client) {
            try {
                await client.query('ROLLBACK');
            } catch (rollbackErr) {
                console.error('ROLLBACK CANDIDATE ERROR:', rollbackErr.message);
            }
        }
        console.error('DELETE CANDIDATE ERROR:', err.message);
        res.status(500).json({ error: 'Failed to delete candidate' });
    } finally {
        if (client) {
            client.release();
        }
    }
});

// ROUTE 3: Get all candidates for a specific poll (Protected - Any Logged-in Voter)
router.get('/:poll_id', verifyToken, async (req, res) => {
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
        console.error(err.message);
        res.status(500).json({ error: 'Server error fetching candidates.' });
    }
});

module.exports = router;