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
router.post('/add', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { poll_id, candidate_name } = req.body;
        
        const newCandidate = await pool.query(
            'INSERT INTO candidates (poll_id, candidate_name) VALUES ($1, $2) RETURNING *',
            [poll_id, candidate_name]
        );

        res.status(201).json({ message: 'Candidate added successfully!', candidate: newCandidate.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error adding candidate.' });
    }
});

// ROUTE 2: Get all candidates for a specific poll (Protected - Any Logged-in Voter)
router.get('/:poll_id', verifyToken, async (req, res) => {
    try {
        const { poll_id } = req.params;
        const candidates = await pool.query('SELECT * FROM candidates WHERE poll_id = $1', [poll_id]);
        res.json(candidates.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error fetching candidates.' });
    }
});

module.exports = router;