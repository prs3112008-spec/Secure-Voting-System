const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const verifyToken = require('../middleware/verifyToken');
const verifyAdmin = require('../middleware/verifyAdmin');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ROUTE 1: Get all polls (Protected Route - Requires Token)
router.get('/', verifyToken, async (req, res) => {
    try {
        const allPolls = await pool.query('SELECT * FROM polls ORDER BY start_time DESC');
        res.json(allPolls.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error fetching polls.' });
    }
});

// ROUTE 2: Create a new poll (Protected - Requires Token)
router.post('/create', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { title, description, start_time, end_time, is_private, security_code } = req.body;
        
        const newPoll = await pool.query(
            'INSERT INTO polls (title, description, start_time, end_time, is_private, security_code, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
            [title, description, start_time, end_time, is_private, security_code, req.user.user_id] // Notice req.user.user_id comes securely from the token!
        );

        res.status(201).json({ message: 'Poll created successfully!', poll: newPoll.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error creating poll.' });
    }
});

// ROUTE: Get live results for a specific poll (Public or Protected)
router.get('/:poll_id/results', async (req, res) => {
    try {
        const { poll_id } = req.params;

        const results = await pool.query(`
            SELECT c.candidate_id, c.candidate_name, COUNT(v.vote_id) as vote_count
            FROM candidates c
            LEFT JOIN votes v ON c.candidate_id = v.candidate_id
            WHERE c.poll_id = $1
            GROUP BY c.candidate_id, c.candidate_name
            ORDER BY vote_count DESC;
        `, [poll_id]);

        res.json({
            poll_id: poll_id,
            results: results.rows
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error fetching results.' });
    }
});

module.exports = router;