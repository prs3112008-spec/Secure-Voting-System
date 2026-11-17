const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const crypto = require('crypto'); // Node's built-in cryptography library
const verifyToken = require('../middleware/verifyToken');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Helper function to create a secure SHA-256 hash
const generateHash = (data) => {
    return crypto.createHash('sha256').update(data).digest('hex');
};

// ROUTE: Cast a vote (Protected - Any Logged-in User)
router.post('/cast', verifyToken, async (req, res) => {
    try {
        const { poll_id, candidate_id } = req.body;
        const user_id = req.user.user_id; 

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

        // 3. BLOCKCHAIN LOGIC: Generate the new hash based on the previous vote and current data
        const voteDataString = `${previous_hash}-${poll_id}-${candidate_id}-${user_id}-${Date.now()}`;
        const current_hash = generateHash(voteDataString);

        // 4. RECORD THE SECURE VOTE
        await pool.query(
            'INSERT INTO votes (poll_id, candidate_id, voter_id, previous_hash, current_hash) VALUES ($1, $2, $3, $4, $5)',
            [poll_id, candidate_id, user_id, previous_hash, current_hash]
        );

        res.status(201).json({ 
            message: 'Vote cast successfully with blockchain security!',
            hash: current_hash
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error casting vote.' });
    }
});

module.exports = router;