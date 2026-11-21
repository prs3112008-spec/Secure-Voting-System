const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const verifyToken = require('../middleware/verifyToken');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ROUTE 1: Register
router.post('/register', async (req, res) => {
    try {
        const { full_name, email, mobile_no, password } = req.body;
        if (!full_name || !email || !mobile_no || !password) {
            return res.status(400).json({ error: 'All fields are required.' });
        }

        const userExists = await pool.query('SELECT * FROM users WHERE email = $1 OR mobile_no = $2', [email, mobile_no]);
        if (userExists.rows.length > 0) return res.status(400).json({ error: 'User already exists.' });

        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            "INSERT INTO users (full_name, email, mobile_no, password_hash, role, is_approved) VALUES ($1, $2, $3, $4, 'voter', FALSE) RETURNING user_id, full_name, email, role, is_approved",
            [full_name, email, mobile_no, password_hash]
        );
        res.status(201).json({
            message: 'Registration successful! Wait for admin approval.',
            user: newUser.rows[0]
        });
    } catch (err) {
        console.error('REGISTER ERROR:', err.message);
        res.status(500).json({ error: 'Server error.' });
    }
});

// ROUTE 2: Login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (user.rows.length === 0) return res.status(401).json({ error: 'Invalid email or password.' });

        const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Invalid email or password.' });

        const token = jwt.sign(
            { user_id: user.rows[0].user_id, role: user.rows[0].role },
            process.env.JWT_SECRET,
            { expiresIn: '2h' }
        );

        res.json({ message: 'Login successful!', token: token, role: user.rows[0].role });
    } catch (err) {
        res.status(500).json({ error: 'Server error during login.' });
    }
});

router.post('/register-face', verifyToken, async (req, res) => {
    const face_embedding = req.body && req.body.face_embedding;
    if (!Array.isArray(face_embedding) || face_embedding.length !== 192 ||
        !face_embedding.every(value => typeof value === 'number' && Number.isFinite(value))) {
        return res.status(400).json({ error: 'face_embedding must be an array of 192 finite numbers.' });
    }

    let client;
    let transactionStarted = false;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        transactionStarted = true;
        await client.query('SELECT pg_advisory_xact_lock(1247112201)');

        const existingUsers = await client.query(
            'SELECT face_embedding FROM users WHERE user_id != $1 AND face_embedding IS NOT NULL',
            [req.user.user_id]
        );
        for (const row of existingUsers.rows) {
            let storedEmbedding = row.face_embedding;
            if (typeof storedEmbedding === 'string') {
                storedEmbedding = JSON.parse(storedEmbedding);
            }
            if (!Array.isArray(storedEmbedding) || storedEmbedding.length !== face_embedding.length ||
                !storedEmbedding.every(value => typeof value === 'number' && Number.isFinite(value))) {
                throw new Error('Stored face embedding is invalid.');
            }

            const squaredDistance = face_embedding.reduce((sum, value, index) => {
                const difference = value - storedEmbedding[index];
                return sum + difference * difference;
            }, 0);
            if (Math.sqrt(squaredDistance) < 0.90) {
                await client.query('ROLLBACK');
                transactionStarted = false;
                return res.status(409).json({ error: 'This face is already registered to another voter account.' });
            }
        }

        const result = await client.query(
            'UPDATE users SET face_embedding = $1 WHERE user_id = $2',
            [JSON.stringify(face_embedding), req.user.user_id]
        );
        if (result.rowCount === 0) {
            await client.query('ROLLBACK');
            transactionStarted = false;
            return res.status(404).json({ error: 'User not found.' });
        }

        await client.query('COMMIT');
        transactionStarted = false;
        res.status(200).json({ message: 'Face registered successfully!' });
    } catch (err) {
        if (client && transactionStarted) {
            try {
                await client.query('ROLLBACK');
            } catch (rollbackErr) {
                console.error('Error rolling back face registration:', rollbackErr.message);
            }
        }
        console.error('Error registering face:', err.message);
        res.status(500).json({ error: 'Server error registering face.' });
    } finally {
        if (client) client.release();
    }
});

router.get('/face-embedding', verifyToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT face_embedding FROM users WHERE user_id = $1',
            [req.user.user_id]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'User not found.' });

        res.status(200).json({ face_embedding: result.rows[0].face_embedding });
    } catch (err) {
        console.error('Error retrieving face embedding:', err.message);
        res.status(500).json({ error: 'Server error retrieving face embedding.' });
    }
});

module.exports = router;