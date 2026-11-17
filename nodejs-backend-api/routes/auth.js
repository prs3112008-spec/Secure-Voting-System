const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ROUTE 1: Register
router.post('/register', async (req, res) => {
    try {
        const { full_name, email, mobile_no, password } = req.body;
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1 OR mobile_no = $2', [email, mobile_no]);
        if (userExists.rows.length > 0) return res.status(400).json({ error: 'User already exists.' });

        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            'INSERT INTO users (full_name, email, mobile_no, password_hash) VALUES ($1, $2, $3, $4) RETURNING user_id, full_name, email, role',
            [full_name, email, mobile_no, password_hash]
        );
        res.status(201).json({ message: 'User registered!', user: newUser.rows[0] });
    } catch (err) {
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

module.exports = router;