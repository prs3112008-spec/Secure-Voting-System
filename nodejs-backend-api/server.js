require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const { initializeAuditLogs, logAdminAction, getLatestAuditLogs } = require('./utils/auditLog');

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});
app.use('/api/auth', require('./routes/auth'));
app.use('/api/polls', require('./routes/polls'));
app.use('/api/candidates', require('./routes/candidates'));
app.use('/api/votes', require('./routes/votes'));

// Connect to Supabase
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Test the connection
pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error acquiring client', err.stack);
    }
    console.log('Successfully connected to the Secure Voting Database!');
    release();
});

const verifyToken = require('./middleware/verifyToken');
const verifyAdmin = require('./middleware/verifyAdmin');

// GET all voters for the Admin Dashboard
app.get('/api/admin/voters', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT user_id, full_name, email, is_approved FROM users WHERE role = 'voter' ORDER BY created_at DESC"
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to load voters.' });
    }
});

// PUT toggle a voter's approval status
app.put('/api/admin/voters/:id/approve', verifyToken, verifyAdmin, async (req, res) => {
    const { id } = req.params;
    const { is_approved } = req.body;

    if (typeof is_approved !== 'boolean') {
        return res.status(400).json({ error: 'is_approved must be a boolean.' });
    }

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
        console.error(err);
        res.status(500).json({ error: 'Failed to update voter approval.' });
    }
});

app.get('/api/admin/audit-logs', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const result = await getLatestAuditLogs();
        res.json(result.rows);
    } catch (err) {
        console.error('LOAD AUDIT LOGS ERROR:', err);
        res.status(500).json({ error: 'Failed to load audit logs.' });
    }
});

// A simple test route
app.get('/', (req, res) => {
    res.send('Secure Voting API is running!');
});

const PORT = process.env.PORT || 5000;
// Test the connection
pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error acquiring client', err.stack);
    }
    console.log('Successfully connected to the Secure Voting Database!');
    release();
});

// A simple test route
app.get('/', (req, res) => {
    res.send('Secure Voting API is running!');
});

initializeAuditLogs()
    .then(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)))
    .catch(err => {
        console.error('AUDIT LOG TABLE INITIALIZATION ERROR:', err);
        process.exit(1);
    });