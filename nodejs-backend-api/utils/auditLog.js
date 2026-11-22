const { Pool } = require('pg');
const logError = require('./logError');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const initializeAuditLogs = () => pool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER NOT NULL,
        admin_email TEXT NOT NULL,
        action TEXT NOT NULL,
        target_details TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
`);

async function logAdminAction(adminUser, action, targetDetails) {
    try {
        const adminId = adminUser.user_id;
        const adminResult = adminUser.email
            ? null
            : await pool.query('SELECT email FROM users WHERE user_id = $1', [adminId]);
        const adminEmail = adminUser.email || (adminResult.rows[0] && adminResult.rows[0].email);

        await pool.query(
            'INSERT INTO audit_logs (admin_id, admin_email, action, target_details) VALUES ($1, $2, $3, $4)',
            [adminId, adminEmail, action, targetDetails]
        );
    } catch (err) {
        logError('Admin audit logging failed', err);
    }
}

const getLatestAuditLogs = () => pool.query(
    'SELECT id, admin_id, admin_email, action, target_details, created_at FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 50'
);

module.exports = { initializeAuditLogs, logAdminAction, getLatestAuditLogs };
