const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const defaultPool = require('../db/pool');
const verifyToken = require('../middleware/verifyToken');
const rateLimiters = require('../middleware/rateLimits');
const { setRateLimitResponse } = rateLimiters;
const validate = require('../middleware/validate');
const { faceEmbeddingSchema, loginSchema, registerSchema } = require('../middleware/schemas');
const logError = require('../utils/logError');
const { euclideanDistance, FACE_MATCH_THRESHOLD, parseStoredEmbedding } = require('../utils/faceEmbedding');
const { issueVerificationToken } = require('../utils/verificationToken');

function createLoginBackoff(config) {
    const accounts = new Map();
    const normalizeEmail = email => typeof email === 'string' ? email.trim().toLowerCase() : '';

    return {
        middleware(req, res, next) {
            const email = normalizeEmail(req.loginAccountEmail || (req.body && req.body.email));
            const account = accounts.get(email);
            if (!account) return next();

            const now = Date.now();
            if (now - account.windowStartedAt >= config.accountFailureWindowMs) {
                accounts.delete(email);
                return next();
            }
            if (account.retryAt > now) {
                return setRateLimitResponse(
                    res,
                    config.accountFailureThreshold,
                    config.accountFailureWindowMs,
                    new Date(account.retryAt)
                );
            }
            next();
        },
        recordFailure(email) {
            const key = normalizeEmail(email);
            if (!key) return;

            const now = Date.now();
            let account = accounts.get(key);
            if (!account || now - account.windowStartedAt >= config.accountFailureWindowMs) {
                account = { windowStartedAt: now, failures: 0, retryAt: 0 };
            }
            account.failures += 1;
            if (account.failures >= config.accountFailureThreshold) {
                const exponent = account.failures - config.accountFailureThreshold;
                const delay = Math.min(
                    config.accountBackoffBaseMs * Math.pow(config.accountBackoffMultiplier, exponent),
                    config.accountBackoffMaxMs
                );
                account.retryAt = now + delay;
            }
            accounts.set(key, account);
        },
        reset(email) {
            accounts.delete(normalizeEmail(email));
        }
    };
}

function createAuthRouter(pool = defaultPool, limits = rateLimiters) {
    const router = express.Router();
    const loginBackoff = createLoginBackoff(limits.config);
    const resolveLoginAccount = async (req, res, next) => {
        try {
            const result = await pool.query(
                'SELECT * FROM users WHERE email = $1 OR mobile_no = $1',
                [req.body.email]
            );
            req.loginUser = result.rows[0] || null;
            req.loginAccountEmail = req.loginUser ? req.loginUser.email : req.body.email;
            next();
        } catch (err) {
            next(err);
        }
    };

    // ROUTE 1: Register
    router.post('/register', limits.registerIp, validate(registerSchema), async (req, res, next) => {
        try {
            const { full_name, email, mobile_no, password } = req.body;

            const userExists = await pool.query('SELECT * FROM users WHERE email = $1 OR mobile_no = $2', [email, mobile_no]);
            if (userExists.rows.length > 0) return res.status(400).json({ error: 'User already exists.' });

            const salt = await bcrypt.genSalt(10);
            const password_hash = await bcrypt.hash(password, salt);

            const newUser = await pool.query(
                "INSERT INTO users (full_name, email, mobile_no, password_hash, role, is_approved) VALUES ($1, $2, $3, $4, 'voter', FALSE) RETURNING user_id, full_name, email, role, is_approved",
                [full_name, email, mobile_no, password_hash]
            );
            const user = newUser.rows[0];
            const enroll_token = jwt.sign(
                { user_id: user.user_id, role: user.role, scope: 'face_enroll' },
                process.env.JWT_SECRET,
                { expiresIn: '10m' }
            );
            res.status(201).json({
                message: 'Registration successful! Wait for admin approval.',
                user,
                enroll_token
            });
        } catch (err) {
            next(err);
        }
    });

    // ROUTE 2: Login
    router.post('/login', limits.loginIp, validate(loginSchema), resolveLoginAccount, loginBackoff.middleware, async (req, res, next) => {
        try {
            const { email, password } = req.body;

            const user = req.loginUser;
            if (!user) {
                loginBackoff.recordFailure(req.loginAccountEmail);
                return res.status(401).json({ error: 'Invalid email or password.' });
            }

            const validPassword = await bcrypt.compare(password, user.password_hash);
            if (!validPassword) {
                loginBackoff.recordFailure(req.loginAccountEmail);
                return res.status(401).json({ error: 'Invalid email or password.' });
            }

            loginBackoff.reset(req.loginAccountEmail);

            if (user.role !== 'admin' && !user.is_approved) {
                return res.status(403).json({ error: 'Your account is pending Admin approval. Please wait for verification.' });
            }

            const token = jwt.sign(
                { user_id: user.user_id, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: '2h' }
            );

            res.json({ message: 'Login successful!', token: token, role: user.role });
        } catch (err) {
            next(err);
        }
    });

    router.post('/register-face', verifyToken.allowFaceEnroll, limits.voter, validate(faceEmbeddingSchema), async (req, res, next) => {
        const { face_embedding } = req.body;

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
                const storedEmbedding = parseStoredEmbedding(row.face_embedding);
                if (euclideanDistance(face_embedding, storedEmbedding) < FACE_MATCH_THRESHOLD) {
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
                    logError('Face registration rollback failed', rollbackErr);
                }
            }
            next(err);
        } finally {
            if (client) client.release();
        }
    });

    router.post('/verify-face', verifyToken, limits.voter, validate(faceEmbeddingSchema), async (req, res, next) => {
        try {
            const result = await pool.query(
                'SELECT face_embedding FROM users WHERE user_id = $1',
                [req.user.user_id]
            );
            if (result.rowCount === 0) return res.status(404).json({ error: 'User not found.' });

            if (result.rows[0].face_embedding === null) {
                return res.status(403).json({ error: 'Face has not been registered.' });
            }

            const storedEmbedding = parseStoredEmbedding(result.rows[0].face_embedding);
            const distance = euclideanDistance(req.body.face_embedding, storedEmbedding);
            if (distance >= FACE_MATCH_THRESHOLD) {
                return res.status(401).json({ error: 'Face verification failed.' });
            }

            res.status(200).json({
                verification_token: issueVerificationToken(req.user.user_id)
            });
        } catch (err) {
            next(err);
        }
    });

    return router;
}

const router = createAuthRouter();
router.createAuthRouter = createAuthRouter;
module.exports = router;