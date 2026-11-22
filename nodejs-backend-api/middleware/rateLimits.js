const { rateLimit } = require('express-rate-limit');

const RATE_LIMIT_ERROR = 'Too many requests. Please try again later.';

function positiveNumber(env, name, fallback, integer = true) {
    const raw = env[name];
    if (raw === undefined || raw === '') return fallback;

    const value = Number(raw);
    if (!Number.isFinite(value) || value <= 0 || (integer && !Number.isInteger(value))) {
        throw new Error(`${name} must be a positive ${integer ? 'integer' : 'number'}.`);
    }
    return value;
}

function getRateLimitConfig(env = process.env) {
    const accountBackoffMultiplier = positiveNumber(
        env,
        'RATE_LIMIT_ACCOUNT_BACKOFF_MULTIPLIER',
        2,
        false
    );
    if (accountBackoffMultiplier <= 1) {
        throw new Error('RATE_LIMIT_ACCOUNT_BACKOFF_MULTIPLIER must be greater than 1.');
    }

    return {
        authWindowMs: positiveNumber(env, 'RATE_LIMIT_AUTH_WINDOW_MS', 15 * 60 * 1000),
        loginIpMax: positiveNumber(env, 'RATE_LIMIT_LOGIN_IP_MAX', 30),
        registerIpMax: positiveNumber(env, 'RATE_LIMIT_REGISTER_IP_MAX', 5),
        accountFailureThreshold: positiveNumber(env, 'RATE_LIMIT_ACCOUNT_FAILURE_THRESHOLD', 5),
        accountFailureWindowMs: positiveNumber(env, 'RATE_LIMIT_ACCOUNT_FAILURE_WINDOW_MS', 15 * 60 * 1000),
        accountBackoffBaseMs: positiveNumber(env, 'RATE_LIMIT_ACCOUNT_BACKOFF_BASE_MS', 1000),
        accountBackoffMultiplier,
        accountBackoffMaxMs: positiveNumber(env, 'RATE_LIMIT_ACCOUNT_BACKOFF_MAX_MS', 15 * 60 * 1000),
        publicWindowMs: positiveNumber(env, 'RATE_LIMIT_PUBLIC_WINDOW_MS', 60 * 1000),
        publicMax: positiveNumber(env, 'RATE_LIMIT_PUBLIC_MAX', 120),
        voterWindowMs: positiveNumber(env, 'RATE_LIMIT_VOTER_WINDOW_MS', 60 * 1000),
        voterMax: positiveNumber(env, 'RATE_LIMIT_VOTER_MAX', 120),
        adminWindowMs: positiveNumber(env, 'RATE_LIMIT_ADMIN_WINDOW_MS', 60 * 1000),
        adminMax: positiveNumber(env, 'RATE_LIMIT_ADMIN_MAX', 300)
    };
}

function setRateLimitResponse(res, limit, windowMs, resetTime) {
    const resetAt = resetTime instanceof Date ? resetTime.getTime() : Date.now() + windowMs;
    const retryAfterSeconds = Math.max(1, Math.ceil((resetAt - Date.now()) / 1000));

    res.set({
        'RateLimit-Limit': String(limit),
        'RateLimit-Remaining': '0',
        'RateLimit-Reset': String(retryAfterSeconds),
        'RateLimit-Policy': `${limit};w=${Math.ceil(windowMs / 1000)}`,
        'Retry-After': String(retryAfterSeconds)
    });
    return res.status(429).json({
        error: RATE_LIMIT_ERROR,
        retryAfterSeconds
    });
}

function createRateLimiter(limit, windowMs, keyGenerator) {
    return rateLimit({
        windowMs,
        limit,
        ...(keyGenerator ? { keyGenerator } : {}),
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => setRateLimitResponse(
            res,
            req.rateLimit.limit,
            windowMs,
            req.rateLimit.resetTime
        )
    });
}

function createRateLimiters(config = getRateLimitConfig()) {
    return {
        config,
        loginIp: createRateLimiter(config.loginIpMax, config.authWindowMs),
        registerIp: createRateLimiter(config.registerIpMax, config.authWindowMs),
        public: createRateLimiter(config.publicMax, config.publicWindowMs),
        voter: createRateLimiter(config.voterMax, config.voterWindowMs, req => String(req.user.user_id)),
        admin: createRateLimiter(config.adminMax, config.adminWindowMs, req => String(req.user.user_id))
    };
}

const rateLimiters = createRateLimiters();

module.exports = {
    ...rateLimiters,
    createRateLimiters,
    getRateLimitConfig,
    setRateLimitResponse
};
