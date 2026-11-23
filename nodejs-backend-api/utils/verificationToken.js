const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const TOKEN_TTL_SECONDS = 120;
const issuedTokens = new Map();

function pruneExpiredTokens() {
    const now = Date.now();
    for (const [jti, expiresAt] of issuedTokens) {
        if (expiresAt <= now) issuedTokens.delete(jti);
    }
}

function issueVerificationToken(userId) {
    pruneExpiredTokens();
    const jti = crypto.randomUUID();
    const expiresAt = Date.now() + TOKEN_TTL_SECONDS * 1000;
    issuedTokens.set(jti, expiresAt);
    return jwt.sign(
        { scope: 'vote_verify', userId, jti },
        process.env.JWT_SECRET,
        { expiresIn: TOKEN_TTL_SECONDS }
    );
}

function getValidPayload(token, userId) {
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        const expiresAt = typeof payload.jti === 'string' ? issuedTokens.get(payload.jti) : undefined;
        if (payload.scope !== 'vote_verify' || payload.userId !== userId ||
            !expiresAt || expiresAt <= Date.now()) {
            return null;
        }
        return payload;
    } catch (err) {
        return null;
    }
}

function verifyVerificationToken(token, userId) {
    return getValidPayload(token, userId) !== null;
}

function consumeVerificationToken(token, userId) {
    const payload = getValidPayload(token, userId);
    if (!payload) return false;
    issuedTokens.delete(payload.jti);
    return true;
}

module.exports = { consumeVerificationToken, issueVerificationToken, verifyVerificationToken };
