const jwt = require('jsonwebtoken');

function createVerifyToken(allowFaceEnroll = false) {
    return function (req, res, next) {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ error: 'Access Denied. No token provided.' });

        try {
            const cleanToken = token.replace('Bearer ', '');
            const verified = jwt.verify(cleanToken, process.env.JWT_SECRET);
            if (verified.scope !== undefined &&
                !(allowFaceEnroll && verified.scope === 'face_enroll')) {
                return res.status(403).json({ error: 'This token cannot be used for this route.' });
            }

            req.user = verified;
            next();
        } catch (err) {
            res.status(400).json({ error: 'Invalid Token.' });
        }
    };
}

const verifyToken = createVerifyToken();
verifyToken.allowFaceEnroll = createVerifyToken(true);

module.exports = verifyToken;