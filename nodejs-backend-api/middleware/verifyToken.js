const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
    // 1. Check if the app sent an ID card (Token) in the header
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access Denied. No token provided.' });

    try {
        // 2. Verify the token is real and hasn't been tampered with
        // (Removes 'Bearer ' if the frontend includes it)
        const cleanToken = token.replace('Bearer ', '');
        const verified = jwt.verify(cleanToken, process.env.JWT_SECRET);
        
        // 3. Attach the user's ID to the request and let them pass
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid Token.' });
    }
};