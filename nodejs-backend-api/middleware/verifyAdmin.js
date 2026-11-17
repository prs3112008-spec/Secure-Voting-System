module.exports = function (req, res, next) {
    // The verifyToken guard runs first and attaches the user's data to req.user.
    // Now we check if their digital ID card says 'admin'.
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access Denied. Only admins can perform this action.' });
    }
    next(); // They are an admin, let them through!
};