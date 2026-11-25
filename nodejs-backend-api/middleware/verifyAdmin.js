function verifyAdmin(permission) {
    return function (req, res, next) {
        const role = req.user && req.user.role;
        if (role === 'super_admin' || role === 'admin') return next();
        if (role === 'sub_admin') {
            if (permission && req.user.permissions && req.user.permissions[permission] === true) {
                return next();
            }
            return res.status(403).json({ error: 'Insufficient delegated permissions' });
        }
        return res.status(403).json({ error: 'Access Denied. Only admins can perform this action.' });
    };
}

verifyAdmin.checkSubAdminPermission = function (permission) {
    return function (req, res, next) {
        if (req.user && req.user.role === 'sub_admin' &&
            (!req.user.permissions || req.user.permissions[permission] !== true)) {
            return res.status(403).json({ error: 'Insufficient delegated permissions' });
        }
        next();
    };
};

module.exports = verifyAdmin;