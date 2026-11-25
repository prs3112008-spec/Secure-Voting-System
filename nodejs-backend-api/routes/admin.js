const express = require('express');
const sharedPool = require('../db/pool');
const verifyToken = require('../middleware/verifyToken');
const verifyAdmin = require('../middleware/verifyAdmin');
const validate = require('../middleware/validate');
const { delegateRoleSchema } = require('../middleware/schemas');
const { logAdminAction } = require('../utils/auditLog');

function createAdminRouter(pool = sharedPool, logAction = logAdminAction) {
    const router = express.Router();

    router.post('/delegate-role', verifyToken, verifyAdmin(), validate(delegateRoleSchema), async (req, res, next) => {
        const { user_id, role, permissions } = req.body;
        const assignedPermissions = role === 'sub_admin'
            ? permissions
            : {
                can_approve_voters: false,
                can_view_results: false,
                can_export_csv: false
            };

        try {
            const result = await pool.query(
                'UPDATE public.users SET role = $1, permissions = $2::jsonb WHERE user_id = $3 RETURNING user_id, full_name, email, role, permissions',
                [role, JSON.stringify(assignedPermissions), user_id]
            );
            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'User not found.' });
            }

            const action = role === 'sub_admin' ? 'DELEGATE_SUB_ADMIN' : 'REVOKE_SUB_ADMIN';
            await logAction(req.user, action, JSON.stringify({
                user_id,
                role,
                permissions: assignedPermissions
            }));
            return res.status(200).json({
                message: role === 'sub_admin' ? 'Sub-admin role delegated successfully.' : 'Sub-admin role revoked successfully.',
                user: result.rows[0]
            });
        } catch (err) {
            next(err);
        }
    });

    return router;
}

const router = createAdminRouter();
router.createAdminRouter = createAdminRouter;

module.exports = router;
