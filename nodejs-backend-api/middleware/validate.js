const validate = (schema, target = 'body') => (req, res, next) => {
    const result = schema.safeParse(req[target]);
    if (!result.success) {
        return res.status(400).json({
            error: 'Validation failed',
            details: result.error.issues.map(issue => `${issue.path.join('.')}: ${issue.message}`)
        });
    }

    req[target] = result.data;
    next();
};

module.exports = validate;
