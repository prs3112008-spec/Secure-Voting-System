const logError = require('../utils/logError');

function notFound(req, res) {
    res.status(404).json({ error: 'Not found' });
}

function errorHandler(err, req, res, next) {
    const malformedJson = err instanceof SyntaxError &&
        err.status === 400 &&
        err.type === 'entity.parse.failed';

    logError(malformedJson ? 'Malformed JSON request' : 'Request failed', err);

    if (res.headersSent) {
        return res.end();
    }

    if (malformedJson) {
        return res.status(400).json({ error: 'Invalid JSON payload' });
    }

    res.status(500).json({ error: 'Internal server error' });
}

module.exports = { errorHandler, notFound };
