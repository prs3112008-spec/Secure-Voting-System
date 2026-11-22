function safeErrorDetails(err) {
    const details = {
        name: typeof err.name === 'string' && /^[A-Za-z][A-Za-z0-9]*$/.test(err.name)
            ? err.name
            : 'Error'
    };

    if (typeof err.code === 'string' && /^[A-Za-z0-9_-]{1,32}$/.test(err.code)) {
        details.code = err.code;
    }

    if (typeof err.stack === 'string') {
        const frames = err.stack.split('\n').slice(1);
        if (frames.length > 0) details.stack = frames.join('\n');
    }

    return details;
}

module.exports = function logError(context, err) {
    const entry = { level: 'error', context };
    if (err && typeof err === 'object') {
        entry.error = safeErrorDetails(err);
    }
    console.error(JSON.stringify(entry));
};
