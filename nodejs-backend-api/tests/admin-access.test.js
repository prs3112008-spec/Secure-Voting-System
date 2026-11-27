const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const adminRouter = require('../routes/admin');
const candidatesRouter = require('../routes/candidates');
const pollsRouter = require('../routes/polls');

test('voter tokens are denied access to admin-only endpoints', async t => {
    const originalSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    t.after(() => {
        if (originalSecret === undefined) delete process.env.JWT_SECRET;
        else process.env.JWT_SECRET = originalSecret;
    });

    let databaseCalls = 0;
    const noDatabase = {
        async query() {
            databaseCalls += 1;
            throw new Error('Database must not be accessed by a voter request.');
        },
        async connect() {
            databaseCalls += 1;
            throw new Error('Database must not be accessed by a voter request.');
        }
    };

    const app = express();
    app.use(express.json());
    app.use('/api/admin', adminRouter.createAdminRouter(noDatabase, async () => {}));
    app.use('/api/polls', pollsRouter.createPollsRouter(noDatabase, async () => {}));
    app.use('/api/candidates', candidatesRouter.createCandidatesRouter(
        noDatabase,
        async () => {},
        async () => { throw new Error('Photo upload must not be reached by a voter request.'); }
    ));

    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
    });
    t.after(() => new Promise((resolve, reject) => {
        server.close(err => err ? reject(err) : resolve());
    }));

    const voterJwt = jwt.sign(
        { user_id: 101, role: 'voter', is_approved: true },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const adminActions = [
        { method: 'post', path: '/api/polls/create', body: { title: 'Test poll' } },
        {
            method: 'post',
            path: '/api/admin/delegate-role',
            body: { user_id: 102, role: 'voter', permissions: {} }
        },
        {
            method: 'post',
            path: '/api/candidates/add',
            body: { poll_id: 999, name: 'Test candidate', party: 'Test' }
        },
        {
            method: 'put',
            path: '/api/admin/voters/102/approve',
            body: { is_approved: true }
        },
        { method: 'get', path: '/api/admin/voters' }
    ];

    for (const action of adminActions) {
        const response = await fetch(`${baseUrl}${action.path}`, {
            method: action.method.toUpperCase(),
            headers: {
                Authorization: `Bearer ${voterJwt}`,
                'Content-Type': 'application/json'
            },
            ...(action.body ? { body: JSON.stringify(action.body) } : {})
        });

        assert.equal(
            response.status,
            403,
            `Expected 403 for ${action.method.toUpperCase()} ${action.path}, got ${response.status}`
        );
    }

    assert.equal(databaseCalls, 0, 'Voter requests must not reach the database');
});
