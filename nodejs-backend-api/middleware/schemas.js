const { z } = require('zod');

const password = z.string().min(8).max(64);
const email = z.string().trim().max(100).email();
const phone = z.string().trim().regex(/^\d{10}$/);
const positiveId = z.union([
    z.number(),
    z.string().regex(/^[1-9]\d*$/)
]).pipe(z.coerce.number().int().positive().max(Number.MAX_SAFE_INTEGER));
const datetime = z.string().datetime({ offset: true });

const loginIdentifier = z.string().trim().min(5).max(100).refine(
    value => phone.safeParse(value).success || email.safeParse(value).success,
    'Must be a valid email address or 10-digit mobile number.'
);
const loginSchema = z.union([
    z.object({
        identifier: loginIdentifier,
        password
    }).strict(),
    z.object({
        email,
        password
    }).strict()
]).transform(data => ({
    email: (data.identifier || data.email).toLowerCase(),
    password: data.password
}));

const registerSchema = z.object({
    full_name: z.string().trim().min(2).max(100),
    email,
    mobile_no: z.string().trim().regex(/^\+?\d{10,15}$/),
    password
}).strict();

const resetPasswordSchema = z.object({
    email,
    mobile_no: z.string().trim().regex(/^\+?\d{10,15}$/),
    face_embedding: z.array(z.number().finite()).length(192),
    new_password: password
}).strict();

const candidateName = z.string().trim().min(2).max(60).regex(/^[a-zA-Z0-9 .\-()+]+$/);
const party = z.string().trim().max(50).refine(value => value.length === 0 || value.length >= 2);
function isImageDataUri(value) {
    const match = /^data:image\/[a-zA-Z0-9.+-]+;base64,([A-Za-z0-9+/]+={0,2})$/.exec(value);
    if (!match) return false;

    const payload = match[1];
    if (payload.length % 4 === 1) return false;
    const paddedPayload = payload.padEnd(Math.ceil(payload.length / 4) * 4, '=');
    const decoded = Buffer.from(paddedPayload, 'base64');
    return decoded.length > 0 && decoded.toString('base64') === paddedPayload;
}

function isHttpUrl(value) {
    try {
        const url = new URL(value);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (err) {
        return false;
    }
}

const photoUrl = z.string().min(1).max(4_000_000).refine(
    value => isImageDataUri(value) || isHttpUrl(value),
    'Must be an HTTP(S) URL or Base64 image data URI.'
);
const candidateSchema = z.object({
    name: candidateName.optional(),
    candidate_name: candidateName.optional(),
    party: z.union([party, z.null()]).optional(),
    poll_id: positiveId.optional(),
    photo_url: photoUrl
}).strict().refine(
    data => Boolean(data.name || data.candidate_name),
    { path: ['name'], message: 'A candidate name is required.' }
).transform(data => {
    const { candidate_name, ...candidate } = data;
    return {
        ...candidate,
        name: candidate.name || candidate_name,
        party: candidate.party || 'Independent'
    };
});

const voteSchema = z.union([
    z.object({
        candidate_id: positiveId,
        election_id: positiveId,
        verification_token: z.string().min(1).max(4096)
    }).strict(),
    z.object({
        candidate_id: positiveId,
        poll_id: positiveId,
        verification_token: z.string().min(1).max(4096)
    }).strict()
]).transform(data => ({
    candidate_id: data.candidate_id,
    poll_id: data.election_id || data.poll_id,
    verification_token: data.verification_token
}));

const faceEmbeddingSchema = z.object({
    face_embedding: z.array(z.number().finite()).length(192)
}).strict();

const pollCreateSchema = z.object({
    title: z.string().trim().min(2).max(100),
    description: z.string().max(2000).optional(),
    start_time: datetime,
    end_time: datetime,
    is_private: z.boolean().optional(),
    security_code: z.string().min(1).max(100).optional()
}).strict().refine(
    data => Date.parse(data.end_time) > Date.parse(data.start_time),
    { path: ['end_time'], message: 'End time must be after start time.' }
);

const scheduleSchema = z.object({
    poll_id: positiveId,
    start_time: datetime,
    end_time: datetime,
    is_active: z.boolean()
}).strict().refine(
    data => Date.parse(data.end_time) > Date.parse(data.start_time),
    { path: ['end_time'], message: 'End time must be after start time.' }
);

const voterApprovalSchema = z.object({
    is_approved: z.boolean()
}).strict();

const receiptHashParamsSchema = z.object({
    hash: z.string().regex(/^[a-f0-9]{64}$/i)
}).strict();
const pollIdParamsSchema = z.object({ poll_id: positiveId }).strict();
const candidateIdParamsSchema = z.object({ candidate_id: positiveId }).strict();
const voterIdParamsSchema = z.object({ id: positiveId }).strict();
const optionalPollIdParamsSchema = z.object({ poll_id: positiveId.optional() }).strict();

module.exports = {
    candidateIdParamsSchema,
    candidateSchema,
    faceEmbeddingSchema,
    loginSchema,
    optionalPollIdParamsSchema,
    pollCreateSchema,
    pollIdParamsSchema,
    receiptHashParamsSchema,
    registerSchema,
    resetPasswordSchema,
    scheduleSchema,
    voterApprovalSchema,
    voterIdParamsSchema,
    voteSchema
};
