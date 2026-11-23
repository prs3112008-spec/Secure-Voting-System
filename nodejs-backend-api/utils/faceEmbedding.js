const FACE_MATCH_THRESHOLD = 0.90;

function parseStoredEmbedding(value) {
    const embedding = typeof value === 'string' ? JSON.parse(value) : value;
    if (!Array.isArray(embedding) || embedding.length !== 192 ||
        !embedding.every(item => typeof item === 'number' && Number.isFinite(item))) {
        throw new Error('Stored face embedding is invalid.');
    }
    return embedding;
}

function euclideanDistance(left, right) {
    if (left.length !== right.length) {
        throw new Error('Face embeddings must have the same dimensions.');
    }
    const squaredDistance = left.reduce((sum, value, index) => {
        const difference = value - right[index];
        return sum + difference * difference;
    }, 0);
    return Math.sqrt(squaredDistance);
}

module.exports = { euclideanDistance, FACE_MATCH_THRESHOLD, parseStoredEmbedding };
