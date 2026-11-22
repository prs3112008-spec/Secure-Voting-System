const crypto = require('crypto');

const generateHash = (data) => crypto.createHash('sha256').update(data).digest('hex');

async function verifyVoteChain(pool) {
    const result = await pool.query(
        'SELECT vote_id, poll_id, candidate_id, voter_id, previous_hash, current_hash FROM votes ORDER BY vote_id ASC'
    );
    const votes = result.rows;

    if (votes.length === 0) {
        return {
            valid: true,
            total_votes: 0,
            verified_blocks: 0,
            message: 'No votes cast yet. Ledger is clean.'
        };
    }

    let expectedPrevHash = '0';
    let verifiedBlocks = 0;

    for (const vote of votes) {
        if (vote.previous_hash !== expectedPrevHash) {
            return {
                valid: false,
                total_votes: votes.length,
                verified_blocks: verifiedBlocks,
                tampered_vote_id: vote.vote_id,
                message: `Chain broken at Vote ID #${vote.vote_id}: previous_hash mismatch.`
            };
        }

        const rawData = `${vote.poll_id}-${vote.candidate_id}-${vote.voter_id}-${vote.previous_hash}`;
        const recalculatedHash = generateHash(rawData);

        if (recalculatedHash !== vote.current_hash) {
            return {
                valid: false,
                total_votes: votes.length,
                verified_blocks: verifiedBlocks,
                tampered_vote_id: vote.vote_id,
                message: `Data tampered at Vote ID #${vote.vote_id}: hash mismatch!`
            };
        }

        expectedPrevHash = vote.current_hash;
        verifiedBlocks += 1;
    }

    return {
        valid: true,
        total_votes: votes.length,
        verified_blocks: verifiedBlocks,
        message: `Blockchain Intact! All ${votes.length} vote(s) verified with 0 tampering.`
    };
}

module.exports = { generateHash, verifyVoteChain };
