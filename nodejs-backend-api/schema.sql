CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    mobile_no VARCHAR(16) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'voter',
    permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_approved BOOLEAN NOT NULL DEFAULT FALSE,
    face_embedding JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '{}'::jsonb;
UPDATE public.users SET role = 'super_admin' WHERE role = 'admin';

CREATE TABLE IF NOT EXISTS polls (
    poll_id SERIAL PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    description TEXT,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_private BOOLEAN DEFAULT FALSE,
    security_code TEXT,
    created_by INTEGER REFERENCES users(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT polls_valid_schedule CHECK (end_time > start_time)
);

CREATE TABLE IF NOT EXISTS candidates (
    candidate_id SERIAL PRIMARY KEY,
    poll_id INTEGER NOT NULL REFERENCES polls(poll_id),
    candidate_name VARCHAR(60) NOT NULL,
    party VARCHAR(50) NOT NULL DEFAULT 'Independent',
    photo_url TEXT NOT NULL,
    CONSTRAINT candidates_candidate_poll_unique UNIQUE (candidate_id, poll_id)
);

CREATE TABLE IF NOT EXISTS voter_turnout (
    poll_id INTEGER NOT NULL REFERENCES polls(poll_id) ON DELETE CASCADE,
    voter_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    voted_date DATE NOT NULL DEFAULT CURRENT_DATE,
    PRIMARY KEY (poll_id, voter_id)
);

CREATE TABLE IF NOT EXISTS votes (
    vote_id BIGSERIAL PRIMARY KEY,
    poll_id INTEGER NOT NULL,
    candidate_id INTEGER NOT NULL,
    ballot_nonce VARCHAR(64) NOT NULL,
    previous_hash TEXT NOT NULL,
    current_hash CHAR(64) NOT NULL UNIQUE,
    vote_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT votes_candidate_matches_poll
        FOREIGN KEY (candidate_id, poll_id)
        REFERENCES candidates(candidate_id, poll_id)
);

ALTER TABLE votes ADD COLUMN IF NOT EXISTS ballot_nonce VARCHAR(64);

DO $$
DECLARE
    has_legacy_voter_id BOOLEAN;
    vote_row RECORD;
    chain_previous_hash TEXT := '0';
    ballot_nonce_value VARCHAR(64);
    current_hash_value CHAR(64);
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'votes'
          AND column_name = 'voter_id'
    ) INTO has_legacy_voter_id;

    IF has_legacy_voter_id THEN
        INSERT INTO voter_turnout (poll_id, voter_id, voted_date)
        SELECT poll_id, voter_id, vote_timestamp::date
        FROM votes
        ON CONFLICT (poll_id, voter_id) DO NOTHING;

        FOR vote_row IN
            SELECT vote_id, poll_id, candidate_id
            FROM votes
            ORDER BY vote_id ASC
        LOOP
            ballot_nonce_value := encode(gen_random_bytes(32), 'hex');
            current_hash_value := encode(
                digest(
                    format(
                        '%s-%s-%s-%s',
                        vote_row.poll_id,
                        vote_row.candidate_id,
                        ballot_nonce_value,
                        chain_previous_hash
                    ),
                    'sha256'
                ),
                'hex'
            );

            UPDATE votes
            SET ballot_nonce = ballot_nonce_value,
                previous_hash = chain_previous_hash,
                current_hash = current_hash_value
            WHERE vote_id = vote_row.vote_id;

            chain_previous_hash := current_hash_value;
        END LOOP;

        ALTER TABLE votes DROP CONSTRAINT IF EXISTS votes_one_per_voter_per_poll;
        ALTER TABLE votes DROP CONSTRAINT IF EXISTS votes_poll_id_voter_id_key;
        ALTER TABLE votes DROP COLUMN voter_id;
    END IF;

    ALTER TABLE votes ALTER COLUMN ballot_nonce SET NOT NULL;
END
$$;

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES users(user_id),
    admin_email TEXT NOT NULL,
    action TEXT NOT NULL,
    target_details TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS candidates_poll_id_idx ON candidates(poll_id);
CREATE INDEX IF NOT EXISTS votes_candidate_id_idx ON votes(candidate_id);
CREATE INDEX IF NOT EXISTS voter_turnout_voter_id_idx ON voter_turnout(voter_id);
CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs(created_at DESC, id DESC);
