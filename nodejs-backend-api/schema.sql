CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    mobile_no VARCHAR(16) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'voter',
    is_approved BOOLEAN NOT NULL DEFAULT FALSE,
    face_embedding JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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

CREATE TABLE IF NOT EXISTS votes (
    vote_id BIGSERIAL PRIMARY KEY,
    poll_id INTEGER NOT NULL,
    candidate_id INTEGER NOT NULL,
    voter_id INTEGER NOT NULL REFERENCES users(user_id),
    previous_hash TEXT NOT NULL,
    current_hash CHAR(64) NOT NULL UNIQUE,
    vote_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT votes_one_per_voter_per_poll UNIQUE (poll_id, voter_id),
    CONSTRAINT votes_candidate_matches_poll
        FOREIGN KEY (candidate_id, poll_id)
        REFERENCES candidates(candidate_id, poll_id)
);

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
CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs(created_at DESC, id DESC);
