const REQUIRED_ENVIRONMENT_VARIABLES = ['DATABASE_URL', 'JWT_SECRET'];

function getRequiredEnvironment(env = process.env) {
    const missing = REQUIRED_ENVIRONMENT_VARIABLES.filter(
        name => typeof env[name] !== 'string' || env[name].trim() === ''
    );
    if (missing.length > 0) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }

    return {
        DATABASE_URL: env.DATABASE_URL,
        JWT_SECRET: env.JWT_SECRET
    };
}

module.exports = getRequiredEnvironment;
