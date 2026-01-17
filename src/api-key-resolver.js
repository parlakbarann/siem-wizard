const { userDb } = require('./database');
const { decryptApiKey } = require('./crypto-utils');
const { JWT_SECRET } = require('./auth');

async function resolveApiKey(req) {
    const envApiKey = process.env.DEEPSEEK_API_KEY;

    // If user is authenticated, try to get their API key
    if (req.user && req.user.userId) {
        try {
            const encryptedKey = userDb.getApiKey(req.user.userId);

            if (encryptedKey) {
                // Decrypt and return user's key
                const userApiKey = decryptApiKey(encryptedKey, JWT_SECRET);
                return {
                    apiKey: userApiKey,
                    source: 'user'
                };
            }
        } catch (error) {
            console.error('Error resolving user API key:', error);
            // Fall through to env variable
        }
    }

    // Fall back to environment variable
    if (envApiKey) {
        return {
            apiKey: envApiKey,
            source: 'env'
        };
    }

    // No API key available
    return {
        apiKey: null,
        source: 'none'
    };
}

module.exports = { resolveApiKey };
