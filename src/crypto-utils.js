const crypto = require('crypto');

// Derive encryption key from JWT_SECRET
const ALGORITHM = 'aes-256-gcm';
const SALT = 'siem-wizard-api-key-salt'; // Application-specific salt

function deriveKey(secret) {
    return crypto.pbkdf2Sync(secret, SALT, 100000, 32, 'sha256');
}

// Encrypt API key
function encryptApiKey(plaintext, jwtSecret) {
    try {
        const key = deriveKey(jwtSecret);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        // Format: iv:encrypted:authTag
        return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
    } catch (error) {
        console.error('Encryption error:', error);
        throw new Error('Failed to encrypt API key');
    }
}

// Decrypt API key
function decryptApiKey(encryptedData, jwtSecret) {
    try {
        const parts = encryptedData.split(':');
        if (parts.length !== 3) {
            throw new Error('Invalid encrypted data format');
        }

        const [ivHex, encrypted, authTagHex] = parts;
        const key = deriveKey(jwtSecret);
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Failed to decrypt API key');
    }
}

// Mask API key for display (show only last 4 characters)
function maskApiKey(apiKey) {
    if (!apiKey || apiKey.length < 8) {
        return '****';
    }
    const lastFour = apiKey.slice(-4);
    return `sk-...${lastFour}`;
}

module.exports = {
    encryptApiKey,
    decryptApiKey,
    maskApiKey
};
