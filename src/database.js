// Database setup and initialization using sql.js
const initSqlJs = require('sql.js');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, 'users.db');

let db = null;

// Helper function to save database to file
function saveDatabase() {
    if (db) {
        const data = db.export();
        const buffer = Buffer.from(data);
        fs.writeFileSync(DB_PATH, buffer);
    }
}

// Initialize database
async function initDatabase() {
    const SQL = await initSqlJs();

    // Load existing database or create new one
    if (fs.existsSync(DB_PATH)) {
        const buffer = fs.readFileSync(DB_PATH);
        db = new SQL.Database(buffer);
    } else {
        db = new SQL.Database();
    }

    // Create users table if it doesn't exist
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            encrypted_deepseek_api_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Create sessions table for tracking
    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    `);

    // Create history table for API query history
    db.run(`
        CREATE TABLE IF NOT EXISTS query_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            query_type TEXT NOT NULL,
            request_data TEXT NOT NULL,
            response_data TEXT NOT NULL,
            siem_platform TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    `);

    // Run migration to add encrypted_deepseek_api_key column if it doesn't exist
    try {
        const result = db.exec("PRAGMA table_info(users)");
        const columns = result[0]?.values.map(v => v[1]) || [];

        if (!columns.includes('encrypted_deepseek_api_key')) {
            db.run('ALTER TABLE users ADD COLUMN encrypted_deepseek_api_key TEXT');
            saveDatabase();
            console.log('✓ Database migrated: added encrypted_deepseek_api_key column');
        }
    } catch (error) {
        console.error('Migration error:', error);
    }

    saveDatabase();
    return db;
}

// Helper function to convert array result to object
function rowToObject(columns, values) {
    if (!values || values.length === 0) return null;
    const obj = {};
    columns.forEach((col, index) => {
        obj[col] = values[0][index];
    });
    return obj;
}

// User functions
const userDb = {
    // Create new user
    createUser: async (username, email, password, encryptedApiKey = null) => {
        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run('INSERT INTO users (username, email, password, encrypted_deepseek_api_key) VALUES (?, ?, ?, ?)',
                   [username, email, hashedPassword, encryptedApiKey]);

            const result = db.exec('SELECT last_insert_rowid() as id');
            const userId = result[0].values[0][0];

            saveDatabase();
            return { id: userId, username, email };
        } catch (error) {
            if (error.message.includes('UNIQUE constraint failed')) {
                throw new Error('Username or email already exists');
            }
            throw error;
        }
    },

    // Find user by username
    findByUsername: (username) => {
        const result = db.exec('SELECT * FROM users WHERE username = ?', [username]);
        if (result.length === 0 || result[0].values.length === 0) return null;
        return rowToObject(result[0].columns, result[0].values);
    },

    // Find user by email
    findByEmail: (email) => {
        const result = db.exec('SELECT * FROM users WHERE email = ?', [email]);
        if (result.length === 0 || result[0].values.length === 0) return null;
        return rowToObject(result[0].columns, result[0].values);
    },

    // Find user by ID
    findById: (id) => {
        const result = db.exec('SELECT id, username, email, created_at, encrypted_deepseek_api_key FROM users WHERE id = ?', [id]);
        if (result.length === 0 || result[0].values.length === 0) return null;
        return rowToObject(result[0].columns, result[0].values);
    },

    // Verify password
    verifyPassword: async (password, hashedPassword) => {
        return await bcrypt.compare(password, hashedPassword);
    },

    // Create session
    createSession: (userId, token, expiresAt) => {
        db.run('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)',
               [userId, token, expiresAt]);
        saveDatabase();
        return { success: true };
    },

    // Delete session (logout)
    deleteSession: (token) => {
        db.run('DELETE FROM sessions WHERE token = ?', [token]);
        saveDatabase();
        return { success: true };
    },

    // Clean expired sessions
    cleanExpiredSessions: () => {
        db.run('DELETE FROM sessions WHERE expires_at < datetime("now")');
        saveDatabase();
        return { success: true };
    },

    // Update user's API key
    updateApiKey: async (userId, encryptedApiKey) => {
        try {
            db.run(
                'UPDATE users SET encrypted_deepseek_api_key = ? WHERE id = ?',
                [encryptedApiKey, userId]
            );
            saveDatabase();
            return { success: true };
        } catch (error) {
            console.error('Update API key error:', error);
            throw new Error('Failed to update API key');
        }
    },

    // Get user's encrypted API key
    getApiKey: (userId) => {
        try {
            const result = db.exec(
                'SELECT encrypted_deepseek_api_key FROM users WHERE id = ?',
                [userId]
            );
            if (result.length === 0 || result[0].values.length === 0) {
                return null;
            }
            return result[0].values[0][0]; // Returns encrypted key or NULL
        } catch (error) {
            console.error('Get API key error:', error);
            return null;
        }
    },

    // Delete user's API key
    deleteApiKey: (userId) => {
        try {
            db.run(
                'UPDATE users SET encrypted_deepseek_api_key = NULL WHERE id = ?',
                [userId]
            );
            saveDatabase();
            return { success: true };
        } catch (error) {
            console.error('Delete API key error:', error);
            throw new Error('Failed to delete API key');
        }
    },

    // Save query history
    saveQueryHistory: (userId, queryType, requestData, responseData, siemPlatform = null) => {
        try {
            db.run(
                'INSERT INTO query_history (user_id, query_type, request_data, response_data, siem_platform) VALUES (?, ?, ?, ?, ?)',
                [userId, queryType, JSON.stringify(requestData), JSON.stringify(responseData), siemPlatform]
            );
            saveDatabase();
            return { success: true };
        } catch (error) {
            console.error('Save history error:', error);
            throw new Error('Failed to save query history');
        }
    },

    // Get user's query history
    getQueryHistory: (userId, limit = 50) => {
        try {
            const result = db.exec(
                'SELECT * FROM query_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
                [userId, limit]
            );
            if (result.length === 0) return [];

            const columns = result[0].columns;
            const rows = result[0].values;

            return rows.map(row => {
                const obj = {};
                columns.forEach((col, index) => {
                    obj[col] = row[index];
                });
                // Parse JSON fields
                try {
                    obj.request_data = JSON.parse(obj.request_data);
                    obj.response_data = JSON.parse(obj.response_data);
                } catch (e) {
                    console.error('Parse error:', e);
                }
                return obj;
            });
        } catch (error) {
            console.error('Get history error:', error);
            return [];
        }
    },

    // Delete query history item
    deleteHistoryItem: (userId, historyId) => {
        try {
            db.run(
                'DELETE FROM query_history WHERE id = ? AND user_id = ?',
                [historyId, userId]
            );
            saveDatabase();
            return { success: true };
        } catch (error) {
            console.error('Delete history error:', error);
            throw new Error('Failed to delete history item');
        }
    },

    // Clear all history for user
    clearHistory: (userId) => {
        try {
            db.run(
                'DELETE FROM query_history WHERE user_id = ?',
                [userId]
            );
            saveDatabase();
            return { success: true };
        } catch (error) {
            console.error('Clear history error:', error);
            throw new Error('Failed to clear history');
        }
    },

    // ============================================
    // ANALYTICS FUNCTIONS
    // ============================================

    // Get analytics data for user
    getAnalytics: (userId) => {
        try {
            // Total queries
            const totalResult = db.exec(
                'SELECT COUNT(*) as count FROM query_history WHERE user_id = ?',
                [userId]
            );
            const totalQueries = totalResult.length > 0 ? totalResult[0].values[0][0] : 0;

            // Today's queries
            const todayResult = db.exec(
                'SELECT COUNT(*) as count FROM query_history WHERE user_id = ? AND DATE(created_at) = DATE("now")',
                [userId]
            );
            const todayQueries = todayResult.length > 0 ? todayResult[0].values[0][0] : 0;

            // Platform breakdown
            const platformResult = db.exec(
                'SELECT siem_platform, COUNT(*) as count FROM query_history WHERE user_id = ? AND siem_platform IS NOT NULL GROUP BY siem_platform',
                [userId]
            );
            const platformBreakdown = {};
            if (platformResult.length > 0) {
                platformResult[0].values.forEach(row => {
                    platformBreakdown[row[0]] = row[1];
                });
            }

            // Query type breakdown
            const typeResult = db.exec(
                'SELECT query_type, COUNT(*) as count FROM query_history WHERE user_id = ? GROUP BY query_type',
                [userId]
            );
            const queryTypeBreakdown = {};
            if (typeResult.length > 0) {
                typeResult[0].values.forEach(row => {
                    queryTypeBreakdown[row[0]] = row[1];
                });
            }

            // Top platform
            let topPlatform = null;
            let maxCount = 0;
            Object.entries(platformBreakdown).forEach(([platform, count]) => {
                if (count > maxCount) {
                    maxCount = count;
                    topPlatform = platform;
                }
            });

            // Daily usage (last 30 days)
            const dailyResult = db.exec(
                `SELECT DATE(created_at) as date, COUNT(*) as count
                 FROM query_history
                 WHERE user_id = ? AND created_at >= DATE('now', '-30 days')
                 GROUP BY DATE(created_at)
                 ORDER BY date ASC`,
                [userId]
            );
            const dailyUsage = [];
            if (dailyResult.length > 0) {
                dailyResult[0].values.forEach(row => {
                    dailyUsage.push({ date: row[0], count: row[1] });
                });
            }

            return {
                totalQueries,
                todayQueries,
                platformBreakdown,
                queryTypeBreakdown,
                topPlatform,
                dailyUsage,
                avgScore: null // Will be implemented when scoring is added
            };
        } catch (error) {
            console.error('Get analytics error:', error);
            return {
                totalQueries: 0,
                todayQueries: 0,
                platformBreakdown: {},
                queryTypeBreakdown: {},
                topPlatform: null,
                dailyUsage: [],
                avgScore: null
            };
        }
    }
};

module.exports = { initDatabase, userDb };
