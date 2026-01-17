const fetch = require('node-fetch');

const DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions";
const VALIDATION_TIMEOUT = 5000; // 5 seconds

async function validateDeepSeekKey(apiKey) {
    if (!apiKey || typeof apiKey !== 'string') {
        return {
            valid: false,
            error: 'API anahtarı boş olamaz'
        };
    }

    // Basic format check
    if (!apiKey.startsWith('sk-')) {
        return {
            valid: false,
            error: 'DeepSeek API anahtarları "sk-" ile başlamalıdır'
        };
    }

    // Validate with actual API call
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), VALIDATION_TIMEOUT);

        const response = await fetch(DEEPSEEK_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: "deepseek-chat",
                messages: [{ role: "user", content: "test" }],
                max_tokens: 1,
                stream: false
            }),
            signal: controller.signal
        });

        clearTimeout(timeout);

        // Success responses (200, 201)
        if (response.ok) {
            return { valid: true };
        }

        // Parse error response
        const data = await response.json();

        // 401 = invalid key, 403 = unauthorized
        if (response.status === 401 || response.status === 403) {
            return {
                valid: false,
                error: 'API anahtarı geçersiz veya yetkisiz'
            };
        }

        // 429 = rate limit (but key might be valid)
        if (response.status === 429) {
            return {
                valid: true, // Assume valid since it wasn't rejected
                warning: 'API hız sınırına ulaşıldı, ancak anahtar geçerli görünüyor'
            };
        }

        // Other errors
        return {
            valid: false,
            error: data.error?.message || 'API anahtarı doğrulanamadı'
        };

    } catch (error) {
        if (error.name === 'AbortError') {
            return {
                valid: false,
                error: 'Doğrulama zaman aşımına uğradı'
            };
        }

        console.error('API key validation error:', error);
        return {
            valid: false,
            error: 'Doğrulama sırasında hata oluştu: ' + error.message
        };
    }
}

module.exports = { validateDeepSeekKey };
