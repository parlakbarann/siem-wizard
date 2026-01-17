// Express Server for SIEM Wizard
// Replaces Vercel serverless functions with a local Node.js server

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fetch = require('node-fetch');
const cookieParser = require('cookie-parser');
const { initDatabase, userDb } = require('./src/database');
const { generateToken, authenticateToken, optionalAuth } = require('./src/auth');
const { encryptApiKey, decryptApiKey, maskApiKey } = require('./src/crypto-utils');
const { validateDeepSeekKey } = require('./src/api-key-validator');
const { resolveApiKey } = require('./src/api-key-resolver');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// API Configuration
const DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions";
const API_KEY = process.env.DEEPSEEK_API_KEY;

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        message: 'SIEM Wizard API is running',
        apiKeyConfigured: !!API_KEY
    });
});

// ============================================
// AUTHENTICATION ENDPOINTS
// ============================================

// Register new user
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, deepseekApiKey } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: 'Username, email ve password gereklidir' });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: 'Şifre en az 6 karakter olmalıdır' });
        }

        // If API key provided, validate and encrypt it
        let encryptedApiKey = null;
        if (deepseekApiKey && deepseekApiKey.trim()) {
            const validation = await validateDeepSeekKey(deepseekApiKey.trim());

            if (!validation.valid) {
                return res.status(400).json({
                    message: 'DeepSeek API anahtarı geçersiz: ' + validation.error
                });
            }

            const { JWT_SECRET } = require('./src/auth');
            encryptedApiKey = encryptApiKey(deepseekApiKey.trim(), JWT_SECRET);
        }

        const user = await userDb.createUser(username, email, password, encryptedApiKey);
        const token = generateToken(user.id, user.username);

        // Set HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            sameSite: 'lax'
        });

        res.status(201).json({
            message: 'Kullanıcı başarıyla oluşturuldu',
            user: { id: user.id, username: user.username, email: user.email },
            hasApiKey: !!encryptedApiKey,
            token
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username ve password gereklidir' });
        }

        const user = userDb.findByUsername(username);

        if (!user) {
            return res.status(401).json({ message: 'Kullanıcı adı veya şifre hatalı' });
        }

        const isValidPassword = await userDb.verifyPassword(password, user.password);

        if (!isValidPassword) {
            return res.status(401).json({ message: 'Kullanıcı adı veya şifre hatalı' });
        }

        const token = generateToken(user.id, user.username);

        // Set HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            sameSite: 'lax'
        });

        res.json({
            message: 'Giriş başarılı',
            user: { id: user.id, username: user.username, email: user.email },
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Giriş işlemi başarısız' });
    }
});

// Logout user
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Çıkış başarılı' });
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
    const user = userDb.findById(req.user.userId);
    if (!user) {
        return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
    }
    res.json({ user });
});

// Get user's API key status (masked)
app.get('/api/auth/api-key', authenticateToken, (req, res) => {
    try {
        const encryptedKey = userDb.getApiKey(req.user.userId);

        if (!encryptedKey) {
            return res.json({
                hasApiKey: false,
                message: 'API anahtarı ayarlanmadı'
            });
        }

        // Decrypt to get masked version
        const { JWT_SECRET } = require('./src/auth');
        const apiKey = decryptApiKey(encryptedKey, JWT_SECRET);
        const maskedKey = maskApiKey(apiKey);

        res.json({
            hasApiKey: true,
            maskedKey: maskedKey,
            source: 'user'
        });
    } catch (error) {
        console.error('Get API key error:', error);
        res.status(500).json({ message: 'API anahtarı alınamadı' });
    }
});

// Update user's API key
app.put('/api/auth/api-key', authenticateToken, async (req, res) => {
    try {
        const { apiKey } = req.body;

        if (!apiKey) {
            return res.status(400).json({ message: 'API anahtarı gereklidir' });
        }

        // Validate the API key first
        const validation = await validateDeepSeekKey(apiKey);

        if (!validation.valid) {
            return res.status(400).json({
                message: validation.error || 'API anahtarı geçersiz',
                valid: false
            });
        }

        // Encrypt and save
        const { JWT_SECRET } = require('./src/auth');
        const encryptedKey = encryptApiKey(apiKey, JWT_SECRET);
        await userDb.updateApiKey(req.user.userId, encryptedKey);

        res.json({
            success: true,
            message: 'API anahtarı başarıyla güncellendi',
            validated: true,
            warning: validation.warning
        });
    } catch (error) {
        console.error('Update API key error:', error);
        res.status(500).json({ message: 'API anahtarı güncellenemedi' });
    }
});

// Delete user's API key
app.delete('/api/auth/api-key', authenticateToken, (req, res) => {
    try {
        userDb.deleteApiKey(req.user.userId);

        res.json({
            success: true,
            message: 'API anahtarı kaldırıldı. Sistem varsayılan anahtarı kullanılacak.'
        });
    } catch (error) {
        console.error('Delete API key error:', error);
        res.status(500).json({ message: 'API anahtarı silinemedi' });
    }
});

// Validate an API key without saving
app.post('/api/auth/validate-api-key', authenticateToken, async (req, res) => {
    try {
        const { apiKey } = req.body;

        if (!apiKey) {
            return res.status(400).json({ message: 'API anahtarı gereklidir' });
        }

        const validation = await validateDeepSeekKey(apiKey);

        res.json({
            valid: validation.valid,
            message: validation.valid
                ? 'API anahtarı geçerli'
                : validation.error,
            warning: validation.warning
        });
    } catch (error) {
        console.error('Validate API key error:', error);
        res.status(500).json({
            valid: false,
            message: 'Doğrulama başarısız oldu'
        });
    }
});

// ============================================
// HISTORY ENDPOINTS
// ============================================

// Get user's query history
app.get('/api/history', authenticateToken, (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const history = userDb.getQueryHistory(req.user.userId, limit);
        res.json({ history });
    } catch (error) {
        console.error('Get history error:', error);
        res.status(500).json({ message: 'Geçmiş yüklenemedi' });
    }
});

// Delete history item
app.delete('/api/history/:id', authenticateToken, (req, res) => {
    try {
        const historyId = parseInt(req.params.id);
        userDb.deleteHistoryItem(req.user.userId, historyId);
        res.json({ success: true, message: 'Geçmiş kaydı silindi' });
    } catch (error) {
        console.error('Delete history error:', error);
        res.status(500).json({ message: 'Geçmiş kaydı silinemedi' });
    }
});

// Clear all history
app.delete('/api/history', authenticateToken, (req, res) => {
    try {
        userDb.clearHistory(req.user.userId);
        res.json({ success: true, message: 'Tüm geçmiş temizlendi' });
    } catch (error) {
        console.error('Clear history error:', error);
        res.status(500).json({ message: 'Geçmiş temizlenemedi' });
    }
});

// ============================================
// ENDPOINT 1: Generate SIEM Rule
// ============================================
app.post('/api/generate', optionalAuth, async (req, res) => {
    // Resolve which API key to use
    const { apiKey, source } = await resolveApiKey(req);

    if (!apiKey) {
        return res.status(401).json({
            message: 'DeepSeek API anahtarı gerekli. Lütfen ayarlardan API anahtarınızı ekleyin veya giriş yapın.',
            requiresAuth: !req.user,
            settingsUrl: '/settings.html'
        });
    }

    try {
        const { siemPlatform, userRequest, ruleName } = req.body;

        let syntaxInfo = "";
        switch(siemPlatform) {
            case 'Splunk': syntaxInfo = "Splunk SPL"; break;
            case 'QRadar': syntaxInfo = "QRadar AQL"; break;
            case 'LogSign': syntaxInfo = "LogSign LQL"; break;
            case 'Wazuh': syntaxInfo = "Wazuh XML Rules"; break;
            default: syntaxInfo = "SIEM syntax";
        }

        const systemPrompt = `Sen profesyonel bir SIEM kural geliştiricisisin. Sadece ${siemPlatform} (${syntaxInfo}) formatında kural kodu üret. Açıklamaları kodun içine Türkçe yorum satırı olarak ekle. Ekstra metin yazma.`;
        const userPrompt = `Kural Adı: ${ruleName}. Talep: ${userRequest}.`;

        const response = await fetch(DEEPSEEK_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: "deepseek-chat",
                messages: [
                    { role: "system", content: systemPrompt },
                    { role: "user", content: userPrompt }
                ],
                stream: false
            })
        });

        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).json({
                message: data.error?.message || 'API Hatası'
            });
        }

        const responseText = data.choices[0].message.content;

        // Save to history if user is authenticated
        if (req.user && req.user.userId) {
            try {
                userDb.saveQueryHistory(
                    req.user.userId,
                    'generate',
                    { siemPlatform, userRequest, ruleName },
                    { text: responseText },
                    siemPlatform
                );
            } catch (historyError) {
                console.error('History save error:', historyError);
                // Don't fail the request if history save fails
            }
        }

        res.status(200).json({
            text: responseText,
            sources: [],
            apiKeySource: source
        });

    } catch (error) {
        console.error('Generate endpoint error:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// ============================================
// ENDPOINT 2: Get SIEM Rule Catalog
// ============================================
app.get('/api/rules', (req, res) => {
    try {
        const rules = [
            // 1. Firewall Kategorisi
            {
                id: "1",
                category: "Firewall",
                name: "Firewall Kuralları",
                description: "Güvenlik duvarı olay tespiti ve analizi"
            },
            {
                id: "1.1",
                category: "Firewall",
                name: "Firewall VPN Logları",
                description: "VPN bağlantı girişimleri ve oturum yönetimi"
            },
            {
                id: "1.2",
                category: "Firewall",
                name: "Firewall Bağlantı Reddi",
                description: "Reddedilen bağlantı girişimlerinin izlenmesi"
            },
            {
                id: "1.3",
                category: "Firewall",
                name: "Firewall Port Tarama",
                description: "Şüpheli port tarama aktivitelerinin tespiti"
            },

            // 2. Authentication Kategorisi
            {
                id: "2",
                category: "Authentication",
                name: "Kimlik Doğrulama",
                description: "Kullanıcı kimlik doğrulama ve yetkilendirme olayları"
            },
            {
                id: "2.1",
                category: "Authentication",
                name: "Başarısız Login Girişimleri",
                description: "Ardışık başarısız oturum açma denemeleri (Brute Force)"
            },
            {
                id: "2.2",
                category: "Authentication",
                name: "Çoklu Cihazdan Login",
                description: "Aynı kullanıcının farklı cihazlardan eş zamanlı girişi"
            },
            {
                id: "2.3",
                category: "Authentication",
                name: "Yetki Yükseltme",
                description: "Yetki yükseltme (privilege escalation) girişimleri"
            },
            {
                id: "2.4",
                category: "Authentication",
                name: "Mesai Dışı Giriş",
                description: "Çalışma saatleri dışında gerçekleşen erişim denemeleri"
            },

            // 3. Network Traffic Kategorisi
            {
                id: "3",
                category: "Network Traffic",
                name: "Ağ Trafiği",
                description: "Ağ iletişimi ve trafik anomalileri"
            },
            {
                id: "3.1",
                category: "Network Traffic",
                name: "DDoS Saldırı Tespiti",
                description: "Dağıtık hizmet reddi saldırılarının algılanması"
            },
            {
                id: "3.2",
                category: "Network Traffic",
                name: "Data Exfiltration",
                description: "Olağandışı veri çıkışı ve sızma girişimleri"
            },
            {
                id: "3.3",
                category: "Network Traffic",
                name: "DNS Tunelling",
                description: "DNS protokolü üzerinden veri kaçırma tespiti"
            },
            {
                id: "3.4",
                category: "Network Traffic",
                name: "Yasaklı IP İletişimi",
                description: "Kara listedeki IP adresleriyle iletişim denemeleri"
            },

            // 4. Endpoint Security Kategorisi
            {
                id: "4",
                category: "Endpoint Security",
                name: "Endpoint Güvenliği",
                description: "Uç nokta sistemlerinde güvenlik olayları"
            },
            {
                id: "4.1",
                category: "Endpoint Security",
                name: "Malware Tespiti",
                description: "Zararlı yazılım aktivitelerinin algılanması"
            },
            {
                id: "4.2",
                category: "Endpoint Security",
                name: "USB Cihaz Kullanımı",
                description: "Yetkisiz USB ve harici cihaz bağlantıları"
            },
            {
                id: "4.3",
                category: "Endpoint Security",
                name: "Kritik Dosya Değişiklikleri",
                description: "Sistem dosyalarında yetkisiz değişiklik tespiti"
            },
            {
                id: "4.4",
                category: "Endpoint Security",
                name: "Şüpheli Proses Aktivitesi",
                description: "Anormal proses davranışları ve komut satırı işlemleri"
            },

            // 5. RDP/Remote Access Kategorisi
            {
                id: "5",
                category: "Remote Access",
                name: "Uzaktan Erişim",
                description: "RDP, SSH ve uzak masaüstü bağlantıları"
            },
            {
                id: "5.1",
                category: "Remote Access",
                name: "RDP Brute Force",
                description: "RDP üzerinden şifre kırma girişimleri"
            },
            {
                id: "5.2",
                category: "Remote Access",
                name: "SSH Başarısız Giriş",
                description: "SSH protokolünde ardışık hatalı kimlik doğrulama"
            },
            {
                id: "5.3",
                category: "Remote Access",
                name: "Bilinmeyen Lokasyondan RDP",
                description: "Alışılmadık coğrafi konumlardan uzak erişim"
            },

            // 6. Web Application Kategorisi
            {
                id: "6",
                category: "Web Application",
                name: "Web Uygulama Güvenliği",
                description: "Web uygulama saldırıları ve açıklar"
            },
            {
                id: "6.1",
                category: "Web Application",
                name: "SQL Injection Girişimi",
                description: "SQL enjeksiyon saldırısı tespiti"
            },
            {
                id: "6.2",
                category: "Web Application",
                name: "XSS Saldırısı",
                description: "Cross-Site Scripting (XSS) saldırı girişimleri"
            },
            {
                id: "6.3",
                category: "Web Application",
                name: "Path Traversal",
                description: "Dizin geçişi ve yetkisiz dosya erişimi denemeleri"
            },
            {
                id: "6.4",
                category: "Web Application",
                name: "Anormal HTTP Request",
                description: "Olağandışı HTTP istek desenleri ve anomaliler"
            },

            // 7. Email Security Kategorisi
            {
                id: "7",
                category: "Email Security",
                name: "E-posta Güvenliği",
                description: "E-posta tabanlı tehditler ve spam"
            },
            {
                id: "7.1",
                category: "Email Security",
                name: "Phishing Girişimi",
                description: "Kimlik avı (phishing) e-posta tespiti"
            },
            {
                id: "7.2",
                category: "Email Security",
                name: "Zararlı Ek Dosya",
                description: "Tehlikeli dosya ekleri ve makrolar"
            },
            {
                id: "7.3",
                category: "Email Security",
                name: "Spoofing Saldırısı",
                description: "E-posta gönderen sahteciliği tespiti"
            },

            // 8. Cloud Security Kategorisi
            {
                id: "8",
                category: "Cloud Security",
                name: "Bulut Güvenliği",
                description: "Bulut ortamı güvenlik olayları"
            },
            {
                id: "8.1",
                category: "Cloud Security",
                name: "IAM Değişiklikleri",
                description: "Kimlik ve erişim yönetimi yapılandırma değişiklikleri"
            },
            {
                id: "8.2",
                category: "Cloud Security",
                name: "Açık S3 Bucket",
                description: "Herkese açık depolama alanları tespiti"
            },
            {
                id: "8.3",
                category: "Cloud Security",
                name: "API Kötüye Kullanım",
                description: "Olağandışı API çağrıları ve aşırı kullanım"
            },

            // 9. Database Security Kategorisi
            {
                id: "9",
                category: "Database Security",
                name: "Veritabanı Güvenliği",
                description: "Veritabanı erişim ve güvenlik olayları"
            },
            {
                id: "9.1",
                category: "Database Security",
                name: "Yetkisiz DB Erişimi",
                description: "Yetki dışı veritabanı bağlantı girişimleri"
            },
            {
                id: "9.2",
                category: "Database Security",
                name: "Büyük Veri Sorgusu",
                description: "Olağandışı büyük veri çekme işlemleri"
            },
            {
                id: "9.3",
                category: "Database Security",
                name: "Schema Değişiklikleri",
                description: "Veritabanı yapısında yetkisiz değişiklikler"
            },

            // 10. Compliance & Audit Kategorisi
            {
                id: "10",
                category: "Compliance",
                name: "Uyumluluk ve Denetim",
                description: "Regülasyon uyumluluğu ve denetim logları"
            },
            {
                id: "10.1",
                category: "Compliance",
                name: "PII Veri Erişimi",
                description: "Kişisel veriye yetkisiz erişim denemeleri"
            },
            {
                id: "10.2",
                category: "Compliance",
                name: "Audit Log Silme",
                description: "Denetim kayıtlarının silinmesi veya değiştirilmesi"
            },
            {
                id: "10.3",
                category: "Compliance",
                name: "Kritik Dosya Paylaşımı",
                description: "Hassas dosyaların dış kaynaklarla paylaşımı"
            }
        ];

        res.status(200).json({
            rules: rules,
            total: rules.length,
            lastUpdated: new Date().toISOString()
        });

    } catch (error) {
        console.error('Rules endpoint error:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// ============================================
// ENDPOINT 3: Optimize SIEM Rule
// ============================================
app.post('/api/optimize', optionalAuth, async (req, res) => {
    // Resolve which API key to use
    const { apiKey, source } = await resolveApiKey(req);

    if (!apiKey) {
        return res.status(401).json({
            message: 'DeepSeek API anahtarı gerekli. Lütfen ayarlardan API anahtarınızı ekleyin.',
            requiresAuth: !req.user,
            settingsUrl: '/settings.html'
        });
    }

    try {
        const { siemPlatform, ruleContent } = req.body;

        if (!siemPlatform || !ruleContent || typeof ruleContent !== 'string') {
            return res.status(400).json({
                message: 'SIEM platformu ve kural içeriği gereklidir.'
            });
        }

        let syntaxInfo = "";
        switch(siemPlatform) {
            case 'Splunk': syntaxInfo = "Splunk SPL"; break;
            case 'QRadar': syntaxInfo = "QRadar AQL"; break;
            case 'LogSign': syntaxInfo = "LogSign LQL"; break;
            case 'Wazuh': syntaxInfo = "Wazuh XML"; break;
            default: syntaxInfo = "SIEM";
        }

        const systemPrompt = `Sen ${siemPlatform} (${syntaxInfo}) güvenlik kuralları konusunda uzman bir güvenlik analistisin. Sana verilen ${siemPlatform} kuralını detaylı bir şekilde analiz et ve aşağıdaki konularda iyileştirme önerileri sun:

1. **Kural Yapısı**: Syntax, format ve yapı
2. **Tespit Etkinliği**: Yanlış pozitif/negatif riski, tespit hassasiyeti
3. **Performans**: Kural verimlilik ve kaynak kullanımı
4. **Best Practices**: ${siemPlatform} önerilen uygulamaları ve güvenlik standartları
5. **Pattern Matching**: Eşleştirme desenleri ve regex iyileştirmeleri
6. **Severity & Classification**: Olay seviyesi ve kategorizasyon
7. **Correlation**: Diğer kurallarla korelasyon potansiyeli

Her öneriyi Türkçe olarak, madde madde ve açıklayıcı şekilde sun. Eğer kural iyi yazılmışsa, bunu da belirt ve küçük iyileştirmeler öner.`;

        const userPrompt = `Aşağıdaki ${siemPlatform} kuralını analiz et ve iyileştirme önerileri sun:\n\n${ruleContent}`;

        const response = await fetch(DEEPSEEK_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: "deepseek-chat",
                messages: [
                    { role: "system", content: systemPrompt },
                    { role: "user", content: userPrompt }
                ],
                stream: false,
                temperature: 0.7,
                max_tokens: 2000
            })
        });

        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).json({
                message: data.error?.message || 'DeepSeek API Hatası'
            });
        }

        const suggestions = data.choices[0].message.content;

        // Save to history if user is authenticated
        if (req.user && req.user.userId) {
            try {
                userDb.saveQueryHistory(
                    req.user.userId,
                    'optimize',
                    { siemPlatform, ruleContent },
                    { suggestions },
                    siemPlatform
                );
            } catch (historyError) {
                console.error('History save error:', historyError);
                // Don't fail the main request if history save fails
            }
        }

        res.status(200).json({
            suggestions: suggestions,
            analyzedAt: new Date().toISOString(),
            ruleLength: ruleContent.length,
            apiKeySource: source
        });

    } catch (error) {
        console.error('Optimize endpoint error:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// ============================================
// ENDPOINT 4: Analyze Log and Generate Rules
// ============================================
app.post('/api/analyze-log', optionalAuth, async (req, res) => {
    // Resolve which API key to use
    const { apiKey, source } = await resolveApiKey(req);

    if (!apiKey) {
        return res.status(401).json({
            message: 'DeepSeek API anahtarı gerekli. Lütfen ayarlardan API anahtarınızı ekleyin.',
            requiresAuth: !req.user,
            settingsUrl: '/settings.html'
        });
    }

    try {
        const { siemPlatform, logSample, detectionGoal } = req.body;

        if (!siemPlatform || !logSample || !detectionGoal) {
            return res.status(400).json({
                message: 'Tüm alanlar gereklidir: siemPlatform, logSample, detectionGoal'
            });
        }

        let syntaxInfo = "";
        switch(siemPlatform) {
            case 'Splunk': syntaxInfo = "Splunk SPL"; break;
            case 'QRadar': syntaxInfo = "QRadar AQL"; break;
            case 'LogSign': syntaxInfo = "LogSign LQL"; break;
            case 'Wazuh': syntaxInfo = "Wazuh XML Rules"; break;
            default: syntaxInfo = "SIEM syntax";
        }

        const systemPrompt = `Sen profesyonel bir SIEM kural geliştiricisi ve güvenlik analistisin. Sana verilen log örneklerini analiz edecek ve ${siemPlatform} (${syntaxInfo}) formatında üç ayrı çıktı üreteceksin:

1. **DETECTION_RULE**: Log örneğinde görülen olayı tespit eden temel kural
2. **CORRELATION_RULE**: Benzer olayları ilişkilendiren ve daha gelişmiş tehdit tespiti için korelasyon kuralı
3. **EXPLANATION**: Kuralların nasıl çalıştığı, neyi tespit ettiği ve öneriler

ÖNEMLİ: Yanıtını tam olarak aşağıdaki formatta ver. Her bölümü ayırıcı ile işaretle:

===DETECTION_RULE===
[Tespit kuralının kodu buraya - sadece kod, açıklama yok]

===CORRELATION_RULE===
[Korelasyon kuralının kodu buraya - sadece kod, açıklama yok]

===EXPLANATION===
[Türkçe açıklama: Kuralların ne yaptığını, hangi senaryoları tespit ettiğini, dikkat edilmesi gereken noktaları ve iyileştirme önerilerini açıkla]

Kod bloklarında Türkçe yorum satırları kullanabilirsin ama açıklama metni sadece EXPLANATION bölümünde olmalı.`;

        const userPrompt = `Log Örneği:
${logSample}

Tespit Hedefi:
${detectionGoal}

Yukarıdaki log örneğine göre tespit ve korelasyon kuralları oluştur.`;

        const response = await fetch(DEEPSEEK_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: "deepseek-chat",
                messages: [
                    { role: "system", content: systemPrompt },
                    { role: "user", content: userPrompt }
                ],
                stream: false,
                temperature: 0.7,
                max_tokens: 3000
            })
        });

        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).json({
                message: data.error?.message || 'API Hatası'
            });
        }

        const fullResponse = data.choices[0].message.content;

        // Yanıtı parse et
        const detectionMatch = fullResponse.match(/===DETECTION_RULE===\s*([\s\S]*?)\s*===CORRELATION_RULE===/);
        const correlationMatch = fullResponse.match(/===CORRELATION_RULE===\s*([\s\S]*?)\s*===EXPLANATION===/);
        const explanationMatch = fullResponse.match(/===EXPLANATION===\s*([\s\S]*?)$/);

        const detectionRule = detectionMatch ? detectionMatch[1].trim() : fullResponse.split('===')[0] || 'Tespit kuralı oluşturulamadı';
        const correlationRule = correlationMatch ? correlationMatch[1].trim() : 'Korelasyon kuralı oluşturulamadı';
        const explanation = explanationMatch ? explanationMatch[1].trim() : 'Açıklama oluşturulamadı';

        // Save to history if user is authenticated
        if (req.user && req.user.userId) {
            try {
                userDb.saveQueryHistory(
                    req.user.userId,
                    'analyze-log',
                    { siemPlatform, logSample, detectionGoal },
                    { detectionRule, correlationRule, explanation },
                    siemPlatform
                );
            } catch (historyError) {
                console.error('History save error:', historyError);
                // Don't fail the main request if history save fails
            }
        }

        res.status(200).json({
            detectionRule: detectionRule,
            correlationRule: correlationRule,
            explanation: explanation,
            analyzedAt: new Date().toISOString(),
            platform: siemPlatform,
            apiKeySource: source
        });

    } catch (error) {
        console.error('Analyze-log endpoint error:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// ============================================
// ANALYTICS ENDPOINT
// ============================================
app.get('/api/analytics', authenticateToken, (req, res) => {
    try {
        const analytics = userDb.getAnalytics(req.user.userId);
        res.json(analytics);
    } catch (error) {
        console.error('Analytics endpoint error:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// ============================================
// RULE TESTING ENDPOINT
// ============================================
app.post('/api/rules/test', optionalAuth, async (req, res) => {
    try {
        const { siemPlatform, ruleContent, testLogs } = req.body;

        if (!siemPlatform || !ruleContent || !testLogs) {
            return res.status(400).json({
                message: 'siemPlatform, ruleContent ve testLogs gereklidir'
            });
        }

        // Resolve API key
        const { apiKey, source } = await resolveApiKey(req);

        if (!apiKey) {
            return res.status(401).json({
                message: 'API anahtarı bulunamadı. Lütfen ayarlardan API anahtarınızı ekleyin veya giriş yapın.',
                requiresAuth: true
            });
        }

        // Platform syntax info
        const syntaxMap = {
            'Splunk': 'SPL - Search Processing Language',
            'QRadar': 'AQL - Ariel Query Language',
            'LogSign': 'LQL - LogSign Query Language',
            'Wazuh': 'XML based detection rules'
        };
        const syntaxInfo = syntaxMap[siemPlatform] || 'SIEM query language';

        const systemPrompt = `Sen bir ${siemPlatform} (${syntaxInfo}) güvenlik kuralları test uzmanısın.
Verilen kuralı test loglarına uygula ve analiz et.

Görevin:
1. Her log satırını kuralın koşullarına göre değerlendir
2. Kural sözdizimini kontrol et
3. Yanlış pozitif riskini tahmin et
4. Potansiyel sorunları belirle

SADECE aşağıdaki JSON formatında yanıt ver (başka metin ekleme):
{
    "matchedLogs": ["eşleşen log satırları..."],
    "unmatchedLogs": ["eşleşmeyen log satırları..."],
    "detectionRate": 0-100 arası sayı,
    "falsePositiveRisk": "low" veya "medium" veya "high",
    "issues": ["tespit edilen sorunlar listesi..."]
}`;

        const userPrompt = `Kural (${siemPlatform}):
${ruleContent}

Test Logları:
${testLogs}`;

        const response = await fetch(DEEPSEEK_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: "deepseek-chat",
                messages: [
                    { role: "system", content: systemPrompt },
                    { role: "user", content: userPrompt }
                ],
                stream: false,
                temperature: 0.3,
                max_tokens: 2000
            })
        });

        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).json({
                message: data.error?.message || 'API Hatası'
            });
        }

        const responseText = data.choices[0].message.content;

        // Parse JSON response
        let result;
        try {
            // Extract JSON from response (in case there's extra text)
            const jsonMatch = responseText.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                result = JSON.parse(jsonMatch[0]);
            } else {
                throw new Error('JSON not found in response');
            }
        } catch (parseError) {
            console.error('JSON parse error:', parseError);
            // Fallback response
            result = {
                matchedLogs: [],
                unmatchedLogs: testLogs.split('\n').filter(l => l.trim()),
                detectionRate: 0,
                falsePositiveRisk: 'medium',
                issues: ['Yanıt ayrıştırılamadı. Lütfen tekrar deneyin.']
            };
        }

        // Save to history if user is authenticated
        if (req.user && req.user.userId) {
            try {
                userDb.saveQueryHistory(
                    req.user.userId,
                    'test',
                    { siemPlatform, ruleContent, testLogs },
                    result,
                    siemPlatform
                );
            } catch (historyError) {
                console.error('History save error:', historyError);
            }
        }

        res.status(200).json({
            ...result,
            testedAt: new Date().toISOString(),
            platform: siemPlatform,
            apiKeySource: source
        });

    } catch (error) {
        console.error('Rule test endpoint error:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// Serve HTML pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'index.html'));
});

app.get('/catalog', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'catalog.html'));
});

app.get('/optimizer', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'optimizer.html'));
});

app.get('/log-analyzer', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'log-analyzer.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'register.html'));
});

app.get('/history', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'history.html'));
});

app.get('/analytics', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'analytics.html'));
});

app.get('/settings', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'settings.html'));
});

app.get('/rule-tester', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'rule-tester.html'));
});

app.get('/catalog-enhanced', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'catalog-enhanced.html'));
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ message: 'Endpoint bulunamadı' });
});

// Start server with async database initialization
async function startServer() {
    try {
        // Initialize database first
        await initDatabase();
        console.log('✓ Database initialized');

        app.listen(PORT, () => {
            console.log(`
╔════════════════════════════════════════════════════════════╗
║                     SIEM WIZARD                            ║
║              AI-Powered SIEM Rule Management               ║
╠════════════════════════════════════════════════════════════╣
║  🚀 Server running at: http://localhost:${PORT}            ║
║                                                            ║
║  📄 Pages:                                                 ║
║     • http://localhost:${PORT}/                            ║
║     • http://localhost:${PORT}/catalog                     ║
║     • http://localhost:${PORT}/optimizer                   ║
║     • http://localhost:${PORT}/log-analyzer                ║
║                                                            ║
║  🔌 API Endpoints:                                         ║
║     • POST /api/generate     - Generate SIEM rules        ║
║     • GET  /api/rules        - Get rule catalog           ║
║     • POST /api/optimize     - Optimize SIEM rules        ║
║     • POST /api/analyze-log  - Analyze logs & create rules║
║     • POST /api/rules/test   - Test rules with logs       ║
║     • GET  /api/analytics    - Get usage analytics        ║
║     • POST /api/auth/register - Register new user         ║
║     • POST /api/auth/login    - User login                ║
║     • GET  /api/health       - Health check               ║
║                                                            ║
║  ⚙️  API Key: ${API_KEY ? '✓ Configured' : '✗ Missing'}                              ║
║  💾 Database: ✓ SQLite (sql.js)                            ║
╚════════════════════════════════════════════════════════════╝
            `);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();
