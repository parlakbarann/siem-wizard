// Vercel Serverless Function: api/optimize.js
// Bu dosya Wazuh XML kurallarını analiz eder ve iyileştirme önerileri sunar.

const DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions";
const API_KEY = process.env.DEEPSEEK_API_KEY;

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    if (!API_KEY) {
        return res.status(500).json({ message: 'DEEPSEEK_API_KEY bulunamadı. Lütfen Vercel ayarlarından ekleyin.' });
    }

    try {
        const { xmlRule } = req.body;

        if (!xmlRule || typeof xmlRule !== 'string') {
            return res.status(400).json({ message: 'Geçerli bir XML kuralı gönderilmedi.' });
        }

        // Temel XML doğrulama
        if (!xmlRule.includes('<rule') || !xmlRule.includes('</rule>')) {
            return res.status(400).json({ message: 'Geçersiz Wazuh XML formatı.' });
        }

        const systemPrompt = `Sen Wazuh güvenlik kuralları konusunda uzman bir güvenlik analistisin. Sana verilen Wazuh XML kuralını detaylı bir şekilde analiz et ve aşağıdaki konularda iyileştirme önerileri sun:

1. **Kural Yapısı**: XML syntax, etiket kullanımı ve hiyerarşi
2. **Tespit Etkinliği**: Yanlış pozitif/negatif riski, tespit hassasiyeti
3. **Performans**: Kural verimlilik ve kaynak kullanımı
4. **Best Practices**: Wazuh önerilen uygulamaları ve güvenlik standartları
5. **Regex & Pattern**: Düzenli ifadeler ve desen eşleştirme iyileştirmeleri
6. **Severity & Classification**: Olay seviyesi ve kategorizasyon
7. **Correlation**: Diğer kurallarla korelasyon potansiyeli

Her öneriyi Türkçe olarak, madde madde ve açıklayıcı şekilde sun. Eğer kural iyi yazılmışsa, bunu da belirt ve küçük iyileştirmeler öner.`;

        const userPrompt = `Aşağıdaki Wazuh XML kuralını analiz et ve iyileştirme önerileri sun:\n\n${xmlRule}`;

        const response = await fetch(DEEPSEEK_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${API_KEY}`
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

        res.status(200).json({
            suggestions: suggestions,
            analyzedAt: new Date().toISOString(),
            ruleLength: xmlRule.length
        });

    } catch (error) {
        console.error('Optimize endpoint error:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
}
