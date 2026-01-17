// Vercel Serverless Function: api/generate.js
// Bu dosya sunucu tarafında çalışır ve API anahtarınızı gizli tutar.

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
                'Authorization': `Bearer ${API_KEY}`
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
            return res.status(response.status).json({ message: data.error?.message || 'API Hatası' });
        }

        res.status(200).json({ 
            text: data.choices[0].message.content,
            sources: [] // DeepSeek grounding verisi destekliyorsa buraya eklenebilir
        });

    } catch (error) {
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
}
