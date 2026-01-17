// Vercel Serverless Function: api/rules.js
// Bu dosya SIEM kural kataloğu için hiyerarşik kural verisi sağlar.

export default async function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    try {
        // Hiyerarşik SIEM kuralları
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
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
}
