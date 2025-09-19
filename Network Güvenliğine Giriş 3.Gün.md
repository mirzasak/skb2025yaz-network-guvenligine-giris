# Network Güvenliğine Giriş - Detaylı Ders Notları

## Subnet ve IP Adresleme

### Subnet Nedir?

**Subnet (Alt Ağ)**: Büyük bir IP ağını daha küçük, yönetilebilir parçalara bölme işlemidir. Bu sayede ağ trafiği organize edilir ve güvenlik artırılır.

### Subnet Maskeleme Nedir?

**Subnet Mask**: IP adresinin hangi kısmının network, hangi kısmının host olduğunu belirleyen 32 bitlik değerdir.

#### CIDR Notasyonu
- **CIDR (Classless Inter-Domain Routing)**: IP adresi sonrasında "/" ile belirtilen network bit sayısı
- **Örnek**: 192.168.1.0/24 → İlk 24 bit network, son 8 bit host

### Subnet Hesaplama Yöntemi

#### Adım Adım Hesaplama:
1. **CIDR notasyonunu subnet mask'e çevir**
2. **Network adresini hesapla** (IP AND Subnet Mask)
3. **Broadcast adresini hesapla**
4. **Host aralığını belirle**
5. **Kullanılabilir IP sayısını hesapla**

#### Subnet Mask Tablosu
| CIDR | Subnet Mask | Host Bit | Host Sayısı | Kullanılabilir |
|------|-------------|----------|-------------|----------------|
| /24 | 255.255.255.0 | 8 | 256 | 254 |
| /25 | 255.255.255.128 | 7 | 128 | 126 |
| /26 | 255.255.255.192 | 6 | 64 | 62 |
| /27 | 255.255.255.224 | 5 | 32 | 30 |
| /28 | 255.255.255.240 | 4 | 16 | 14 |

### Örnek Çözümler

#### 1. 165.72.83.194/19

**Hesaplama:**
- **CIDR**: /19 → Network: 19 bit, Host: 13 bit
- **Subnet Mask**: 255.255.224.0 (11111111.11111111.11100000.00000000)

**Binary Hesaplama:**
```
IP: 165.72.83.194 → 10100101.01001000.01010011.11000010
Mask: 255.255.224.0 → 11111111.11111111.11100000.00000000
AND işlemi sonucu:    10100101.01001000.01000000.00000000
```

**Sonuçlar:**
- **Network Adresi**: 165.72.64.0
- **Subnet Mask**: 255.255.224.0
- **Broadcast Adresi**: 165.72.95.255
- **İlk Kullanılabilir IP**: 165.72.64.1
- **Son Kullanılabilir IP**: 165.72.95.254
- **Toplam IP Sayısı**: 2^13 = 8,192
- **Kullanılabilir IP Sayısı**: 8,190

#### 2. 87.121.165.49/14

**Hesaplama:**
- **CIDR**: /14 → Network: 14 bit, Host: 18 bit
- **Subnet Mask**: 255.252.0.0

**Sonuçlar:**
- **Network Adresi**: 87.120.0.0
- **Subnet Mask**: 255.252.0.0
- **Broadcast Adresi**: 87.123.255.255
- **İlk Kullanılabilir IP**: 87.120.0.1
- **Son Kullanılabilir IP**: 87.123.255.254
- **Toplam IP Sayısı**: 2^18 = 262,144
- **Kullanılabilir IP Sayısı**: 262,142

#### 3. 193.169.96.73/17

**Hesaplama:**
- **CIDR**: /17 → Network: 17 bit, Host: 15 bit
- **Subnet Mask**: 255.255.128.0

**Sonuçlar:**
- **Network Adresi**: 193.169.0.0
- **Subnet Mask**: 255.255.128.0
- **Broadcast Adresi**: 193.169.127.255
- **İlk Kullanılabilir IP**: 193.169.0.1
- **Son Kullanılabilir IP**: 193.169.127.254
- **Toplam IP Sayısı**: 2^15 = 32,768
- **Kullanılabilir IP Sayısı**: 32,766

#### 4. 172.20.118.0/22

**Hesaplama:**
- **CIDR**: /22 → Network: 22 bit, Host: 10 bit
- **Subnet Mask**: 255.255.252.0

**Sonuçlar:**
- **Network Adresi**: 172.20.116.0
- **Subnet Mask**: 255.255.252.0
- **Broadcast Adresi**: 172.20.119.255
- **İlk Kullanılabilir IP**: 172.20.116.1
- **Son Kullanılabilir IP**: 172.20.119.254
- **Toplam IP Sayısı**: 2^10 = 1,024
- **Kullanılabilir IP Sayısı**: 1,022

#### 5. 10.25.125.62/12

**Hesaplama:**
- **CIDR**: /12 → Network: 12 bit, Host: 20 bit
- **Subnet Mask**: 255.240.0.0

**Sonuçlar:**
- **Network Adresi**: 10.16.0.0
- **Subnet Mask**: 255.240.0.0
- **Broadcast Adresi**: 10.31.255.255
- **İlk Kullanılabilir IP**: 10.16.0.1
- **Son Kullanılabilir IP**: 10.31.255.254
- **Toplam IP Sayısı**: 2^20 = 1,048,576
- **Kullanılabilir IP Sayısı**: 1,048,574

### 98 Kullanıcı İçin Subnet Tasarımı

**Senaryo**: 192.168.100.0 ağında 98 kullanıcı için subnet oluşturma

**Gereksinimler:**
- 98 kullanıcı + 2 (network + broadcast) = 100 IP gerekli
- En küçük 2^n ≥ 100 → 2^7 = 128 IP (/25 subnet)

**Çözüm: 192.168.100.0/25**

**Sonuçlar:**
- **Network Adresi**: 192.168.100.0
- **Subnet Mask**: 255.255.255.128
- **Broadcast Adresi**: 192.168.100.127
- **İlk Kullanılabilir IP**: 192.168.100.1
- **Son Kullanılabilir IP**: 192.168.100.126
- **Toplam Kullanılabilir IP**: 126 (98 kullanıcı için yeterli)

---
## Malware ve Zararlı Yazılım Analizi

### Malware Nedir?

**Malware (Malicious Software)**: Bilgisayar sistemlerine zarar verme, veri çalma veya yetkisiz erişim sağlama amacıyla tasarlanan zararlı yazılımlardır.

### Malware Türleri

#### 1. Virus (Virüs)
- **Özellik**: Kendini diğer dosyalara kopyalar
- **Yayılma**: Dosya enfeksiyonu yoluyla
- **Etki**: Dosya bozma, sistem yavaşlatma
- **Örnek**: Melissa, ILOVEYOU

#### 2. Worm (Solucan)
- **Özellik**: Kendi kendine çoğalır ve yayılır
- **Yayılma**: Network üzerinden otomatik
- **Etki**: Network trafiğini artırır, sistem kaynaklarını tüketir
- **Örnek**: Blaster, Conficker

#### 3. Trojan Horse (Truva Atı)
- **Özellik**: Yasal programa benzer görünür
- **Yayılma**: Kullanıcı tarafından kasıtsız çalıştırma
- **Etki**: Backdoor açma, veri çalma
- **Örnek**: Zeus, Emotet

#### 4. Ransomware (Fidye Yazılımı)
- **Özellik**: Dosyaları şifreler ve fidye ister
- **Yayılma**: Email, exploit kit'ler
- **Etki**: Veri erişimini engeller
- **Örnek**: WannaCry, Ryuk, LockBit

#### 5. Spyware (Casus Yazılım)
- **Özellik**: Gizli bilgi toplama
- **Yayılma**: Bundled software, drive-by download
- **Etki**: Kişisel bilgi sızdırma
- **Örnek**: Keylogger, browser hijacker

#### 6. Adware (Reklam Yazılımı)
- **Özellik**: İstenmeyen reklam gösterme
- **Yayılma**: Freeware ile birlikte
- **Etki**: Performans düşüşü, popup'lar
- **Örnek**: Gator, Claria

#### 7. Rootkit
- **Özellik**: Sistem seviyesinde gizlenme
- **Yayılma**: Privilege escalation
- **Etki**: Sistem kontrolü ele geçirme
- **Örnek**: Sony BMG, Stuxnet

#### 8. Botnet
- **Özellik**: Uzaktan kontrol edilen zombie bilgisayarlar
- **Yayılma**: Malware enfeksiyonu
- **Etki**: DDoS saldırıları, spam gönderme
- **Örnek**: Mirai, Gh0st

### Malware Analizine Başlamadan Önce Yapılması Gerekenler

#### Güvenlik Önlemleri
- **İzole Ortam Hazırlama**: Malware'in ağa yayılmasını önlemek
- **Sanal Makine Kurulumu**: Ana sistemin korunması için
- **Network İzolasyonu**: Internet bağlantısının kesilmesi
- **Snapshot Alma**: Analiz öncesi sistem durumunu kaydetme

#### Teknik Hazırlıklar
- **Gerekli Araçları Kurma**: Hex editor, disassembler, debugger
- **Log Kayıtlarını Etkinleştirme**: Sistem ve network logları
- **Monitoring Araçlarını Başlatma**: Process monitor, network monitor
- **Backup Alma**: Kritik sistem dosyalarının yedeği

#### Dokümantasyon
- **Analiz Planı Hazırlama**: Hangi adımların takip edileceği
- **Başlangıç Durumunu Kaydetme**: Sistem durumunun fotoğrafı
- **Zaman Damgası**: Analiz başlangıç zamanı

### Neden Malware Analizi Yapılır?

1. **Incident Response**: Güvenlik olaylarına müdahale
2. **Tehdit İstihbaratı**: Saldırgan taktik ve tekniklerini anlama
3. **Koruma Geliştirme**: Yeni koruma mekanizmaları oluşturma
4. **Adli Tıp**: Suç delillerinin toplanması
5. **Risk Değerlendirmesi**: Potansiyel zararın belirlenmesi

### YARA Kuralı Nedir?

**YARA**, malware tanımlama ve sınıflandırma için kullanılan bir kural motoru ve dilidir.

#### YARA Kuralı Bileşenleri:
- **Rule Name**: Kuralın adı
- **Meta**: Kural hakkında bilgiler
- **Strings**: Aranacak string'ler
- **Condition**: Eşleşme koşulları

```yara
rule ExampleMalware
{
    meta:
        author = "Analyst Name"
        date = "2025-01-01"
        description = "Detects example malware"
    
    strings:
        $string1 = "malicious_function"
        $hex1 = { 4D 5A 90 00 }
        $regex1 = /http:\/\/[a-z]+\.badsite\.com/
    
    condition:
        $string1 and $hex1 and $regex1
}
```

---

## Analiz Türleri

### Statik Analiz

**Statik Analiz**, malware'i çalıştırmadan analiz etme yöntemidir.

#### Avantajları:
- Güvenli (malware çalışmaz)
- Hızlı tarama imkanı
- Kod yapısı inceleme

#### Dezavantajları:
- Paketlenmiş/şifrelenmiş malware'de sınırlı
- Runtime davranışı göremez
- Dinamik özellikleri kaçırır

#### Statik Analiz Araçları:
- **File**: Dosya tipini belirleme
- **Strings**: Dosyadaki string'leri listeleme
- **Hexdump**: Hex değerleri görüntüleme
- **IDA Pro**: Disassembler
- **Ghidra**: Reverse engineering

### Dinamik Analiz

**Dinamik Analiz**, malware'i kontrollü ortamda çalıştırarak analiz etme yöntemidir.

#### Avantajları:
- Gerçek davranışı gözlemleme
- Runtime özelliklerini görme
- Network aktivitesini izleme

#### Dezavantajları:
- Risk içerir
- Zaman alıcı
- Anti-analysis tekniklerinden etkilenir

#### Dinamik Analiz Araçları:
- **Process Monitor**: Sistem aktivitesi izleme
- **Wireshark**: Network trafiği analizi
- **Regshot**: Registry değişikliklerini kaydetme
- **VMware**: Sanal ortam

---

## Antivirüs Teknolojileri

### Antivirüs Nedir?

**Antivirüs**, bilgisayar sistemlerini malware'den korumak için tasarlanmış güvenlik yazılımıdır.

### Antivirüs Çalışma Mantığı

#### 1. **Byte Signature (İmza Tabanlı)**
- Bilinen malware'lerin binary desenlerini arar
- Hızlı ve doğru tespit
- Sadece bilinen tehditleri yakalar
- Database güncellemeleri gerekir

```
Örnek Signature:
Malware X: 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF
```

#### 2. **Hash Signature (Hash Tabanlı)**
- Dosyaların MD5/SHA hash değerlerini karşılaştırır
- Tam dosya eşleşmesi arar
- Çok hızlı kontrol
- Küçük değişikliklerde başarısız

```
Örnek MD5 Hash:
d41d8cd98f00b204e9800998ecf8427e = Empty file
```

#### 3. **Heuristic (Davranış Tabanlı)**
- Şüpheli davranış kalıplarını arar
- Bilinmeyen tehditleri yakalayabilir
- Yalancı pozitif oranı yüksek
- Makine öğrenmesi kullanır

#### Heuristic Kontrol Örnekleri:
- Registry'de şüpheli değişiklikler
- Network üzerinden şüpheli bağlantılar
- Sistem dosyalarını değiştirme
- Otomatik başlama kayıtları oluşturma

### Antivirüs Tarama Türleri

#### 1. **Real-time Scanning**
- Sürekli aktif koruma
- Dosya erişiminde anlık tarama
- Yüksek sistem kaynak kullanımı

#### 2. **On-demand Scanning**
- Manuel başlatılan tarama
- Zamanlanmış taramalar
- Kapsamlı sistem kontrolü

#### 3. **Boot-time Scanning**
- Sistem başlangıcında tarama
- Rootkit tespiti için önemli
- Düşük seviye erişim

### VirusTotal Nedir?

**VirusTotal**, şüpheli dosya ve URL'leri 70+ antivirüs motoruyla analiz eden online servisdir.

#### VirusTotal Özellikleri:
- **Multi-engine Scanning**: Çoklu motor analizi
- **Hash Database**: Bilinen hash'lerin kontrolü
- **Behavior Analysis**: Dinamik analiz raporu
- **Community Comments**: Kullanıcı yorumları
- **YARA Rules**: Özel kural uygulaması

---

## Specific Malware: RedLine Stealer

### RedLine Malware Türü

**RedLine Stealer**, bilgi çalma amaçlı tasarlanmış bir trojan türüdür.

#### RedLine'ın Özellikleri:
- **Credential Stealing**: Tarayıcı şifrelerini çalar
- **Crypto Wallet**: Kripto para cüzdanlarını hedefler
- **System Information**: Sistem bilgilerini toplar
- **Screenshots**: Ekran görüntüleri alır
- **File Stealing**: Belirli dosya türlerini çalar

#### RedLine'ın Çalışma Prensibi:
1. **Initial Infection**: Email/web üzerinden bulaşma
2. **Persistence**: Sistemde kalıcı olma
3. **Data Collection**: Bilgi toplama
4. **Exfiltration**: Verileri C&C sunucusuna gönderme

#### Korunma Yöntemleri:
- Güncel antivirüs kullanımı
- Email eklerinde dikkat
- Browser güvenlik ayarları
- 2FA kullanımı

---

## Network Güvenlik Araçları

### Burp Suite Nedir?

**Burp Suite**, web uygulaması güvenlik testi için kullanılan kapsamlı bir araç setidir.

#### Burp Suite Bileşenleri:
- **Proxy**: HTTP/HTTPS trafiğini yakalar
- **Spider**: Web sitesini otomatik keşfeder
- **Scanner**: Güvenlik açıklarını tarar
- **Intruder**: Otomatik saldırılar yapar
- **Repeater**: Request'leri manuel test eder
- **Decoder**: Veri kodlama/çözme
- **Comparer**: Veri karşılaştırması

#### Kullanım Alanları:
- **SQL Injection** testi
- **XSS** (Cross-Site Scripting) testi
- **Authentication** bypass
- **Session** yönetimi testi
- **Input validation** kontrolleri

### Wireshark Nedir?

**Wireshark**, network protokollerini analiz etmek için kullanılan açık kaynaklı paket analiz aracıdır.

#### Wireshark Özellikleri:
- **Live Packet Capture**: Canlı paket yakalama
- **Protocol Analysis**: 1000+ protokol desteği
- **Deep Inspection**: Paket içeriği detay analizi
- **Filtering**: Gelişmiş filtreleme seçenekleri
- **Export Options**: Çeşitli formatlarda dışa aktarma

#### Wireshark Filtreleme Örnekleri:
```
# HTTP trafiği
http

# Belirli IP adresi
ip.addr == 192.168.1.1

# TCP port 80
tcp.port == 80

# DNS sorguları
dns

# Belirli protokol
tcp or udp
```

#### Network Güvenlik Analizinde Kullanım:
- **Malware Communication**: C&C trafiği tespiti
- **Data Exfiltration**: Veri sızıntısı analizi
- **Attack Patterns**: Saldırı desenlerini görme
- **Performance Issues**: Network performans sorunları

---

## Sandbox ve İzolasyon

### Sandbox Nedir?

**Sandbox**, şüpheli yazılımları güvenli ve izole edilmiş ortamda çalıştırmak için kullanılan teknoloji ve yöntemdir.

#### Sandbox Türleri:

#### 1. **Application Sandbox**
- Belirli uygulamaları izole eder
- Sınırlı sistem erişimi
- Örnekler: Browser sandbox, Adobe Reader sandbox

#### 2. **Virtual Machine Sandbox**
- Tam işletim sistemi izolasyonu
- Snapshot/restore özelliği
- Örnekler: VMware, VirtualBox

#### 3. **Container Sandbox**
- Hafif izolasyon
- Hızlı deployment
- Örnekler: Docker, LXC

#### 4. **Hardware-based Sandbox**
- Donanım seviyesinde izolasyon
- Yüksek güvenlik
- Örnekler: Intel VT-x, AMD-V

### Sandbox Avantajları:
- **Güvenli Analiz**: Ana sistem korunur
- **Reverting**: Önceki duruma dönüş
- **Controlled Environment**: Kontrollü ortam
- **Monitoring**: Detaylı izleme imkanı

### Sandbox Dezavantajları:
- **Detection**: Sandbox detection teknikleri
- **Performance**: Performans kaybı
- **Limited Realism**: Gerçek ortamı tam yansıtmama
- **Resource Usage**: Kaynak tüketimi

### Popüler Sandbox Çözümleri:

#### 1. **Cuckoo Sandbox**
- Açık kaynaklı
- Otomatik malware analizi
- API monitoring
- Network trafiği analizi

#### 2. **Joe Sandbox**
- Ticari çözüm
- Gelişmiş evasion detection
- Cloud tabanlı analiz
- Detaylı raporlama

#### 3. **Any.run**
- Online sandbox servisi
- Gerçek zamanlı etkileşim
- Hızlı analiz
- Community paylaşım

### Anti-Sandbox Teknikleri:
- **VM Detection**: Sanal makine tespiti
- **Time Delays**: Zaman gecikmesi
- **User Interaction**: Kullanıcı etkileşimi beklemek
- **Environment Checks**: Ortam kontrolü

---

## Sonuç ve Öneriler

Bu notlar, network güvenliğinin temel konularını kapsamaktadır. İleri seviye analiz ve koruma için:

### Önerilen Çalışma Alanları:
1. **Hands-on Practice**: Sanal laboratuvarlarda uygulama
2. **CTF Competitions**: Capture The Flag yarışmaları
3. **Certification**: CISSP, CEH, GCIH gibi sertifikalar
4. **Continuous Learning**: Güncel tehditler takibi

### Faydalı Kaynaklar:
- OWASP Top 10
- NIST Cybersecurity Framework
- SANS Reading Room
- CVE Database
- Malware Traffic Analysis
