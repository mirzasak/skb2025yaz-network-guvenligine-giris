# Network Güvenliği 1. Gün - Ağ Temelleri ve Güvenlik İlkeleri

## Ağ Temelleri

### İnternetin Keşfi ve Tarihçesi
- **ARPANET (1970'ler)**: İnternetin öncüsü olan ağ sistemi
  - ABD Savunma Bakanlığı (DARPA) tarafından 1969'da geliştirildi
  - Nükleer saldırıya karşı dayanıklı iletişim ağı oluşturma amacıyla kuruldu
  - İlk bağlantı: UCLA ve Stanford Üniversitesi arasında gerçekleştirildi

- **Bilgisayar Altyapı Gelişmesi**: 1970'lerde önemli teknolojik ilerlemeler
  - Paket anahtarlama teknolojisinin gelişimi
  - TCP/IP protokol setinin standardizasyonu
  - Dağıtık ağ mimarisinin temelleri atıldı

- **Router Teknolojisi**: Ağlar arasında veri yönlendirme
  - Farklı ağları birbirine bağlayan cihazlar
  - IP tablolarını kullanarak en uygun yolu bulur
  - Paketleri hedefe ulaştırmak için yönlendirme yapar

- **İlk ARPANET Bağlantıları**: Modern internetin temeli
  - 1969: 4 düğüm ile başladı (UCLA, Stanford, UCSB, Utah)
  - 1973: İlk uluslararası bağlantı (İngiltere ve Norveç)
  - 1983: TCP/IP protokolüne geçiş

### World Wide Web (WWW)
- **HTML ile Web Siteleri**: Hypertext Markup Language
  - Tim Berners-Lee tarafından 1991'de geliştirildi
  - Tag yapısı ile içerik organizasyonu sağlar
  - Web sayfalarının iskeletini oluşturur
  - Örnek: `<h1>Başlık</h1>`, `<p>Paragraf</p>`

- **Browser (Tarayıcı)**: Web sayfalarını görüntüleme yazılımları
  - HTML, CSS ve JavaScript kodlarını yorumlar
  - HTTP protokolü ile web sunucularına istek gönderir
  - Örnekler: Chrome, Firefox, Safari, Edge

- **URL (Uniform Resource Locator)**: Her web sitesinin benzersiz adresi
  - Yapısı: `protokol://alan_adı/yol`
  - Örnek: `https://www.example.com/sayfa`
  - Protokol + Domain + Path bileşenlerinden oluşur

- **Hyperlink**: İçerikler arası geçiş bağlantıları
  - Web sayfaları arasında navigasyon sağlar
  - Örnek: `/eğitim` (göreceli link) veya tam URL
  - HTML'de `<a href="">` etiketi ile oluşturulur

- **Web Server (Web Sunucuları)**:
  - Sunucuda bulunan verilere web üzerinden erişim sağlar
  - HTTP isteklerini karşılayarak dosyaları gönderir
  - Örnekler: Apache, Nginx, IIS
  - Çoğu URL "www" ile başlar (convention)

## Ağ Topolojileri

### Yıldız Topolojisi (Star Topology)
- **Yapısı**: Merkezi bir hub/switch etrafında düzenlenen yapı
- **Avantajları**: 
  - Bir düğüm arızalandığında diğerleri etkilenmez
  - Kolay kurulum ve yönetim
  - Arıza tespiti kolay
- **Dezavantajları**: Merkezi nokta arızalanırsa tüm ağ çöker
- **Kullanım**: Modern Ethernet ağlarında yaygın

### Bus Topolojisi
- **Yapısı**: Tüm cihazlar tek bir kablo üzerine bağlanır
- **Avantajları**: Az kablo gerektirir, ucuz
- **Dezavantajları**: 
  - Ana kablo arızalandığında tüm ağ çöker
  - Çakışmalar (collision) yaşanabilir
- **Kullanım**: Eski Ethernet ağlarında (10Base2, 10Base5)

### Halka Topolojisi (Ring Topology)
- **Yapısı**: Cihazlar dairesel olarak birbirine bağlanır
- **Çalışma**: Token geçiş protokolü kullanır
- **Avantajları**: Çakışma olmaz, adil erişim
- **Dezavantajları**: Bir düğüm arızalandığında tüm ağ etkilenir
- **Kullanım**: Token Ring ağlarında

### Çift Halka Topolojisi (Dual Ring)
- **Yapısı**: İki halka yapısının birleşimi
- **Avantajları**: Yedeklilik sağlar, bir halka arızalandığında diğeri çalışır
- **Dezavantajları**: Daha karmaşık ve pahalı
- **Kullanım**: FDDI (Fiber Distributed Data Interface) ağlarında

### Ağaç Topolojisi (Tree Topology)
- **Yapısı**: Hiyerarşik yapı, yıldız topolojilerinin birleşimi
- **Avantajları**: Kolay genişletme, hiyerarşik yönetim
- **Dezavantajları**: Merkezi düğümler kritik noktalar
- **Kullanım**: Büyük kurumsal ağlarda

### Mesh Topolojisi
- **Full Mesh**: Her düğüm diğer tüm düğümlerle bağlı
- **Partial Mesh**: Bazı düğümler birden fazla bağlantıya sahip
- **Avantajları**: Yüksek yedeklilik, alternatif yollar
- **Dezavantajları**: Yüksek maliyet, karmaşık yönetim
- **Kullanım**: Kritik ağ altyapılarında

### Hibrit Topoloji
- **Yapısı**: Farklı topolojilerin kombinasyonu
- **Avantajları**: En iyi özelliklerden yararlanma
- **Kullanım**: Büyük ölçekli ağlarda yaygın

## Ağ Türleri

### PAN (Personal Area Network)
- **Kapsama Alanı**: 1-10 metre arası
- **Örnekler**: Bluetooth, USB, Infrared
- **Kullanım**: Kişisel cihazlar arası bağlantı
- **Teknolojiler**: Bluetooth 5.0, Zigbee, NFC

### LAN (Local Area Network)
- **Kapsama Alanı**: Binalar veya kampüsler arası (birkaç km)
- **Örnekler**: Ofis ağları, ev ağları
- **Teknolojiler**: Ethernet, Wi-Fi (802.11)
- **Özellikler**: Yüksek hız, düşük gecikme, özel mülkiyet

### MAN (Metropolitan Area Network)
- **Kapsama Alanı**: Şehir çapında (10-100 km)
- **Örnekler**: Şehir geneli fiber ağlar
- **Teknolojiler**: Fiber optik, WiMAX
- **Kullanım**: ISP'ler, belediye ağları

### WAN (Wide Area Network)
- **Kapsama Alanı**: Ülke/kıta çapında
- **Örnekler**: İnternet, kurumsal WAN'lar
- **Teknolojiler**: MPLS, SD-WAN, satelit
- **Özellikler**: Düşük hız, yüksek gecikme, kamu altyapısı

### **NAT (Network Address Translation) ve CGNAT (Carrier-Grade NAT)**
- **NAT (Network Address Translation)**:
  - **Tanım**: NAT, iç ağdaki cihazların özel IP adreslerini tek bir genel IP adresiyle değiştirir.
  - **Avantajlar**: IP adresi tasarrufu sağlar ve ağ güvenliğini artırır.
  - **Kullanım Alanları**: Genellikle internet servis sağlayıcıları (ISP) ve kurumsal ağlarda kullanılır.
  - **Türleri**:
    - **Static NAT**: Her iç IP adresi için sabit bir dış IP atanır.
    - **Dynamic NAT**: İç IP'ler bir havuzdan dış IP'ler ile değiştirilir.
    - **PAT (Port Address Translation)**: Bir dış IP'nin portları, çoklu iç cihazlara yönlendirilir.

- **CGNAT (Carrier-Grade NAT)**:
  - **Tanım**: CGNAT, ISP'ler tarafından çok sayıda kullanıcıya aynı IP adresi sağlamak için kullanılır.
  - **Avantajlar**: IP adresi tasarrufu sağlar ve geniş ölçekli ağlar için etkilidir.
  - **Kullanım Alanları**: Büyük ölçekli ağlar ve internet servis sağlayıcıları.

## Wireless Güvenlik Saldırıları

### Deauthentication Saldırısı
- **Amaç**: İstemcileri AP'den zorla koparmak
- **Yöntem**: Sahte deauth frame'leri gönderilir
- **Etkisi**: Hizmet reddi (DoS) yaratır
- **Korunma**: 802.11w (PMF - Protected Management Frames)

### Evil Twin Saldırısı
- **Tanım**: Sahte erişim noktası oluşturma
- **Yöntem**: 
  - Meşru AP ile aynı SSID kullanılır
  - Daha güçlü sinyal gönderilir
  - Kullanıcılar sahte AP'ye bağlanır
- **Amaç**: Trafik dinleme, veri çalma
- **Korunma**: WPA3-Enterprise, sertifika doğrulama

## Peer-to-Peer (P2P) ve Torrent

### P2P Ağlar
- **Yapısı**: Merkezi sunucu olmayan eşten eşe ağ
- **Özellikler**: Her düğüm hem istemci hem sunucu
- **Avantajları**: Dağıtık yapı, ölçeklenebilirlik
- **Dezavantajları**: Güvenlik riskleri, kontrol zorluğu

- **Yapılandırılmış P2P**:
  - **Tanım**: Merkezi bir sistem veya protokol tarafından koordine edilen ağlar. Her istemci, sunucu gibi görevler üstlenebilir.
  - **Örnekler**: BitTorrent, Gnutella
  - **Avantajları**: Yüksek verimlilik, dağıtık yapı
  - **Dezavantajları**: Kontrol eksikliği, güvenlik riskleri

- **Yapılandırılmamış P2P**:
  - **Tanım**: Merkezi olmayan ağlar; istemciler birbirleriyle doğrudan bağlantı kurar.
  - **Örnekler**: Kaos ve güvenlik açıkları yüksek olabilir.
  - **Avantajları**: Yüksek esneklik, anonimlik
  - **Dezavantajları**: Güvenlik riskleri, denetimsizlik

### Torrent Protokolü
- **Çalışma Mantığı**: 
  - Dosyalar küçük parçalara (chunk) bölünür
  - .torrent dosyası meta bilgileri içerir
  - Tracker sunucuları peer'ları koordine eder
- **Bileşenler**:
  - **Seeder**: Tüm dosyaya sahip kullanıcı
  - **Leecher**: İndirme yapan kullanıcı
  - **Tracker**: Peer koordinasyon sunucusu
  - **DHT**: Dağıtık hash tablosu

### Torrent Güvenlik Riskleri
- **Malware**: Zararlı yazılım bulaşması
- **Telif Hakkı**: Yasadışı içerik paylaşımı
- **Gizlilik**: IP adresi ifşası
- **Korunma Yöntemleri**: VPN kullanımı, güvenlik yazılımları

## OSI Modeli (7 Katman)

### 1. Physical Layer (Fiziksel Katman)
- **İşlevi**: Bit'lerin fiziksel iletimi
- **Örnekler**: Kablolar, hub'lar, repeater'lar
- **Protokoller**: Ethernet fiziksel spesifikasyonları

### 2. Data Link Layer (Veri Bağlantı Katmmanı)
- **İşlevi**: Frame oluşturma, hata kontrolü
- **Alt katmanlar**: LLC (Logical Link Control), MAC (Media Access Control)
- **Protokoller**: Ethernet, Wi-Fi, PPP

### 3. Network Layer (Ağ Katmanı)
- **İşlevi**: Yönlendirme (routing), mantıksal adresleme
- **Protokoller**: IP, ICMP, OSPF, BGP
- **Adres Türü**: IP adresleri

### 4. Transport Layer (Taşıma Katmanı)
- **İşlevi**: Uçtan uca veri iletimi
- **Protokoller**: TCP, UDP
- **Özellikler**: Port numaraları, akış kontrolü

### 5. Session Layer (Oturum Katmanı)
- **İşlevi**: Oturum kurma, yönetme, sonlandırma
- **Örnekler**: NetBIOS, RPC, SQL sessions
- **İşlevler**: Checkpoint'ler, dialog kontrolü

### 6. Presentation Layer (Sunum Katmanı)
- **İşlevi**: Veri formatı dönüşümü, şifreleme
- **Örnekler**: SSL/TLS, JPEG, GIF, ASCII
- **İşlevler**: Sıkıştırma, şifreleme, kod dönüşümü

### 7. Application Layer (Uygulama Katmanı)
- **İşlevi**: Kullanıcı arayüzü, ağ servisleri
- **Protokoller**: HTTP, FTP, SMTP, DNS, DHCP
- **Örnekler**: Web tarayıcıları, e-posta istemcileri

## Ağ Donanımları

### Repeater
- **İşlevi**: Sinyal yükseltme ve yenileme
- **OSI Katmanı**: Physical Layer (1)
- **Kullanım**: Mesafe kısıtlarını aşma
- **Özellik**: Sadece elektriksel sinyal işleme

### Hub
- **İşlevi**: Fiziksel bağlantı merkezi
- **OSI Katmanı**: Physical Layer (1)
- **Çalışma**: Çarpışma domenini genişletir
- **Dezavantaj**: Collision domain paylaşılır
- **Durum**: Günümüzde kullanılmaz

### Bridge
- **İşlevi**: İki LAN segmentini birleştirme
- **OSI Katmanı**: Data Link Layer (2)
- **Özellik**: MAC adres tablosu tutar
- **Avantaj**: Collision domain'i böler
- **Kullanım**: Ağ segmentasyonu

### Switch
- **İşlevi**: Çok portlu bridge, akıllı hub
- **OSI Katmanı**: Data Link Layer (2)
- **Özellikler**:
  - MAC adres tablosu öğrenme
  - Her port ayrı collision domain
  - Full-duplex iletişim
- **Türleri**: Managed, Unmanaged, Layer 3 switch

### Router
- **İşlevi**: Farklı ağlar arasında yönlendirme
- **OSI Katmanı**: Network Layer (3)
- **Özellikler**:
  - IP routing tablosu
  - Broadcast domain'i böler
  - NAT, DHCP, Firewall özellikli olabilir
- **Protokoller**: OSPF, BGP, RIP, EIGRP

## TCP/IP Modeli ve Bayrakları

### TCP/IP Modeli (4 Katman)
1. **Network Access Layer**: OSI'daki Physical + Data Link
2. **Internet Layer**: Network Layer (IP)
3. **Transport Layer**: Transport Layer (TCP/UDP)
4. **Application Layer**: Session + Presentation + Application

### OSI vs TCP/IP Karşılaştırması
- **OSI**: 7 katmanlı teorik model
- **TCP/IP**: 4 katmanlı pratik implementasyon
- **Fark**: TCP/IP daha basit ve yaygın kullanılır

### TCP Bayrakları (Flags)
- **URG (Urgent)**: Acil veri işareti
- **ACK (Acknowledgment)**: Onaylama
- **PSH (Push)**: Veriyi hemen ilet
- **RST (Reset)**: Bağlantıyı sıfırla
- **SYN (Synchronize)**: Bağlantı kurma
- **FIN (Finish)**: Bağlantı sonlandırma

### 3-Way Handshake
1. **SYN**: İstemci sunucuya SYN gönderir
2. **SYN-ACK**: Sunucu SYN-ACK ile cevaplar
3. **ACK**: İstemci ACK ile onaylar
- **Amaç**: Güvenilir TCP bağlantısı kurma
- **Güvenlik**: SYN flood saldırılarına açık

## Port ve Sanal Port Kavramları

### Port Nedir?
- **Tanım**: Ağ trafiğinin yönlendirildiği mantıksal nokta
- **Aralık**: 0-65535 (16 bit)
- **Kategoriler**:
  - **Well-known ports**: 0-1023 (sistem portları)
  - **Registered ports**: 1024-49151
  - **Dynamic/Private ports**: 49152-65535

### Önemli Port Numaraları
- **21**: FTP (File Transfer Protocol)
- **22**: SSH (Secure Shell)
- **23**: Telnet
- **25**: SMTP (Simple Mail Transfer Protocol)
- **53**: DNS (Domain Name System)
- **80**: HTTP (Hypertext Transfer Protocol)
- **110**: POP3 (Post Office Protocol)
- **143**: IMAP (Internet Message Access Protocol)
- **443**: HTTPS (HTTP Secure)
- **993**: IMAPS (IMAP over SSL)
- **995**: POP3S (POP3 over SSL)

### Sanal Port
- **Tanım**: Yazılımsal olarak tanımlanan iletişim noktası
- **Kullanım**: Servislerin birbirinden ayrılması
- **Socket**: IP adresi + Port numarası kombinasyonu

## Siber Güvenliğin İlkeleri

### Active Directory (AD)
- **Tanım**: Microsoft'un dizin hizmeti
- **İşlevi**: Merkezi kullanıcı ve kaynak yönetimi
- **Bileşenler**:
  - **Domain Controller**: Merkezi sunucu
  - **Domain**: Yönetilen ağ alanı
  - **OU (Organizational Unit)**: Organizasyonel birimler
  - **GPO (Group Policy Object)**: Politika nesneleri
- **Güvenlik Önemi**: Merkezi kimlik doğrulama ve yetkilendirme

### CIA Üçgeni (Temel Güvenlik İlkeleri)

#### Confidentiality (Gizlilik)
- **Tanım**: Bilgiye sadece yetkili kişilerin erişmesi
- **Yöntemler**: Şifreleme, erişim kontrolü, VPN
- **Örnekler**: Kişisel veriler, ticari sırlar
- **Tehditler**: Veri sızıntıları, yetkisiz erişim

#### Integrity (Bütünlük)
- **Tanım**: Verinin değiştirilmemesi ve doğruluğunun korunması
- **Yöntemler**: Hash fonksiyonları, dijital imza, versiyon kontrolü
- **Örnekler**: Dosya bütünlük kontrolü, veri tabanı tutarlılığı
- **Tehditler**: Veri manipülasyonu, yetkisiz değişiklik

#### Availability (Erişilebilirlik)
- **Tanım**: Sistemlerin ve verilerin ihtiyaç anında kullanılabilir olması
- **Yöntemler**: Yedekleme, yüksek erişilebilirlik, DDoS koruması
- **Ölçüm**: Uptime yüzdesi (99.9%, 99.99% vb.)
- **Tehditler**: DoS/DDoS saldırıları, sistem arızaları

### DAD Üçgeni (Tehditlerin Sınıflandırılması)

#### Disclosure (İfşa)
- **Tanım**: Gizli bilgilerin yetkisiz kişilere sızmması
- **CIA Karşılığı**: Confidentiality'nin ihlali
- **Örnekler**: Veri sızıntıları, belge çalınması
- **Sonuçlar**: Gizlilik kaybı, rekabet dezavantajı

#### Alteration (Değiştirme)
- **Tanım**: Verilerin yetkisiz değiştirilmesi
- **CIA Karşılığı**: Integrity'nin ihlali
- **Örnekler**: Web sayfası defacement, veri tabanı manipülasyonu
- **Sonuçlar**: Güven kaybı, yanlış kararlar

#### Destruction/Denial (Yok Etme/Reddetme)
- **Tanım**: Sistemlerin veya verilerin kullanılamaz hale getirilmesi
- **CIA Karşılığı**: Availability'nin ihlali
- **Örnekler**: Ransomware, DoS saldırıları, fiziksel zarar
- **Sonuçlar**: İş sürekliliği kaybı, gelir kaybı
