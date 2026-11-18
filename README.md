# 🛡️ AI Projects · NetSec Toolkit

IT, ağ ve siber güvenlik için küçük ama kullanışlı araçlar. Hem **komut satırı (Python)** hem de **web** sürümü var. Sadece Python standart kütüphanesi kullanılır, kurulum gerekmez.

| Modül | Ne yapar | CLI | Web |
|---|---|:-:|:-:|
| `subnet` | CIDR / alt ağ hesaplama, ağı alt ağlara bölme (IPv4 + IPv6) | ✅ | ✅ (IPv4) |
| `scan` | Çok iş parçacıklı TCP port tarayıcı, servis adlarıyla | ✅ | – |
| `logscan` | SSH `auth.log` analizi, brute-force ve olası ele geçirme tespiti | ✅ | ✅ |
| `hash` | Dosya / metin hash'i (MD5, SHA-1, SHA-256, SHA-512) ve doğrulama | ✅ | ✅ (SHA) |

## 🌐 Web sürümü

`index.html` dosyasını tarayıcıda aç. GitHub Pages ile yayınlamak için **Settings → Pages → Branch: `main` / root → Save**.
Adres: `https://hqpe.github.io/ai-projects-netsec-toolkit/`

## 💻 Komut satırı

### Subnet hesaplayıcı
```bash
python netsec.py subnet 192.168.1.10/24
python netsec.py subnet 10.0.0.0/24 --split 26     # 4 adet /26 alt ağa böl
python netsec.py subnet 2001:db8::1/64              # IPv6
```

### Port tarayıcı
```bash
python netsec.py scan 127.0.0.1                     # yaygın 24 port
python netsec.py scan 192.168.1.1 -p 1-1024
python netsec.py scan example.local -p 22,80,443 -t 1
```
> ⚠️ Port taramayı **sadece sahibi olduğun veya yazılı izin aldığın** sistemlerde kullan.

### SSH log analizi
```bash
python netsec.py logscan /var/log/auth.log
python netsec.py logscan samples/auth.log --threshold 3
```
Örnek çıktı:
```
En çok deneyen IP'ler:
  203.0.113.45           6  <-- ŞÜPHELİ
  198.51.100.7           6  <-- ŞÜPHELİ

[!] UYARI: Brute-force yapan IP'den başarılı giriş:
  root <- 198.51.100.7
```
Olası ele geçirme bulunursa çıkış kodu `1` olur, böylece cron veya CI içinde alarm olarak kullanılabilir.

### Hash
```bash
python netsec.py hash dosya.iso                     # SHA-256
python netsec.py hash dosya.iso -a all              # tüm algoritmalar
python netsec.py hash dosya.iso --verify <beklenen_hash>
python netsec.py hash "merhaba" --text -a md5
```

## 🧪 Testler
```bash
python -m unittest discover tests
```

## 📁 Proje yapısı
```
ai-projects-netsec-toolkit/
├── netsec.py            # CLI araç seti
├── index.html           # Web sürümü
├── samples/auth.log     # Örnek SSH logu
├── tests/test_netsec.py
├── README.md
├── LICENSE
└── .gitignore
```

## 📄 Lisans
MIT
