# 🔍 NextSploit: Next.js CVE-2025-29927 & Multi-CVE Security Auditing Framework ⚠️

**NextSploit** adalah framework otomatisasi *penetration testing* (uji penetrasi) modular dengan akurasi tinggi yang dirancang secara khusus untuk memindai, mendeteksi, dan menganalisis kerentanan kritis pada aplikasi web berbasis **Next.js**.

Framework ini dibangun berdasarkan konsep asli dari **[AnonKryptiQuz/NextSploit](https://github.com/AnonKryptiQuz/NextSploit)**. Jika versi aslinya berfokus khusus pada CVE-2025-29927, **NextSploit v2.2.0** oleh **aarsaputra** memperluas kapabilitasnya menjadi mesin audit Next.js yang komprehensif dengan kemampuan deteksi multi-kerentanan (RCE, SSRF, Request Smuggling, DoS, Cache Poisoning, dan Source Exposure), validasi baseline untuk mengeliminasi false positive, serta mesin perhitungan skor confidence yang diadaptasi dari filter false positive standar.


---

## 🚀 **Fitur**

- **🔍 Deteksi Otomatis Versi Next.js & Build ID**: Pemindai aktif dan pasif merayapi aset Next.js untuk mendapatkan Build ID asli dan Server Action ID yang aktif.
- **🛡️ Penilaian Multi-Kerentanan**:
  - **CVE-2025-29927 (Middleware Auth Bypass)**: Mendeteksi dan memvisualisasikan bypass autentikasi middleware.
  - **CVE-2025-66478 (React2Shell RCE)**: Menguji bug deserialisasi RSC Flight Protocol pada sisi server (CVSS 10.0).
  - **CVE-2024-34351 (Server Action SSRF)**: Memvalidasi vektor pengalihan outbound melalui manipulasi Host Header.
  - **CVE-2024-46982 (Cache Poisoning / Stored XSS)**: Menguji injeksi cache pada fallback Route Matches.
  - **CVE-2024-56332 (Pathname Middleware Bypass)**: Mengevaluasi kontrol otorisasi terhadap varian traversal dan URL-encoding.
  - **CVE-2025-48068 (Dev Server Source Exposure)**: Mengidentifikasi paparan bundel kode sumber di server pengembangan menggunakan spoofing origin.
  - **CVE-2024-34350 (HTTP Request Smuggling)**: Menganalisis target dari HTTP Request Smuggling dan Response Queue Poisoning.
  - **CVE-2025-59471 (Image Optimizer DoS)**: Memeriksa kerentanan dynamic OOM Denial of Service secara unauthenticated.
  - **CVE-2026-23870 (RSC Deserialization DoS)**: Mengevaluasi rute fungsi Server Actions terhadap eksploitasi DoS.
- **⚖️ Pengurangan FP & Skor Confidence**: Memperkenalkan perbandingan baseline respons awal untuk menyaring perbedaan dinamis pada script analitik, serta menilai temuan dalam skala `0.0` - `1.0`.
- **🌐 Otomasi Chaining Browser**: Mengintegrasikan Browser Exploit Engine milik AnonKryptiQuz untuk meluncurkan jendela Chrome yang dikendalikan oleh Selenium dengan header bypass yang telah dikonfigurasi melalui CDP.
- **📡 Laporan Multiformat & Self-Update**: Renders temuan secara instan ke Rich CLI, mendukung pengecekan pembaruan via GitHub API, serta fitur auto-updater `--update`.


---

## **Prasyarat** 🛠️

Untuk menjalankan NextSploit dan menggunakan fitur visual chaining peramban, Anda membutuhkan:
- **🐍 Python 3.8+**
- **🧪 Selenium** (Paket Python)
- **🚗 ChromeDriver** & **🦊 GeckoDriver** (dapat diakses pada path sistem)
- **🌐 Google Chrome** (untuk validasi visual berbasis peramban)
- **rich** & **requests** (untuk penataan CLI dan HTTP parsing)

---

## **Instalasi** 📥

1. **Klon repositori:**
   ```bash
   git clone git@github.com:aarsaputra/NextSploit.git
   cd NextSploit
   ```

2. **Pasang paket Python yang dibutuhkan:**
   NextSploit mendukung eksekusi di virtual environment. Pasang dependensi menggunakan pip:
   ```bash
   pip install -r requirements.txt
   ```
   *Jika file `requirements.txt` belum ada, pasang library secara manual:*
   ```bash
   pip install requests rich urllib3 selenium prompt_toolkit colorama
   ```

3. **Konfigurasi Driver:**
   Pastikan `chromedriver` telah terpasang di sistem Kali Linux atau Debian Anda:
   ```bash
   sudo apt update
   sudo apt install chromium-driver -y
   ```

---

## **Penggunaan** 💻

NextSploit menyediakan antarmuka Command-Line (CLI) yang sangat fleksibel:

```bash
python nextsploit.py -t <TARGET_URL> [opsi]
```

### **Parameter CLI Lengkap**

| Parameter | Alternatif | Deskripsi | Contoh Penggunaan |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | URL target aplikasi Next.js (Wajib, kecuali `--list-modules`) | `-t https://target.com` |
| `--fingerprint` | *None* | Hanya melakukan pengenalan (versi, Build ID, Action IDs) | `--fingerprint` |
| `--cve` | *None* | Menjalankan modul tertentu berdasarkan ID (pisahkan dengan koma) | `--cve 29927,46982` |
| `--all` | *None* | Menjalankan seluruh modul pemindaian yang terdaftar | `--all` |
| `-o` | `--output` | Menyimpan laporan pemindaian (format otomatis `.json`/`.html`/`.txt`) | `-o reports/scan.html` |
| `-v` | *None* | Mode Verbose (menampilkan pesan debug analitis detail) | `-v` |
| `-vv` | *None* | Mode Extra Verbose (menampilkan seluruh proses muatan HTTP/trace) | `-vv` |
| `--browser` | *None* | **[Integrasi AnonKryptiQuz]** Meluncurkan Chrome dengan header bypass yang disuntikkan secara dinamis menggunakan Selenium CDP. | `--cve 29927 --browser` |
| `--list-modules`| *None* | Menampilkan tabel modul pemindaian yang tersedia | `--list-modules` |

### **Contoh Penggunaan**

1. **Memeriksa daftar modul aktif:**
   ```bash
   python nextsploit.py --list-modules
   ```

2. **Melakukan deep scan pada target dengan output HTML:**
   ```bash
   python nextsploit.py -t https://target.com --all -o reports/scan.html
   ```

3. **Menghubungkan pemindaian CVE-2025-29927 langsung ke eksploitasi visual Chrome:**
   ```bash
   python nextsploit.py -t https://target.com --cve 29927 --browser
   ```

---

## 📂 **Arsitektur Proyek**

```text
NextSploit/
├── nextsploit.py            # Entry point CLI dan orkestrator pemindaian
├── core/
│   ├── config.py            # Basis data CVE global dan manajemen sesi HTTP
│   ├── output.py            # Format keluaran CLI interaktif menggunakan Rich
│   ├── reporter.py          # Sistem penulisan laporan (JSON, HTML, TXT)
│   ├── version.py           # Konstanta versi aplikasi
│   ├── banner.py            # Modul ASCII Banner kustom
│   └── updater.py           # Pemeriksa rilis baru & rutinitas update otomatis
└── modules/
    ├── __init__.py          # Registri pemetaan modul pemindaian
    ├── fingerprint.py       # Pengenalan Next.js & ekstraksi Build ID / Action ID
    ├── cve_29927.py         # Pemindai Middleware Auth Bypass + Browser Exploit (AnonKryptiQuz)
    ├── cve_34351.py         # Pemindai SSRF via Server Action Host Header
    ├── cve_57822.py         # Pemindai SSRF via Header (Akurasi Tinggi)
    ├── cve_66478.py         # Pemindai RCE React2Shell (Pasif)
    ├── cve_46982.py         # Pemindai Cache Poisoning / Stored XSS
    ├── cve_56332.py         # Pemindai Pathname Middleware Bypass
    ├── cve_48068.py         # Pemindai Dev Server Source Exposure
    ├── cve_34350.py         # Pemindai HTTP Request Smuggling
    ├── cve_59471.py         # Pemindai Image Optimizer DoS
    └── cve_23870.py         # Pemindai DoS via RSC Deserialization

```

### **Bagaimana Orkestrator Bekerja:**
1. **Normalisasi Target**: NextSploit memformat URL target dan mengonfigurasi sesi HTTP global.
2. **Fingerprinting Wajib**: Melakukan perayapan aset statis (`/_next/static/chunks/`) untuk mengambil Build ID serta memeriksa header spesifik server Next.js.
3. **Penyebaran Context**: Build ID dan Server Action ID yang ditemukan akan dibungkus di dalam objek `ScanConfig` agar semua modul dapat mengaksesnya secara runtime.
4. **Eksekusi Pemindaian**: Modul yang terpilih diimpor secara dinamis dan dieksekusi dengan fungsi penangan `scan(config)`.
5. **Kalkulasi Confidence**: Setiap temuan akan dianalisis tingkat akurasinya dalam skala 0.0 - 1.0 sebelum diekspor ke format laporan.

---

## 💻 **Panduan Ekstensi & Kustomisasi untuk Programmer**

NextSploit dirancang agar mudah dikembangkan. Ikuti langkah-langkah berikut jika ingin menambahkan modul pemindaian kerentanan baru:

### **1. Tambahkan Metadata Baru**
Deklarasikan metadata CVE target Anda pada dictionary `CVE_DATABASE` di file [core/config.py](core/config.py):
```python
"CVE-202X-XXXX": {
    "id": "CVE-202X-XXXX",
    "short": "XXXXX",
    "title": "Judul Kerentanan Anda",
    "type": "RCE / SSRF / Auth Bypass / Info Disclosure",
    "severity": "CRITICAL / HIGH / MEDIUM / LOW",
    "fix_version": "15.x.x",
    "description": "Berikan penjelasan singkat mengenai celah keamanan ini.",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-202X-XXXX"]
}
```

### **2. Daftarkan di Registri Modul**
Buka [modules/__init__.py](modules/__init__.py) dan tambahkan baris pemetaan key baru:
```python
"XXXXX": {
    "name": "CVE-202X-XXXX",
    "title": "Nama Singkat Modul",
    "module": "modules.cve_xxxx", # Harus cocok dengan nama file python Anda
    "function": "scan",           # Fungsi utama modul Anda
}
```

### **3. Implementasikan Logika Deteksi (`modules/cve_xxxx.py`)**
Gunakan templat boilerplate berikut untuk membangun modul pemindaian Anda:
```python
#!/usr/bin/env python3
"""
NextSploit — CVE-202X-XXXX: Implementasi Modul Baru
"""

import requests
from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, print_finding

CVE_ID = "CVE-202X-XXXX"
CVE_INFO = CVE_DATABASE[CVE_ID]

def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE"
    )
    
    session = config.create_session()
    target = config.target.rstrip("/")
    
    log_info(f"Memulai pemindaian {CVE_ID}...")
    
    # Anda dapat memanfaatkan variabel global yang ditemukan modul fingerprint:
    # build_id = config.discovered_build_id
    
    try:
        url = f"{target}/endpoint-rentan-spesifik"
        r = session.get(url, timeout=config.timeout)
        
        if r.status_code == 200 and "exploit_indicator" in r.text:
            detail = f"Ditemukan indikasi kerentanan pada {url}"
            log_warning(detail)
            
            evidence = {
                "url": url,
                "response_indicator": "exploit_indicator"
            }
            
            print_finding(CVE_ID, detail, evidence)
            
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Vulnerability Confirmed",
                status="VULNERABLE",
                detail=detail,
                evidence=evidence,
                confidence=0.9 # Set skor tingkat akurasi (0.0 - 1.0)
            ))
            
    except requests.RequestException as e:
        result.error = str(e)
        
    return result
```

---

## ⚠️ **Disclaimer**

- **Hanya untuk Edukasi & Pengujian yang Sah**: Penggunaan framework ini sepenuhnya ditujukan untuk tujuan riset keamanan, peretasan etis, dan penetration testing yang telah mendapatkan izin tertulis. User memikul tanggung jawab penuh untuk mematuhi hukum lokal yang berlaku.
- **Tanpa Jaminan & Tanggung Jawab**: Pengembang NextSploit tidak bertanggung jawab atas segala kerusakan, kegagalan operasional server target, maupun tuntutan hukum yang disebabkan oleh penyalahgunaan framework ini.
- **Validasi Manual Sangat Disarankan**: Hasil penemuan yang dihasilkan oleh tanda tangan otomatis sebaiknya divalidasi kembali secara manual (baik menggunakan flag `--browser` atau Burp Suite) sebelum membuat kesimpulan akhir.

---

## 🐐 **Penulis & Kredit**

- **Pembuat Konsep Asli**: **[AnonKryptiQuz](https://AnonKryptiQuz.github.io/)** — Penemu dari kerangka pemindai awal NextSploit dan pelopor verifikasi visual bypass middleware menggunakan Selenium CDP.
- **Refactoring & Ekspansi**: **aarsaputra** — Memodernisasi NextSploit menjadi versi 2.2.0 dengan kemampuan multi-CVE, validasi baseline respons, mekanisme notifikasi update, Rich banner interaktif, dan sistem pelaporan yang profesional.

