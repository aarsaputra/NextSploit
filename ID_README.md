# 🚀 NextSploit v2.0 — Next.js Security Auditing Framework

NextSploit adalah framework otomatisasi *Penetration Testing* (uji penetrasi) modular yang dirancang secara khusus untuk memindai, mendeteksi, dan menganalisis kerentanan pada aplikasi web berbasis **Next.js**. 

Framework ini membantu *Security Engineer* untuk menguji ketahanan aplikasi dan membantu *Software Developer* untuk mengidentifikasi serta memperbaiki celah keamanan sebelum naik ke lingkungan produksi.

---

## 🎯 Daftar Isi
1. [Prasyarat & Instalasi](#-prasyarat--instalasi)
2. [Fitur Utama v2.0](#-fitur-utama-v20)
3. [Parameter CLI Lengkap](#%EF%B8%8F-parameter-cli-lengkap)
4. [Arsitektur Proyek & Alur Kerja](#-arsitektur-proyek--alur-kerja)
5. [Panduan Integrasi & Pengembangan Modul Baru (Untuk Programmer)](#-panduan-integrasi--pengembangan-modul-baru-untuk-programmer)
6. [Panduan Remediasi & Mitigasi Celah (Untuk User/Developer)](#-panduan-remediasi--mitigasi-celah-untuk-userdeveloper)
7. [Penyelesaian Masalah (Troubleshooting)](#-penyelesaian-masalah-troubleshooting)
8. [Disclaimer](#%EF%B8%8F-disclaimer)

---

## 📋 Prasyarat & Instalasi

### Prasyarat Sistem
*   **Python**: Versi `3.8` atau yang lebih baru.
*   **Koneksi Jaringan**: Diperlukan untuk pemindaian aktif (kecuali mode analisis offline).

### Instalasi Dependensi
NextSploit menggunakan pustaka pihak ketiga seperti `requests` untuk penanganan HTTP dan `rich` untuk antarmuka CLI yang menawan. Pasang dependensi menggunakan perintah berikut:

```bash
pip3 install -r requirements.txt
```

*Jika file `requirements.txt` belum ada, pasang library secara manual:*
```bash
pip3 install requests rich urllib3
```

---

## ✨ Fitur Utama v2.0

NextSploit v2.0 membawa pembaruan besar yang berfokus pada **Akurasi Tinggi** dan **Kemudahan Pengembangan**:

1.  **Baseline-Driven Scanning**: Menghilangkan *false positive* dengan membandingkan tanda tangan respons awal target (*baseline hash*) terhadap respons saat diinjeksi payload.
2.  **Context-Aware Keywords**: Penyaringan cerdas yang menghapus script analitik (seperti Google Tag Manager) sebelum mencari kebocoran kredensial.
3.  **Global Context Sharing**: Data penting seperti *Build ID* atau *Server Action IDs* yang ditemukan pada fase *fingerprint* otomatis didistribusikan ke modul penyerangan.
4.  **Dukungan Kerentanan Kritis Baru**: 
    *   **CVE-2025-66478 (React2Shell)**: Analisis deserialisasi RSC Flight Protocol (CVSS 10.0).
    *   **CVE-2024-34351**: SSRF via manipulasi Host Header pada Server Actions.

---

## ⚙️ Parameter CLI Lengkap

NextSploit menyediakan antarmuka Command Line (CLI) yang fleksibel:

| Parameter | Alternatif | Deskripsi | Contoh Penggunaan |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | URL target aplikasi Next.js (Wajib, kecuali `--list-modules`) | `-t https://target.com` |
| `--fingerprint` | *None* | Hanya melakukan pengenalan (versi, Build ID, Action IDs) | `--fingerprint` |
| `--cve` | *None* | Menjalankan modul tertentu berdasarkan ID (pisahkan dengan koma) | `--cve 57822,34351` |
| `--all` | *None* | Menjalankan seluruh modul pemindaian yang terdaftar | `--all` |
| `-o` | `--output` | Menyimpan laporan pemindaian (format otomatis `.json`/`.html`/`.txt`) | `-o reports/scan.html` |
| `-v` | *None* | Mode Verbose (menampilkan pesan debug analitis detail) | `-v` |
| `-vv` | *None* | Mode Extra Verbose (menampilkan seluruh proses muatan HTTP/trace) | `-vv` |
| `--list-modules`| *None* | Menampilkan tabel modul pemindaian yang tersedia | `--list-modules` |

---

## 📂 Arsitektur Proyek & Alur Kerja

Struktur modular NextSploit memudahkan pemeliharaan kode:

```text
NextSploit/
├── nextsploit.py            # Entry point CLI dan orkestrator pemindaian
├── core/
│   ├── config.py            # Basis data CVE global dan manajemen sesi HTTP
│   ├── output.py            # Format keluaran CLI interaktif menggunakan Rich
│   └── reporter.py          # Sistem penulisan laporan (JSON, HTML, TXT)
└── modules/
    ├── __init__.py          # Registri pemetaan modul pemindaian
    ├── fingerprint.py       # Pengenalan Next.js & ekstraksi Build ID / Action ID
    ├── cve_57822.py         # Pemindai SSRF via Header (Akurasi Tinggi)
    ├── cve_34351.py         # Pemindai SSRF via Server Action Host Header
    ├── cve_66478.py         # Pemindai RCE React2Shell (Pasif)
    ├── cve_29927.py         # Pemindai Middleware Authorization Bypass
    ├── cve_46982.py         # Pemindai Cache Poisoning / Stored XSS
    ├── cve_56332.py         # Pemindai Pathname Middleware Bypass
    ├── cve_48068.py         # Pemindai Dev Server Source Exposure
    └── rsc_attack.py        # Eksploitasi RSC & Prototype Pollution
```

### Alur Kerja Orkestrator (`nextsploit.py`):
1.  **Inisialisasi**: Memvalidasi URL target dan membuat session HTTP dengan User-Agent kustom.
2.  **Fingerprinting (Fase Wajib)**: Mengekstrak metadata Next.js. Jika Build ID atau Server Action IDs ditemukan, data tersebut disimpan di objek `ScanConfig`.
3.  **Seleksi Modul**: Menyeleksi modul yang akan dijalankan berdasarkan input user (`--cve` atau `--all`).
4.  **Eksekusi Modul**: Memanggil fungsi `scan(config)` pada modul terpilih secara dinamis menggunakan `importlib`.
5.  **Pelaporan**: Menyatukan seluruh temuan (`Finding`) ke dalam objek `ScanReport` dan mengekspornya ke format pilihan user.

---

## 💻 Panduan Integrasi & Pengembangan Modul Baru (Untuk Programmer)

NextSploit dirancang agar sangat mudah diperluas (*extensible*). Ikuti 4 langkah ini untuk membuat modul pemindaian baru Anda sendiri:

### Langkah 1: Definisikan CVE Baru di Database
Buka [core/config.py](core/config.py) dan tambahkan metadata kerentanan Anda ke dalam kamus `CVE_DATABASE`:

```python
"CVE-202X-XXXX": {
    "id": "CVE-202X-XXXX",
    "short": "XXXXX",
    "title": "Nama Kerentanan Kustom Anda",
    "type": "RCE / SSRF / Auth Bypass",
    "severity": "CRITICAL / HIGH / MEDIUM / LOW",
    "fix_version": "14.X.X",
    "description": "Deskripsi singkat tentang celah keamanan ini.",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-202X-XXXX"]
}
```

### Langkah 2: Daftarkan Modul ke Registri
Buka [modules/__init__.py](modules/__init__.py) dan daftarkan pemetaan modul:

```python
"XXXXX": {
    "name": "CVE-202X-XXXX",
    "title": "Nama Singkat Modul",
    "module": "modules.cve_xxxx",  # Nama file python di folder modules
    "function": "scan",            # Fungsi utama yang akan dipanggil
}
```

### Langkah 3: Tulis Kode Modul Anda (`modules/cve_xxxx.py`)
Gunakan templat standar berikut untuk modul baru Anda agar terintegrasi sempurna dengan sistem pelaporan:

```python
#!/usr/bin/env python3
"""
NextSploit — CVE-202X-XXXX: Judul Kerentanan
"""

import requests
from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, print_finding

CVE_ID = "CVE-202X-XXXX"
CVE_INFO = CVE_DATABASE[CVE_ID]

def scan(config: ScanConfig) -> ModuleResult:
    # 1. Inisialisasi hasil modul
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE"
    )
    
    # 2. Buat sesi HTTP terkonfigurasi
    session = config.create_session()
    target = config.target.rstrip("/")
    
    log_info(f"Memulai pemindaian {CVE_ID}...")
    
    # [TIPS] Gunakan Build ID atau Action ID yang ditemukan modul fingerprint jika tersedia:
    # build_id = config.discovered_build_id
    # action_ids = config.discovered_action_ids

    # 3. Logika Eksploitasi / Pemindaian Anda
    try:
        url = f"{target}/api/test-endpoint"
        r = session.get(url, timeout=config.timeout)
        
        # Contoh kondisi jika rentan
        if r.status_code == 200 and "vulnerable_indicator" in r.text:
            detail = f"Ditemukan kerentanan pada {url}"
            log_warning(detail)
            
            # Catat bukti eksploitasi
            evidence = {
                "endpoint": url,
                "payload": "normal_request",
                "indicator": "vulnerable_indicator"
            }
            
            print_finding(CVE_ID, detail, evidence)
            
            # Tambahkan temuan ke modul result
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Celah Keamanan Terdeteksi",
                status="VULNERABLE",
                detail=detail,
                evidence=evidence
            ))
            
    except requests.RequestException as e:
        result.error = str(e)
        
    return result
```

---

## 🛡️ Panduan Remediasi & Mitigasi Celah (Untuk User/Developer)

Jika NextSploit menemukan celah keamanan pada aplikasi Next.js Anda, ikuti panduan perbaikan berikut:

### 1. SSRF via Header Injection (`CVE-2025-57822`)
*   **Penyebab**: Server Next.js memproses parameter atau header redirect (`Location`, `X-Forwarded-Host`) yang dikontrol oleh user tanpa validasi protokol/host.
*   **Mitigasi**:
    *   Perbarui versi Next.js Anda ke **14.2.32 / 15.0.0** atau yang lebih baru.
    *   Jika melakukan pengalihan dinamis di kode Anda, pastikan untuk menggunakan **relative redirects** (`redirect('/dashboard')`) alih-alih menerima URL absolut dari input eksternal.
    *   Gunakan whitelist domain jika harus melakukan pengalihan ke URL eksternal.

### 2. SSRF via Server Actions Host Header (`CVE-2024-34351`)
*   **Penyebab**: Server Actions membangun URL absolut untuk pengalihan internal menggunakan nilai header `Host` dari HTTP Request yang dapat dimanipulasi penyerang.
*   **Mitigasi**:
    *   Perbarui versi Next.js ke **14.1.1** atau yang lebih baru.
    *   Pastikan konfigurasi proxy atau Load Balancer Anda (seperti Nginx atau Cloudflare) memaksa penimpaan header `Host` ke nilai internal asli yang valid dan aman.

### 3. RCE via RSC Flight Protocol (`CVE-2025-66478` / React2Shell)
*   **Penyebab**: Unsafe deserialization pada data biner Flight Protocol di Server Actions yang memungkinkan polusi prototipe (`__proto__`) untuk membajak module resolver.
*   **Mitigasi**:
    *   Segera perbarui Next.js ke versi patch terbaru (**15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7**).
    *   Matikan fitur Server Actions jika aplikasi Anda tidak membutuhkannya.

---

## ❓ Penyelesaian Masalah (Troubleshooting)

### 1. Masalah Validasi SSL / HTTPS
*   **Gejala**: Modul gagal terhubung dengan pesan kesalahan `SSLError` atau `certificate verify failed`.
*   **Solusi**: Secara default NextSploit melakukan validasi sertifikat SSL. Jika Anda menguji server lokal dengan sertifikat self-signed, Anda dapat memodifikasi pembuatan session pada `core/config.py` baris `verify_ssl = False`.

### 2. Deteksi Terlalu Banyak False Positive (Terutama pada SSRF)
*   **Gejala**: Semua endpoint ditandai rentan padahal server hanya mengembalikan halaman 404 atau halaman login statis.
*   **Solusi**: Pastikan Anda menjalankan pemindaian tanpa memblokir lalu lintas baseline. NextSploit v2.0 menggunakan baseline diffing. Jika server mengembalikan response size yang selalu sama persis untuk semua payload, NextSploit v2.0 secara otomatis akan menyaring dan menyembunyikannya dari laporan akhir.

### 3. Timeout di Lingkungan Jaringan Lambat
*   **Gejala**: Kesalahan `ConnectionTimeout` terus menerus.
*   **Solusi**: Naikkan durasi batas waktu koneksi pada inisialisasi CLI (misalnya `--timeout 20` jika didukung oleh skrip, atau edit nilai default `timeout: int = 10` di `core/config.py`).

---

## ⚠️ Disclaimer
**NextSploit dibuat MURNI untuk kepentingan Edukasi dan Pengujian Keamanan yang Diizinkan (*Authorized Penetration Testing*).**

Segala bentuk penyalahgunaan framework ini terhadap target eksternal tanpa izin tertulis yang sah dari pemilik sistem adalah tindakan **ilegal** dan dapat dikenakan sanksi hukum sesuai undang-undang ITE yang berlaku. Pengembang tidak bertanggung jawab atas segala kerugian, kerusakan, atau tuntutan hukum yang disebabkan oleh penyalahgunaan alat ini.
