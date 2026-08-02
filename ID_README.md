# 🔍 NextSploit: Next.js Multi-CVE Security Auditing Framework ⚠️

**NextSploit** adalah framework otomatisasi *penetration testing* (uji penetrasi) modular dengan akurasi tinggi yang dirancang secara khusus untuk memindai, mendeteksi, dan menganalisis kerentanan kritis pada aplikasi web berbasis **Next.js**.

Framework ini dibangun berdasarkan konsep asli dari **[AnonKryptiQuz/NextSploit](https://github.com/AnonKryptiQuz/NextSploit)**. Jika versi aslinya berfokus khusus pada CVE-2025-29927, **NextSploit v2.2.0** oleh **aarsaputra** (Author Asli: **AnonKryptiQuz**) memperluas kapabilitasnya menjadi mesin audit Next.js yang komprehensif dengan kemampuan deteksi multi-kerentanan (RCE, SSRF, Request Smuggling, DoS, Cache Poisoning, dan Source Exposure), validasi baseline untuk mengeliminasi false positive, serta mesin perhitungan skor confidence yang diadaptasi dari filter false positive standar.


---

## 🚀 **Fitur**

- **🔍 Deteksi Otomatis Versi Next.js & Build ID**: Pemindai aktif dan pasif merayapi aset Next.js untuk mendapatkan Build ID asli dan Server Action ID yang aktif. Kini dilengkapi dengan normalisasi HTML (decoding stream payload RSC), pengurutan prioritas chunk JS utama, dan peningkatan kedalaman analisis hingga 15 JS chunks untuk mendeteksi versi secara presisi pada arsitektur App Router.
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
  - **CVE-2026-44575 (Middleware Bypass via Segment-Prefetch)**: Mendeteksi bypass middleware via varian rute `.rsc` / `.prefetch.rsc`. Mempengaruhi Next.js 15.2.0–15.5.15. Fix: 15.5.16.
  - **CVE-2026-23864 (RSC Memory Exhaustion DoS)**: Menguji crash OOM melalui amplifikasi token `$K` FormData pada React Flight protocol. CVSS 7.5. Mempengaruhi 15.5.0–15.5.9. Fix: 15.5.10.
  - **GHSA-mg66-mrh9-m8jx (PPR/Cache Components Deadlock DoS)**: Mendeteksi deadlock connection pool yang dipicu header `Next-Resume: 1` pada aplikasi dengan PPR aktif. Fix: 15.5.16.
  - **CVE-2026-45109 (Middleware Bypass via Turbopack)**: Follow-up perbaikan tidak lengkap dari CVE-2026-44575. Mempengaruhi build Turbopack pada 15.5.16–15.5.17. Fix: 15.5.18.
- **⚖️ Pengurangan FP & Skor Confidence**: Memperkenalkan perbandingan baseline respons awal untuk menyaring perbedaan dinamis pada script analitik, serta menilai temuan dalam skala `0.0` - `1.0`. Modul `HEADER-FUZZER` sekarang otomatis mengabaikan rute dengan baseline `404` untuk menghilangkan temuan false-positive pada jalur non-existent.
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
    ├── cve_23870.py         # Pemindai DoS via RSC Deserialization
    ├── cve_44575.py         # Middleware Bypass via Segment-Prefetch (.rsc) [Next.js 15.5.9]
    ├── cve_23864.py         # RSC Memory Exhaustion DoS via FormData $K tokens [Next.js 15.5.9]
    ├── ghsa_mg66.py         # PPR/Cache Components Deadlock DoS [Next.js 15.5.9]
    └── cve_45109.py         # Middleware Bypass via Turbopack (incomplete fix) [Next.js 15.5.9]

```

---

## 🔄 **Alur Kerja Pemindaian & Fase Teknis**

NextSploit menjalankan pipeline multi-fase yang terstruktur pada setiap sesi pemindaian. Berikut adalah alur kerja lengkap setiap fase dan teknik yang digunakan.

```
┌─────────────────────────────────────────────────────────────────────┐
│                   Pipeline Pemindaian NextSploit                    │
│                                                                     │
│  [1] Normalisasi Target ──► [2] Fingerprinting ──► [3] Matriks     │
│                                                         Versi       │
│                                    │                    │           │
│                                    ▼                    ▼           │
│                         [4] Seleksi Modul ◄────── Konteks          │
│                                    │                                │
│                                    ▼                                │
│                       [5] Pemindaian Aktif / Pasif                  │
│                                    │                                │
│                                    ▼                                │
│                     [6] Reduksi FP & Skor Confidence               │
│                                    │                                │
│                                    ▼                                │
│                        [7] Pembuatan Laporan                        │
└─────────────────────────────────────────────────────────────────────┘
```

### **Fase 1 — Normalisasi Target**
- Menghapus trailing slash dan menormalkan skema URL (`http://` → `https://` jika diperlukan).
- Membuat `requests.Session` persisten yang digunakan bersama oleh semua modul.
- Menerapkan header yang meniru peramban asli: `User-Agent` (Chrome/125), `Accept-Language`, `Accept-Encoding`, `Connection: keep-alive`.
- Menyimpan cookie dari respons *handshake* awal (token tantangan WAF seperti Cloudflare `cf_clearance`, cookie sesi Akamai, dll.) ke dalam sesi secara otomatis untuk permintaan berikutnya.

### **Fase 2 — Fingerprinting Multi-Strategi** (`modules/fingerprint.py`)
*Fingerprinter* menggunakan **5 sumber sinyal independen** dan mengagregasinya di `VersionState` yang aman dari *race condition*:

| Sumber Sinyal | Teknik | Contoh |
|:---|:---|:---|
| **HTTP Header** | Membaca `X-Powered-By: Next.js` | Mendeteksi kehadiran framework |
| **`__NEXT_DATA__`** | Mengurai JSON inline dari tag `<script>` di HTML | Mengekstrak `buildId`, `runtimeConfig` |
| **URL Chunk Statis** | Memindai pola path `/_next/static/<buildId>/` via regex | Mengekstrak Build ID dari URL CDN/Akamai |
| **Bundle Leak** | Mengunduh `/_next/static/chunks/main.js` dan mencari string versi | `"next":"14.2.10"` |
| **Error Page Leak** | Memicu `/_next/data/<random>/404.json` — Next.js mengungkap versi di body error | `"nextVersion":"14.2.10"` |

Sinyal yang dikumpulkan: **versi Next.js**, **Build ID**, **Server Action ID aktif** (dari tag `<script>` atau echo header `Next-Action`).

**Peningkatan**: Menggunakan normalisasi HTML untuk menangani escaped slashes (`\/` menjadi `/`) pada RSC payloads, prioritas pemindaian chunk penting (`framework`, `webpack`, `main`), kedalaman pemindaian hingga 15 chunks, dan peningkatan regex versi minified serta pre-release (`canary`, `rc`).

### **Fase 3 — Matriks Kerentanan Versi**
- Membandingkan versi yang terdeteksi dengan `CVE_DATABASE` di `core/config.py`.
- Menggunakan perbandingan tuple integer (`(14, 2, 10)` vs `(14, 2, 25)`) untuk mengklasifikasikan setiap CVE:
  - `VULNERABLE` — versi terdeteksi di bawah versi *fix*
  - `PATCHED` — versi terdeteksi sama atau di atas versi *fix*
  - `UNKNOWN` — versi tidak dapat ditentukan (memicu *active-probe fallback*)
- Mendukung batas multi-cabang, misalnya: `>= 15.0.0, < 15.5.21 | >= 16.0.0, < 16.2.11`.

### **Fase 4 — Seleksi Modul & Pemeriksaan Prasyarat**
Sebelum menjalankan modul apa pun, framework mengevaluasi **prasyarat** untuk menghindari *false positive* dan permintaan yang tidak perlu:

| Helper Prasyarat | Pemeriksaan | Alasan Lewati jika Gagal |
|:---|:---|:---|
| `has_app_router()` | Memeriksa `/_next/static/chunks/app/` | `NOT_APPLICABLE` untuk CVE App Router |
| `has_active_server_actions()` | Memindai `Next-Action` ID di sumber halaman | Melewati modul bergantung Server Action |
| `has_turbopack()` | Memeriksa header `x-turbopack` atau pola penamaan bundle | Melewati CVE khusus Turbopack |
| `has_ppr()` | Memeriksa diferensial header `Next-Resume: 1` | Melewati modul DoS khusus PPR |
| Cek rentang versi | `check_vuln_status()` terhadap CVE_DATABASE | `NOT_APPLICABLE` jika sudah dipatch |

### **Fase 5 — Eksekusi Pemindaian Aktif / Pasif**

Setiap modul berjalan dalam salah satu dari dua mode:

#### 🔒 Mode Pasif (Default)
- **Deteksi berbasis versi**: Melaporkan `VULNERABLE` berdasarkan rentang versi yang dikonfirmasi, tanpa menyentuh endpoint sensitif.
- **Pemeriksaan struktural**: Mengirim permintaan GET ringan dan tidak merusak untuk mengamati perilaku respons (status HTTP, Content-Type, ukuran body).
- **Modul RSC (5 sub-fase)**:
  1. **Penemuan Endpoint RSC** — Memeriksa path `/_next/static/chunks/`, memindai file *layout* App Router.
  2. **Probe Server Action** — POST dengan header `Next-Action: <id>`; hanya menandai jika `HTTP 200` DAN `size_diff > 500 bytes` dari *baseline* GET (mengabaikan `4xx`, blokir WAF seperti `432`).
  3. **Server Action Multipart** — POST `multipart/form-data` dengan field `$ACTION_ID_0`; hanya menandai pada `HTTP 200`.
  4. **Ekstraksi Data RSC** — Mengambil `/_next/data/<buildId>/*.json`; deteksi soft-404 menyaring respons HTML yang menyamar sebagai 200.
  5. **Prototype Pollution Diferensial** — Mengirim payload `__proto__`; divalidasi menggunakan `core/fp_engine.validate_prototype_pollution()` sebelum ditandai.

#### ⚡ Mode Aktif (perlu `--confirm-active`)
- **Probe OOB SSRF**: Mengirim permintaan dengan header `Host:`, `X-Forwarded-Host:`, atau `Location:` yang dikendalikan penyerang yang mengarah ke URL *collaborator* eksternal.
- **Uji diferensial cache**: Menulis ke path cache CDN bersama — hanya dengan *opt-in* eksplisit untuk menghindari keracunan cache produksi yang tidak disengaja.
- **Probe *timing* intrusif**: Mengirim payload berukuran besar untuk mengukur penundaan respons (analisis kelayakan DoS).

#### Rate Limiting & Penghindaran WAF
- `--rate-limit <N>`: Pembatas *token-bucket* membatasi permintaan keluar per detik di semua modul.
- `--delay <detik>`: Penundaan tetap antar pengiriman probe.
- *Jitter* bawaan: Penundaan acak ±15% ditambahkan pada nilai `--delay` untuk mengurangi deteksi pola WAF.
- Persistensi cookie sesi: Semua respons `Set-Cookie` disimpan dalam sesi bersama dan diputar ulang pada permintaan berikutnya (efektif untuk melewati alur tantangan WAF).

### **Fase 6 — Reduksi False Positive & Skor Confidence**
Setiap objek `Finding` memiliki dua nilai confidence:

| Field | Deskripsi | Rentang |
|:---|:---|:---:|
| `confidence` | Skor yang ditetapkan modul berdasarkan kualitas bukti | `0.0 – 1.0` |
| `computed_confidence` | Skor yang disesuaikan setelah analisis `FP Engine` | `0.0 – 1.0` |

Pemeriksaan FP Engine (`core/fp_engine.py`):
- **Diff hash baseline**: Respons harus berbeda dari *baseline* GET (tidak hanya mengembalikan HTML homepage yang sama).
- **Deteksi soft-404**: Respons yang diawali `<!doctype html>` pada endpoint JSON/RSC dibuang.
- **Tanda tangan blokir WAF**: `432 whaleguard block`, `403 Forbidden` dengan body pendek, tantangan Cloudflare `__cf_chl` — ini dilewati tanpa ditandai.
- **Eksklusi Rute 404**: `HEADER-FUZZER` otomatis mengabaikan rute yang mengembalikan status `404 Not Found` pada baseline, meniadakan temuan false-positive akibat respons prefetch bawaan Next.js pada endpoint non-existent.
- **Rasio noise**: Jika > 80% probe pada satu modul menghasilkan respons anomali yang sama, temuan diturunkan ke `INCONCLUSIVE` (skenario WAF massal seperti CVE-2025-29927 dengan 89% noise).

### **Fase 7 — Pembuatan Laporan** (`core/reporter.py`)
- Laporan disimpan ke `reports/<domain>/scan_<domain>_<timestamp>.json`.
- Skema versi `2.3` dengan 5 nilai status: `VULNERABLE`, `NOT VULNERABLE`, `NOT_APPLICABLE`, `INCONCLUSIVE`, `ERROR`.
- Per-modul: `finding_count`, `noise_ratio`, `total_requests`, objek `Finding` individual dengan dict `evidence` dan skor `confidence`.
- Dump HTTP mentah (request + response) disimpan sebagai `reports/<domain>/raw/<modul>_req_<hash>.txt` untuk tinjauan manual.
- Blok ringkasan: jumlah `vulnerable`, `not_vulnerable`, `not_applicable`, `inconclusive`, `errors`.

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

## 🧪 **Matriks Cakupan CVE (Next.js 15.5.9)**

Berikut status kerentanan untuk target yang menjalankan **Next.js 15.5.9**:

| ID Modul | CVE / ID | Severity | Fix Version | Status di 15.5.9 |
|:---:|:---|:---:|:---:|:---:|
| `59471` | CVE-2025-59471 | MEDIUM | 15.5.10 | ✅ Masih Rentan |
| `23870` | CVE-2026-23870 | HIGH | 15.5.16 | ✅ Masih Rentan |
| `44575` | CVE-2026-44575 | HIGH | 15.5.16 | ✅ Masih Rentan |
| `23864` | CVE-2026-23864 | HIGH | 15.5.10 | ✅ Masih Rentan |
| `mg66` | GHSA-mg66-mrh9-m8jx | HIGH | 15.5.16 | ✅ Masih Rentan |
| `45109` | CVE-2026-45109 | HIGH | 15.5.18 | ✅ Masih Rentan |

```bash
# Pindai semua CVE yang relevan untuk Next.js 15.5.9
python nextsploit.py -t https://target.com --cve 59471,23870,44575,23864,mg66,45109 -v
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

