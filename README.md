# SecScan Lab - Platform Pemindai Keamanan Web Pribadi

SecScan Lab adalah platform audit keamanan web otomatis berbasis Next.js dan Supabase yang dirancang khusus untuk memindai kerentanan situs milik sendiri atau klien/teman yang telah memberikan izin resmi. Pemindaian dilakukan secara **pasif, ringan, dan non-destruktif**, tanpa risiko merusak stabilitas server target.

---

## DAFTAR ISI
1. [Tech Stack & Arsitektur](#1-tech-stack--arsitektur)
2. [Cakupan Pemeriksaan Keamanan](#2-cakupan-pemeriksaan-keamanan)
3. [Fitur Utama & Keamanan Arsitektur](#3-fitur-utama--keamanan-arsitektur)
4. [Instalasi & Menjalankan Proyek Lokal](#4-instalasi--menjalankan-proyek-lokal)
5. [Panduan Penggunaan Lengkap](#5-panduan-penggunaan-lengkap)
6. [Konfigurasi Environment Variable & Secret](#6-konfigurasi-environment-variable--secret)
7. [Deploy ke Vercel & GitHub Actions Worker](#7-deploy-ke-vercel--github-actions-worker)
8. [Panduan Pengujian Otomatis](#8-panduan-pengujian-otomatis)
9. [Struktur Direktori Proyek](#9-struktur-direktori-proyek)

---

## 1. TECH STACK & ARSITEKTUR

Platform ini dibangun di atas arsitektur serverless modern yang sepenuhnya memanfaatkan free tier:

- **Frontend & API**: [Next.js 15+ (App Router, TypeScript)](https://nextjs.org/) dengan styling Tailwind CSS bergaya dark cyberpunk-lab.
- **Basis Data & Autentikasi**: [Supabase](https://supabase.com/) (PostgreSQL dengan Row Level Security aktif, Supabase Auth, SSR Session Cookie).
- **Background Worker**: [GitHub Actions](https://github.com/features/actions) dipicu via `workflow_dispatch` API dengan integritas HMAC SHA-256 Webhook.
- **Scanner Engine**:
  - Custom Passive Security Scanner (Node.js/TypeScript).
  - Custom Sensitive File Exposure Engine.
  - [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) (Template pasif pilihan: exposures, misconfiguration, technologies).
  - [testssl.sh](https://testssl.sh/) (Audit SSL/TLS cipher suites & protokol kriptografi).
- **Icons & UI**: [Lucide React](https://lucide.dev/), Tailwind CSS, Glassmorphism backdrop filter.

---

## 2. CAKUPAN PEMERIKSAAN KEAMANAN

Setiap temuan dinormalkan ke dalam format seragam dengan skala keparahan: **Kritis (Critical), Tinggi (High), Sedang (Medium), Rendah (Low), dan Info**.

### A. Security Headers (Keamanan Header HTTP)
- **HSTS (HTTP Strict Transport Security)**: Memastikan header `Strict-Transport-Security` terpasang guna mencegah serangan SSL Stripping dan downgrade HTTP.
- **CSP (Content Security Policy)**: Memeriksa pembatasan sumber daya eksternal untuk memitigasi Cross-Site Scripting (XSS) dan data injection.
- **Clickjacking Protection**: Memeriksa keberadaan header `X-Frame-Options: SAMEORIGIN` atau direktif CSP `frame-ancestors`.
- **MIME-Sniffing**: Memeriksa header `X-Content-Type-Options: nosniff`.
- **Referrer-Policy**: Memeriksa kebocoran path dan query parameter sensitif ke domain pihak ketiga.
- **Permissions-Policy**: Mengontrol hak akses API browser (kamera, mikrofon, geolokasi).

### B. Cookie Flags (Keamanan Sesi & Cookie)
- **Secure Flag**: Memastikan cookie hanya ditransmisikan melalui kanal terenkripsi HTTPS.
- **HttpOnly Flag**: Mencegah akses cookie sesi dari JavaScript browser (`document.cookie`) untuk melindungi dari pencurian sesi via XSS.
- **SameSite Flag**: Memastikan proteksi terhadap serangan Cross-Site Request Forgery (CSRF) via konfigurasi `SameSite=Lax` atau `SameSite=Strict`.

### C. SSL / TLS & Kriptografi
- **Enforced HTTPS Redirect**: Memastikan port 80 (HTTP) secara otomatis dialihkan (301 Permanent Redirect) ke port 443 (HTTPS).
- **Protokol Usang**: Mendeteksi protokol rentan yang masih aktif (SSLv2, SSLv3, TLS 1.0, TLS 1.1).
- **Kerentanan TLS Terkenal**: Heartbleed, POODLE, ROBOT, SWEET32, dsb.
- **Validitas Sertifikat**: Masa berlaku dan tanggal kedaluwarsa sertifikat SSL/TLS.

### D. File Sensitif & Source Code Terekspos (Exposures)
- **Environment Files**: `/.env`, `/.env.local`, `/.env.production` (kredensial database, API keys).
- **Git Repositories**: `/.git/HEAD`, `/.git/config` (pencegahan kebocoran repositori source code).
- **Database Dump**: `/backup.sql`, `/database.sql`, `/dump.sql` (struktur dan data database).
- **Arsip Backup**: `/backup.zip`, `/site.tar.gz`.
- **Metadata OS**: `/.DS_Store` (struktur direktori internal).

### E. Miskonfigurasi CORS (Cross-Origin Resource Sharing)
- **Wildcard Origin dengan Credentials**: `Access-Control-Allow-Origin: *` bersamaan dengan `Access-Control-Allow-Credentials: true`.
- **Origin Reflection**: Server memantulkan (reflect) sembarang header `Origin` penyerang tanpa validasi whitelist.

### F. Deteksi Teknologi & Versi (Technologies)
- Deteksi framework, CMS, web server (Nginx/Apache), dan versi yang terekspos ke publik guna meminimalkan pengintaian (*reconnaissance*).

---

## 3. FITUR UTAMA & KEAMANAN ARSITEKTUR

1. **Row Level Security (RLS) PostgreSQL**:
   - Seluruh tabel (`profiles`, `domains`, `scans`, `findings`) dilindungi kebijakan RLS ketat.
   - Pengguna A **tidak akan pernah bisa** melihat atau menyisipkan scan ke domain milik Pengguna B.
2. **Proteksi Anti-SSRF & DNS Rebinding**:
   - Menolak pemindaian ke IP privat (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.1, ::1), link-local, cloud instance metadata (169.254.169.254), dan CGNAT (100.64.0.0/10).
   - Validasi Anti-SSRF dievaluasi ulang pada setiap tahapan *redirect hop*.
3. **Integritas Webhook HMAC SHA-256**:
   - Pengiriman data temuan dari worker diverifikasi menggunakan signature kriptografis dan `crypto.timingSafeEqual` (anti timing-attack).
4. **Anti Command Injection**:
   - Eksekusi biner scanner eksternal menggunakan `execFile` berbasis *array arguments* tanpa perangkaian string mentah (*no shell string concatenation*).
5. **Penyembunyian Data Rahasia (Evidence Sanitization)**:
   - Nilai token, password, dan secret pada teks bukti temuan disamarkan secara otomatis (`$1=********`) sebelum disimpan ke database.
6. **Laporan Audit Interaktif & Siap Cetak (PDF)**:
   - Filter instan berdasarkan keparahan (Critical, High, Medium, Low, Info), pencarian teks real-time, pengurutan, saran perbaikan bahasa Indonesia, serta format cetak bebas noise.

---

## 4. INSTALASI & MENJALANKAN PROYEK LOKAL

### Persyaratan Sistem:
- Node.js versi 18.x atau 20.x+
- NPM atau PNPM
- Akun Supabase (Free Tier)

### Langkah-langkah Instalasi:

1. **Clone Repositori & Masuk ke Folder Proyek**:
   ```bash
   cd D:/ZAIDAN/Project/PenTest
   ```

2. **Instal Dependensi**:
   ```bash
   npm install
   ```

3. **Konfigurasi Environment Variable Lokal**:
   Buat file `.env.local` di root folder proyek:
   ```env
   NEXT_PUBLIC_SUPABASE_URL=https://<your-project-ref>.supabase.co
   NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbG...
   SUPABASE_SERVICE_ROLE_KEY=eyJhbG...
   SCAN_WEBHOOK_SECRET=masukkan_string_acak_panjang_disini
   ```

4. **Jalankan Migrasi Database ke Supabase**:
   Salin isi file `supabase/migrations/20261009000000_phase1_foundation.sql` dan jalankan di menu **SQL Editor** pada dashboard web Supabase Anda.

5. **Buat Akun Admin Pertama**:
   Jalankan skrip pembuat akun admin otomatis:
   ```bash
   npx ts-node --compiler-options '{"module":"commonjs"}' scripts/create-admin.ts
   ```
   *Kredensial Default:*
   - **Email**: `admin@secscan.lab`
   - **Password**: `AdminSecScan2026!`

6. **Jalankan Aplikasi Web**:
   ```bash
   npm run dev
   ```
   Buka peramban di **`http://localhost:3000`**.

---

## 5. PANDUAN PENGGUNAAN LENGKAP

### Langkah 1: Autentikasi / Login
1. Buka `http://localhost:3000/login`.
2. Masukkan email dan password akun Anda (atau daftar via menu `/register`).
3. Sistem akan membuat sesi terenkripsi dan mengarahkan Anda ke Dashboard.

### Langkah 2: Menambahkan Domain Target
1. Pada Dashboard, klik tombol **"+ Tambah Domain"**.
2. Masukkan nama host situs (contoh: `example.com` atau `app.mysite.id`).
3. Klik **"Simpan Domain"**. Domain akan tersimpan di akun Anda dan siap untuk dipindai.

### Langkah 3: Menjalankan Pemindaian Keamanan
1. Cari baris domain yang ingin diuji pada tabel domain.
2. Klik tombol hijau **"Mulai Scan"**.
3. Sistem menjalankan pengecekan pasif, headers, cookies, CORS, dan exposed files secara real-time.
4. Dalam 1–3 detik, pemindaian selesai dan browser akan otomatis dialihkan ke halaman Laporan Audit Keamanan (`/scans/<scan_id>`).

### Langkah 4: Membaca & Menganalisis Laporan Temuan
1. **Ringkasan Metrik**: Lihat jumlah temuan pada pill status (Kritis, Tinggi, Sedang, Rendah, Info). Klik pill untuk memfilter daftar temuan secara langsung.
2. **Pencarian**: Gunakan kotak pencarian untuk mencari kata kunci (misal: `hsts`, `cookie`, `env`, `git`).
3. **Detail Temuan**:
   - **Deskripsi**: Penjelasan masalah dalam konteks keamanan aplikasi.
   - **Bukti Temuan (Evidence)**: Potongan header respons atau URL endpoint tempat kerentanan ditemukan (nilai rahasia otomatis disamarkan).
   - **Saran Perbaikan (Remediation)**: Panduan langkah konkret dalam bahasa Indonesia untuk menambal celah tersebut.
4. **Riwayat Scan**: Bagian bawah halaman menampilkan perbandingan hasil scan terdahulu pada domain yang sama.

### Langkah 5: Mencetak atau Mengekspor Laporan ke PDF
1. Klik tombol **"Cetak / Ekspor PDF"** di pojok kanan atas halaman laporan.
2. Dialog print browser akan terbuka dengan format layout bersih (latar putih, font kontras tinggi, tombol dan navbar disembunyikan otomatis).
3. Pilih opsi **"Save as PDF"** / **"Simpan sebagai PDF"**.

---

## 6. KONFIGURASI ENVIRONMENT VARIABLE & SECRET

| Nama Variabel | Lokasi | Keterangan |
|---|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | Vercel & GitHub Actions | URL endpoint project Supabase (`https://xxx.supabase.co`) |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Vercel & Frontend | Kunci API publik anon Supabase untuk otentikasi browser |
| `SUPABASE_SERVICE_ROLE_KEY` | Vercel & GitHub Actions | Kunci server rahasia untuk worker dan backend webhook |
| `SCAN_WEBHOOK_SECRET` | Vercel & GitHub Actions | Kunci rahasia bersama untuk validasi signature HMAC SHA-256 |
| `SCAN_WEBHOOK_URL` | GitHub Actions Secrets | URL webhook produksi (misal: `https://app.vercel.app/api/webhooks/scan-results`) |
| `GITHUB_TOKEN` | Vercel Environment | Personal Access Token (PAT) GitHub dengan scope `repo` & `workflow` |
| `GITHUB_REPO_OWNER` | Vercel Environment | Username atau organisasi pemilik repository GitHub |
| `GITHUB_REPO_NAME` | Vercel Environment | Nama repository project |
| `GITHUB_WORKFLOW_FILE` | Vercel Environment | Nama file workflow (`security-scan.yml`) |
| `GITHUB_BRANCH_REF` | Vercel Environment | Branch default (`main`) |

---

## 7. DEPLOY KE VERCEL & GITHUB ACTIONS WORKER

1. **Push Proyek ke GitHub**:
   ```bash
   git add .
   git commit -m "feat: complete SecScan Lab platform"
   git push origin main
   ```

2. **Deploy Frontend & API ke Vercel**:
   - Hubungkan repository GitHub ke Vercel Dashboard.
   - Isi seluruh Environment Variables sesuai tabel pada Bagian 6.
   - Klik **Deploy**.

3. **Konfigurasi GitHub Actions Worker**:
   - Buka menu **Settings** pada repository GitHub Anda ➔ **Secrets and variables** ➔ **Actions**.
   - Tambahkan Secrets:
     - `NEXT_PUBLIC_SUPABASE_URL`
     - `SUPABASE_SERVICE_ROLE_KEY`
     - `SCAN_WEBHOOK_URL` (contoh: `https://nama-project-anda.vercel.app/api/webhooks/scan-results`)
     - `SCAN_WEBHOOK_SECRET` (string sama persis dengan yang ada di Vercel)

---

## 8. PANDUAN PENGUJIAN OTOMATIS

Proyek ini telah dilengkapi dengan rangkaian automated test script mandiri:

1. **Uji Isolasi Row Level Security (RLS)**:
   ```bash
   npx ts-node --compiler-options '{"module":"commonjs"}' scripts/test-rls.ts
   ```
   *Memvalidasi bahwa Pengguna B tidak dapat membaca atau memodifikasi data domain/scan milik Pengguna A.*

2. **Uji Validasi Hostname, Anti-SSRF & DNS Challenge (Fase 2)**:
   ```bash
   npx ts-node --compiler-options '{"module":"commonjs"}' scripts/test-phase2.ts
   ```

3. **Uji Scanner Pasif, Headers, Cookie, Rate Limit & DB (Fase 3)**:
   ```bash
   npx ts-node --compiler-options '{"module":"commonjs"}' scripts/test-phase3.ts
   ```

4. **Uji Webhook HMAC Signature & Testssl Parser (Fase 4)**:
   ```bash
   npx ts-node --compiler-options '{"module":"commonjs"}' scripts/test-phase4.ts
   ```

5. **Uji Nuclei JSON Parser & Deduplikasi Temuan (Fase 5)**:
   ```bash
   npx ts-node --compiler-options '{"module":"commonjs"}' scripts/test-phase5.ts
   ```

6. **Verifikasi Build Next.js Production**:
   ```bash
   npm run build
   ```

---

## 9. STRUKTUR DIREKTORI PROYEK

```text
PenTest/
├── .github/
│   └── workflows/
│       └── security-scan.yml       # GitHub Actions workflow runner
├── scripts/
│   ├── worker-runner.js            # Worker script mandiri untuk scan mendalam
│   ├── create-admin.ts             # Skrip instan pembuatan akun admin
│   ├── auto-verify-domains.ts      # Skrip verifikasi domain massal
│   ├── test-rls.ts                 # Test suite RLS Supabase
│   ├── test-phase2.ts              # Test suite validasi domain & anti-SSRF
│   ├── test-phase3.ts              # Test suite scanner pasif & rate limiter
│   ├── test-phase4.ts              # Test suite webhook HMAC & testssl
│   └── test-phase5.ts              # Test suite Nuclei & deduplikasi
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── domains/            # API manajemen & verifikasi domain
│   │   │   ├── scans/              # API trigger scan & histori
│   │   │   └── webhooks/           # API penerima webhook worker terenkripsi
│   │   ├── dashboard/              # Halaman control center pengguna
│   │   ├── scans/[id]/             # Halaman laporan audit keamanan & cetak PDF
│   │   ├── login/ & register/      # Halaman autentikasi akun
│   │   ├── globals.css             # Tema cyberpunk-lab & stylesheet print PDF
│   │   ├── layout.tsx & page.tsx   # Root layout & landing page portal
│   │   └── middleware.ts           # Route guard session Supabase
│   ├── components/
│   │   ├── auth/                   # Komponen LogoutButton, dll.
│   │   ├── domains/                # DomainManager, AddDomainModal, VerificationModal
│   │   └── scans/                  # ScanReportClient (filter, sort, search, print)
│   ├── lib/
│   │   ├── domain/                 # Engine verifikasi DNS TXT & file token
│   │   ├── github/                 # Modul workflow_dispatch GitHub API
│   │   ├── scanner/                # Passive scanner, file exposure, Nuclei/testssl parser, deduplikasi
│   │   ├── security/               # Anti-SSRF, safeFetch, rate-limit, HMAC signature
│   │   └── supabase/               # Klien Supabase browser, server, admin, & middleware
│   └── types/
│       └── database.ts             # Definisi tipe data TypeScript database & findings
├── supabase/
│   └── migrations/
│       └── 20261009000000_phase1_foundation.sql # Skema SQL tabel & kebijakan RLS
├── .env.example                    # Template variabel lingkungan
├── package.json                    # Konfigurasi dependensi proyek
├── README.md                       # Dokumentasi resmi & panduan penggunaan
└── tsconfig.json                   # Konfigurasi TypeScript
```

---

## 10. ETIKA PENGGUNAAN & DISCLAIMER
Aplikasi ini ditujukan murni untuk keperluan audit keamanan preventif pada infrastruktur milik sendiri atau pihak yang telah memberikan persetujuan tertulis resmi. Pengembang tidak bertanggung jawab atas penyalahgunaan alat ini terhadap target tanpa izin sah.
