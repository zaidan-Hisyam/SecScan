# Spesifikasi & Prompt Master: Web Pemindai Keamanan Pribadi

## 1. Ringkasan, tujuan, dan batasan

Proyek ini adalah web pribadi untuk memindai celah keamanan situs milik sendiri secara otomatis: masukkan URL, sistem menjalankan pemeriksaan non-destruktif, lalu menampilkan laporan temuan berikut saran perbaikannya. Targetnya versi kecil yang bisa selesai sendirian, bukan SaaS penuh.

**Tujuan**

- Memeriksa web milikmu secara berkala dan mendapat laporan yang mudah dibaca.
- Bisa dipakai teman: kamu yang menjalankan pengecekan, hasilnya dikirim sebagai laporan.
- Biaya hampir nol (Vercel, Supabase, GitHub Actions di free tier).

**Di luar cakupan (sengaja ditunda)**

- Pendaftaran publik, billing, dan multi-tenant penuh.
- Scan aktif agresif (fuzzing, brute force, uji beban).
- OWASP ZAP penuh. Ditambahkan nanti, bila ada waktu.

**Aturan penggunaan (wajib, masuk ke kode)**

1. Hanya memindai domain milikmu atau domain teman yang memberi izin tertulis (cukup pesan chat yang disimpan).
2. Setiap domain harus berstatus *terverifikasi* (token DNS TXT atau file token) sebelum bisa dipindai.
3. Hanya pemeriksaan pasif dan ringan. Tidak ada eksploitasi dan tidak ada perubahan data di target.
4. Hasil scan bersifat rahasia: hanya pemilik domain yang boleh melihat laporannya.
5. Semua scan dicatat (siapa, domain apa, kapan).

## 2. Arsitektur dan tech stack

Vercel menampung dashboard dan API ringan, Supabase menyimpan data, dan GitHub Actions menjalankan scan, karena Vercel tidak cocok menjalankan Nuclei atau testssl.sh (batas waktu singkat, tanpa proses panjang).

| Komponen | Teknologi | Peran |
| --- | --- | --- |
| Frontend + API | Next.js (TypeScript) di Vercel | Form URL, dashboard, halaman laporan, endpoint pemicu scan |
| Database + auth | Supabase (PostgreSQL + Auth + RLS) | Pengguna, domain, scan, temuan |
| Worker scan | GitHub Actions (workflow dipicu API) | Menjalankan Nuclei, testssl.sh, dan pengecekan buatan sendiri di lingkungan sekali pakai |
| Scanner inti | Nuclei dengan template terpilih | Misconfiguration, file terekspos, deteksi teknologi dan versi |
| Scanner TLS | testssl.sh (output JSON) | Protokol usang, cipher lemah, masa berlaku sertifikat |
| Pengecekan buatan sendiri | Skrip Node/Python kecil | Security headers, cookie flags, file sensitif (.env, .git) |
| Penyimpanan rahasia | Environment variable Vercel dan GitHub Secrets | Token GitHub, service key Supabase |

**Catatan penting**

- Worker mengirim hasil ke Supabase lewat endpoint API yang dilindungi secret (webhook), bukan lewat kunci database di frontend.
- Kuota gratis GitHub Actions dan Vercel terbatas dan bisa berubah. Cek ketentuan terbarunya sebelum mulai.
- ZAP baseline (pasif) ditambahkan di fase akhir sebagai langkah tambahan di workflow yang sama.

## 3. Fitur MVP dan daftar pemeriksaan

MVP cukup lima fitur: login, daftar domain terverifikasi, tombol scan, daftar riwayat scan, dan halaman laporan per scan dengan saran perbaikan.

**Pemeriksaan yang masuk MVP (semuanya pasif dan non-destruktif)**

| Kategori | Yang diperiksa | Tool | Tingkat keparahan umum |
| --- | --- | --- | --- |
| Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | Skrip sendiri | Rendah sampai Sedang |
| Cookie | Flag Secure, HttpOnly, SameSite pada cookie sesi | Skrip sendiri | Sedang |
| TLS/SSL | Versi protokol usang, cipher lemah, sertifikat kedaluwarsa atau hampir kedaluwarsa, redirect HTTP ke HTTPS | testssl.sh | Sedang sampai Tinggi |
| File terekspos | .env, .git, backup (.zip, .bak, .sql), direktori listing, file konfigurasi | Nuclei + skrip sendiri | Tinggi sampai Kritis |
| Misconfiguration | Panel admin terbuka, halaman debug, banner versi server | Nuclei (template exposures dan misconfiguration) | Sedang sampai Tinggi |
| Deteksi teknologi | Framework, CMS, dan versi yang terlihat, dicocokkan dengan CVE yang dikenal | Nuclei (template technologies) | Informasi sampai Tinggi |
| CORS | Wildcard origin dengan credentials, origin refleksif | Skrip sendiri | Sedang sampai Tinggi |

**Skala tingkat keparahan:** Info, Rendah, Sedang, Tinggi, Kritis. Setiap temuan wajib punya tingkat ini.

**Ditunda sampai fase lanjutan:** ZAP baseline, pemeriksaan XSS dan SQLi aktif, pemindaian port, crawling dalam, dan scan terautentikasi (login). Semua ini lebih berat, lebih berisik, dan lebih berisiko bagi target.

## 4. Database dan format temuan

Empat tabel sudah cukup: profil pengguna, domain, scan, dan temuan. Row Level Security (RLS) aktif di semua tabel supaya setiap pengguna hanya melihat datanya sendiri.

| Tabel | Kolom utama | Catatan |
| --- | --- | --- |
| profiles | id (sama dengan auth.users.id), email, created\_at | Dibuat otomatis saat pendaftaran |
| domains | id, owner\_id, hostname, verify\_token, verified (boolean), verified\_at, created\_at | Scan hanya boleh jika verified = true |
| scans | id, domain\_id, status (queued, running, done, failed), started\_at, finished\_at, summary (jsonb), triggered\_by | Satu baris per eksekusi scan |
| findings | id, scan\_id, tool, rule\_id, title, severity, description, evidence, remediation, created\_at | Format seragam untuk semua tool |

**Aturan RLS**

- Pengguna hanya bisa membaca dan mengubah baris yang owner\_id-nya sama dengan auth.uid(). Untuk scans dan findings, kepemilikan dicek lewat domains.
- Penulisan hasil scan oleh worker memakai service key di sisi server saja, tidak pernah di frontend.

**Format temuan seragam (JSON)**

Setiap parser tool wajib mengubah outputnya ke bentuk ini sebelum disimpan:

```json
{
  "tool": "nuclei",
  "rule_id": "exposed-env-file",
  "title": "File .env dapat diakses publik",
  "severity": "critical",
  "description": "Penjelasan singkat masalahnya dalam bahasa sederhana.",
  "evidence": "URL atau potongan respons yang membuktikan temuan.",
  "remediation": "Langkah konkret untuk memperbaikinya."
}
```

Temuan duplikat (tool berbeda, masalah sama) digabung berdasarkan kombinasi rule\_id dan lokasi (URL). Evidence dipotong dan nilai rahasia disamarkan sebelum disimpan.

## 5. Alur scan dan persyaratan keamanan

Satu scan melewati delapan langkah, dan langkah pengecekan verifikasi domain tidak boleh dilewati di titik mana pun.

**Alur scan end-to-end**

1. Pengguna login dan menambahkan hostname. Sistem membuat verify\_token.
2. Pengguna memasang token (TXT record DNS atau file di path yang ditentukan), lalu menekan Verifikasi.
3. Server mengecek token. Jika cocok, domains.verified = true.
4. Pengguna menekan Scan. API memeriksa: pengguna login, domain miliknya, domain terverifikasi, dan batas frekuensi belum terlampaui.
5. API membuat baris scans berstatus queued lalu memicu workflow GitHub Actions dengan scan\_id dan hostname.
6. Workflow menjalankan pengecekan buatan sendiri, testssl.sh, dan Nuclei, lalu menormalkan semua hasil ke format temuan seragam.
7. Workflow mengirim hasil ke endpoint webhook API (ditandatangani secret). API menyimpan findings dan menandai scan done atau failed.
8. Dashboard menampilkan laporan: ringkasan jumlah temuan per tingkat keparahan, lalu daftar temuan beserta saran perbaikan.

**Persyaratan keamanan (wajib)**

- **Verifikasi kepemilikan:** scan ditolak oleh API dan oleh workflow bila domain belum terverifikasi. Cek dilakukan dua kali.
- **Anti-SSRF:** hostname di-resolve dulu. Tolak IP privat, loopback, link-local, dan alamat metadata cloud. Cek ulang setelah redirect.
- **Rate limit:** batasi jumlah scan per pengguna per hari dan per domain per jam. Batasi juga request per detik ke target.
- **Non-destruktif:** hanya metode GET/HEAD/OPTIONS. Tidak ada payload eksploitasi.
- **Timeout:** batas waktu keseluruhan per scan, dan job dihentikan bila terlampaui.
- **Rahasia:** semua secret hanya di environment variable server atau GitHub Secrets. Tidak pernah di kode klien atau repo.
- **Validasi input:** hostname divalidasi ketat (huruf, angka, titik, tanda hubung). Tidak pernah disusun mentah ke dalam perintah shell.
- **Audit log:** catat siapa, domain apa, kapan, dan hasil akhirnya.
- **Privasi hasil:** laporan hanya bisa dibuka pemilik domain (RLS). Tautan berbagi publik tidak ada di MVP.

## 6. Rencana pengerjaan dan pengujian

Kerjakan enam fase berurutan. Tiap fase harus lolos pengujiannya sebelum lanjut, supaya selalu ada versi yang berfungsi.

1. **Fondasi:** proyek Next.js, Supabase (tabel, RLS, auth), login.
   - [ ] Pengguna A tidak bisa melihat data pengguna B (uji RLS)
2. **Domain dan verifikasi:** tambah domain, buat token, verifikasi DNS atau file.
   - [ ] Scan ditolak untuk domain yang belum terverifikasi
3. **Scan pertama tanpa worker:** pengecekan security headers, cookie, dan redirect HTTPS langsung di API, dengan perlindungan anti-SSRF dan rate limit.
   - [ ] Alamat IP privat dan localhost ditolak
4. **Worker GitHub Actions:** pindahkan eksekusi ke workflow, kirim hasil lewat webhook, tambahkan testssl.sh dan pengecekan file terekspos.
   - [ ] Webhook tanpa secret yang benar ditolak
5. **Nuclei:** tambahkan template terpilih (exposures, misconfiguration, technologies), parser ke format temuan seragam, dan penggabungan duplikat.
   - [ ] Scan ke aplikasi sengaja-rentan (OWASP Juice Shop atau DVWA lokal) menghasilkan temuan yang diharapkan
6. **Laporan dan penyempurnaan:** halaman laporan, ringkasan per tingkat keparahan, saran perbaikan, ekspor PDF atau cetak, riwayat scan.
   - [ ] Laporan terbaca jelas oleh orang non-teknis

**Checklist sebelum dipakai di web nyata**

- [ ] Semua secret ada di environment variable, tidak ada di repo
- [ ] RLS aktif di semua tabel dan sudah diuji
- [ ] Rate limit dan timeout berfungsi
- [ ] Uji ke target uji lokal dulu, baru ke webmu sendiri
- [ ] Untuk web teman: simpan bukti izin tertulis dan verifikasi domain tetap dilakukan

**Fase lanjutan (kalau ada waktu):** ZAP baseline, notifikasi (Telegram atau email) bila ada temuan baru, penjadwalan scan berkala, dan pendaftaran untuk teman.

