import { safeFetch, resolveAndValidateSSRF } from "../security/ssrf";
import { SeverityLevel } from "../../types/database";

export interface ExposedFileFinding {
  tool: string;
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  description: string;
  evidence: string;
  remediation: string;
}

// Daftar path file sensitif yang sering terekspos secara tidak sengaja
const SENSITIVE_PATHS = [
  {
    path: "/.env",
    rule_id: "exposed-env-file",
    title: "File Environment (.env) Dapat Diakses Publik",
    severity: "critical" as SeverityLevel,
    signature: ["DB_", "DATABASE_", "SECRET", "API_KEY", "PASSWORD", "SUPABASE_"],
    remediation:
      "Segera hapus file .env dari public root web server dan konfigurasikan web server (Nginx/Apache) untuk memblokir akses ke semua file yang diawali titik (dotfiles).",
  },
  {
    path: "/.git/HEAD",
    rule_id: "exposed-git-repository",
    title: "Repositori Git (.git) Terekspos ke Publik",
    severity: "high" as SeverityLevel,
    signature: ["ref: refs/", "ref:"],
    remediation:
      "Blokir akses publik ke folder /.git/ pada konfigurasi web server Anda. Siapa pun dapat mengunduh seluruh source code aplikasi jika folder ini terbuka.",
  },
  {
    path: "/.git/config",
    rule_id: "exposed-git-config",
    title: "File Konfigurasi Git (.git/config) Terekspos",
    severity: "high" as SeverityLevel,
    signature: ["[core]", "[remote"],
    remediation: "Blokir seluruh akses ke direktori /.git/ pada konfigurasi web server.",
  },
  {
    path: "/backup.zip",
    rule_id: "exposed-backup-archive",
    title: "File Arsip Backup (.zip) Dapat Diunduh Publik",
    severity: "high" as SeverityLevel,
    signature: ["PK\x03\x04"], // Zip header magic bytes
    remediation:
      "Pindahkan file arsip backup ke luar direktori root web atau simpan di storage privat yang terotentikasi.",
  },
  {
    path: "/backup.sql",
    rule_id: "exposed-database-backup-sql",
    title: "Dump Database SQL (.sql) Terekspos Publik",
    severity: "critical" as SeverityLevel,
    signature: ["INSERT INTO", "CREATE TABLE", "-- MySQL dump", "-- PostgreSQL database dump"],
    remediation:
      "Hapus file dump database dari web root dan ganti semua kredensial yang kemungkinan telah terekspos.",
  },
  {
    path: "/database.sql",
    rule_id: "exposed-database-sql",
    title: "File Database SQL (database.sql) Terekspos Publik",
    severity: "critical" as SeverityLevel,
    signature: ["INSERT INTO", "CREATE TABLE", "-- MySQL dump"],
    remediation: "Hapus file database.sql dari folder publik web server.",
  },
  {
    path: "/.DS_Store",
    rule_id: "exposed-ds-store-file",
    title: "File Metadata macOS (.DS_Store) Terekspos",
    severity: "low" as SeverityLevel,
    signature: ["\x00\x00\x00\x01Bud1"],
    remediation: "Hapus file .DS_Store dan tambahkan konfigurasi web server untuk memblokir akses ke file .DS_Store.",
  },
];

/**
 * Memeriksa eksposur file sensitif secara pasif & non-destruktif dengan safeFetch
 */
export async function checkExposedFiles(hostname: string): Promise<ExposedFileFinding[]> {
  const findings: ExposedFileFinding[] = [];

  for (const item of SENSITIVE_PATHS) {
    const targetUrl = `https://${hostname}${item.path}`;

    try {
      const res = await safeFetch(targetUrl, {
        timeoutMs: 5000,
        maxSizeBytes: 20 * 1024, // Max 20KB
      });

      if (res.ok && res.status === 200 && res.text) {
        // Cek apakah respons mengandung signature atau format file yang dicurigai
        const bodyContent = res.text;
        const matchesSignature = item.signature.some((sig) => bodyContent.includes(sig));

        // Hindari false positive: abaikan jika mengembalikan HTML (misal custom 404 page yang return 200)
        const isHtmlPage =
          bodyContent.toLowerCase().includes("<!doctype html") ||
          bodyContent.toLowerCase().includes("<html");

        if (matchesSignature && !isHtmlPage) {
          // Mask / samarkan nilai evidence jika ada kemungkinan rahasia
          const safeEvidence = bodyContent
            .slice(0, 300)
            .replace(/(password|secret|key|token)=([^\s\n]+)/gi, "$1=********");

          findings.push({
            tool: "custom-file-exposure",
            rule_id: item.rule_id,
            title: item.title,
            severity: item.severity,
            description: `File sensitif ditemukan di ${targetUrl} dan dapat diakses tanpa autentikasi.`,
            evidence: `URL: ${targetUrl}\nPotongan Respons:\n${safeEvidence}`,
            remediation: item.remediation,
          });
        }
      }
    } catch {
      // Abaikan error koneksi individual
    }
  }

  return findings;
}
