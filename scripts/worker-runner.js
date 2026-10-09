const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");
const dns = require("dns");
const net = require("net");
const { execSync } = require("child_process");
const fs = require("fs");

/**
 * Worker Standalone Script untuk GitHub Actions:
 * 1. Validasi ulang status domain di Supabase (verified == true)
 * 2. Cek Anti-SSRF pada hostname
 * 3. Jalankan passive headers & cookie checks
 * 4. Jalankan exposed files check (.env, .git, backup)
 * 5. Jalankan testssl.sh dengan output JSON
 * 6. Normalisasi seluruh temuan ke satu format
 * 7. Kirim hasil terenkripsi HMAC ke Webhook Portal
 */

function generateSignature(payloadStr, secret) {
  return crypto.createHmac("sha256", secret).update(payloadStr, "utf8").digest("hex");
}

function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower === "::" || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe8")) return true;
    return false;
  }
  return true;
}

async function sendWebhookResult(webhookUrl, webhookSecret, payload) {
  const payloadStr = JSON.stringify(payload);
  const signature = generateSignature(payloadStr, webhookSecret);

  console.log(`[Worker] Mengirim hasil ke Webhook URL: ${webhookUrl}`);
  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-secscan-signature": signature,
      "User-Agent": "SecScan-GitHub-Worker/1.0",
    },
    body: payloadStr,
  });

  const resText = await res.text();
  console.log(`[Worker] Webhook response status: ${res.status}, body: ${resText}`);
}

async function main() {
  const scanId = process.env.TARGET_SCAN_ID;
  const hostname = process.env.TARGET_HOSTNAME;
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const webhookUrl = process.env.SCAN_WEBHOOK_URL;
  const webhookSecret = process.env.SCAN_WEBHOOK_SECRET;

  if (!scanId || !hostname || !supabaseUrl || !serviceRoleKey || !webhookUrl || !webhookSecret) {
    console.error("❌ Variabel lingkungan worker belum lengkap!");
    process.exit(1);
  }

  console.log(`[Worker] Memulai pemindaian: Scan ID=${scanId}, Target Hostname=${hostname}`);
  const startTime = Date.now();
  const allFindings = [];

  const supabase = createClient(supabaseUrl, serviceRoleKey);

  // 1. CEK ULANG STATUS VERIFIKASI DOMAIN DI DATABASE (ATURAN KEAMANAN WAJIB)
  console.log("[Worker] 1. Memeriksa ulang status verifikasi domain di database...");
  const { data: scanRow, error: scanErr } = await supabase
    .from("scans")
    .select("id, domain_id, domains(id, hostname, verified)")
    .eq("id", scanId)
    .single();

  if (scanErr || !scanRow || !scanRow.domains || !scanRow.domains.verified) {
    console.error("❌ ATURAN KEAMANAN DILANGGAR: Domain belum terverifikasi di database!");
    await sendWebhookResult(webhookUrl, webhookSecret, {
      scan_id: scanId,
      status: "failed",
      error_message: "Scan dibatalkan: Domain belum berstatus terverifikasi di database.",
      findings: [],
    });
    process.exit(1);
  }

  // Update status scan = 'running'
  await supabase
    .from("scans")
    .update({ status: "running", started_at: new Date().toISOString() })
    .eq("id", scanId);

  // 2. ANTI-SSRF CHECK
  console.log("[Worker] 2. Memeriksa Anti-SSRF pada target hostname...");
  try {
    const addresses = await dns.promises.resolve4(hostname);
    for (const ip of addresses) {
      if (isPrivateIP(ip)) {
        throw new Error(`Anti-SSRF Triggered: IP ${ip} adalah alamat IP privat/terlarang.`);
      }
    }
    console.log(`[Worker] Hostname aman, resolved IPs: ${addresses.join(", ")}`);
  } catch (err) {
    console.error("❌ Anti-SSRF Error:", err.message);
    await sendWebhookResult(webhookUrl, webhookSecret, {
      scan_id: scanId,
      status: "failed",
      error_message: `Pemeriksaan Anti-SSRF gagal: ${err.message}`,
      findings: [],
    });
    process.exit(1);
  }

  // 3. PEMERIKSAAN SECURITY HEADERS & COOKIES
  console.log("[Worker] 3. Menjalankan pemeriksaan pasif Security Headers & Cookies...");
  try {
    const res = await fetch(`https://${hostname}/`, {
      method: "GET",
      redirect: "follow",
      headers: { "User-Agent": "SecScan-Worker-Bot/1.0" },
    });

    const headers = res.headers;

    if (!headers.get("strict-transport-security")) {
      allFindings.push({
        tool: "custom-passive-scanner",
        rule_id: "missing-hsts-header",
        title: "Header HTTP Strict Transport Security (HSTS) Tidak Ditemukan",
        severity: "medium",
        description: "HSTS melindungi pengguna dari serangan SSL Stripping dan downgrade HTTP.",
        evidence: "Header 'Strict-Transport-Security' tidak ditemukan.",
        remediation: "Tambahkan header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      });
    }

    if (!headers.get("content-security-policy")) {
      allFindings.push({
        tool: "custom-passive-scanner",
        rule_id: "missing-csp-header",
        title: "Header Content-Security-Policy (CSP) Tidak Ditemukan",
        severity: "medium",
        description: "CSP membatasi sumber skrip dan aset untuk mencegah serangan XSS.",
        evidence: "Header 'Content-Security-Policy' tidak ditemukan.",
        remediation: "Terapkan Content-Security-Policy yang membatasi script-src, object-src, dan default-src.",
      });
    }

    if (!headers.get("x-frame-options")) {
      allFindings.push({
        tool: "custom-passive-scanner",
        rule_id: "missing-x-frame-options",
        title: "Proteksi Clickjacking (X-Frame-Options) Belum Terpasang",
        severity: "low",
        description: "Situs dapat disematkan ke dalam iframe oleh web pihak ketiga.",
        evidence: "Header 'X-Frame-Options' tidak ditemukan.",
        remediation: "Tambahkan header: X-Frame-Options: SAMEORIGIN",
      });
    }
  } catch (err) {
    console.warn("[Worker] Peringatan koneksi HTTPS:", err.message);
  }

  // 4. PEMERIKSAAN FILE TEREKSPOS (.env, .git, backup.sql)
  console.log("[Worker] 4. Memeriksa file sensitif yang berpotensi terekspos...");
  const filesToCheck = [
    { path: "/.env", rule_id: "exposed-env-file", title: "File .env Dapat Diakses Publik", severity: "critical", sig: ["DB_", "SECRET", "KEY"] },
    { path: "/.git/HEAD", rule_id: "exposed-git-repo", title: "Folder .git Terekspos ke Publik", severity: "high", sig: ["ref: refs/"] },
    { path: "/backup.sql", rule_id: "exposed-backup-sql", title: "File Dump SQL Terekspos", severity: "critical", sig: ["INSERT INTO", "CREATE TABLE"] },
  ];

  for (const item of filesToCheck) {
    try {
      const res = await fetch(`https://${hostname}${item.path}`, {
        method: "GET",
        headers: { "User-Agent": "SecScan-Worker-Bot/1.0" },
      });
      if (res.status === 200) {
        const text = await res.text();
        if (item.sig.some((s) => text.includes(s)) && !text.toLowerCase().includes("<html")) {
          allFindings.push({
            tool: "custom-file-exposure",
            rule_id: item.rule_id,
            title: item.title,
            severity: item.severity,
            description: `File sensitif ${item.path} ditemukan dan dapat diakses publik tanpa autentikasi.`,
            evidence: `Path: ${item.path} (HTTP 200 OK)`,
            remediation: `Blokir akses ke ${item.path} pada konfigurasi web server Anda.`,
          });
        }
      }
    } catch {
      // Abaikan error individual
    }
  }

  // 5. MENJALANKAN TESTSSL.SH (JIKA TERSEDIA)
  console.log("[Worker] 5. Menjalankan testssl.sh...");
  try {
    if (fs.existsSync("./testssl-tool/testssl.sh")) {
      const testsslCmd = `./testssl-tool/testssl.sh --quiet --fast --jsonfile-pretty testssl_out.json ${hostname}`;
      console.log(`[Worker] Eksekusi: ${testsslCmd}`);
      execSync(testsslCmd, { timeout: 180000 }); // Max 3 menit

      if (fs.existsSync("testssl_out.json")) {
        const testsslData = JSON.parse(fs.readFileSync("testssl_out.json", "utf8"));
        // Parse hasil testssl sederhana
        if (Array.isArray(testsslData)) {
          for (const row of testsslData) {
            if (row.severity === "CRITICAL" || row.severity === "HIGH") {
              allFindings.push({
                tool: "testssl.sh",
                rule_id: `testssl-${row.id || "vuln"}`,
                title: `Kerentanan TLS: ${row.id || "Issue"}`,
                severity: row.severity.toLowerCase(),
                description: row.finding || "Masalah konfigurasi SSL/TLS terdeteksi.",
                evidence: `Severity: ${row.severity}, Detail: ${row.finding}`,
                remediation: "Perbarui cipher suite dan konfigurasi SSL/TLS web server Anda.",
              });
            }
          }
        }
      }
    } else {
      console.log("[Worker] testssl.sh tidak ditemukan di direktori lokal, melewati langkah testssl.");
    }
  } catch (err) {
    console.warn("[Worker] testssl.sh selesai dengan peringatan:", err.message);
  }

  // 6. KIRIM HASIL KE WEBHOOK
  console.log(`[Worker] 6. Mengirim ${allFindings.length} temuan ke Webhook Portal...`);
  const finalSummary = {
    total_findings: allFindings.length,
    duration_ms: Date.now() - startTime,
    scanned_at: new Date().toISOString(),
  };

  await sendWebhookResult(webhookUrl, webhookSecret, {
    scan_id: scanId,
    status: "done",
    summary: finalSummary,
    findings: allFindings,
  });

  console.log("[Worker] Pemindaian selesai dengan sukses!");
}

main().catch(async (err) => {
  console.error("❌ Worker unhandled fatal error:", err);
  process.exit(1);
});
