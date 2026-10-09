const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");
const dns = require("dns");
const net = require("net");
const { execFile, execFileSync } = require("child_process");
const fs = require("fs");

/**
 * Worker Comprehensive Scan:
 * 1. Validasi ulang status domain di Supabase (verified == true)
 * 2. Cek Anti-SSRF pada target hostname
 * 3. Passive checks (Security Headers, Cookie Flags)
 * 4. Exposed files check (.env, .git, backup.sql)
 * 5. Nuclei scan (Hanya template exposures, misconfiguration, technologies dengan rate-limit ketat)
 * 6. testssl.sh scan (TLS/SSL cipher suites)
 * 7. Deduplikasi temuan berdasarkan rule_id + matched_url
 * 8. Kirim payload terverifikasi HMAC ke Webhook Portal
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
    if (a === 100 && b >= 64 && b <= 127) return true;
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

const SEVERITY_WEIGHT = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function deduplicateFindings(findings) {
  const mergedMap = new Map();

  for (const item of findings) {
    const urlKey = (item.matched_url || item.evidence || "root").toLowerCase().trim().replace(/\/+$/, "");
    const dedupeKey = `${item.rule_id.toLowerCase()}::${urlKey}`;

    if (!mergedMap.has(dedupeKey)) {
      mergedMap.set(dedupeKey, { ...item });
    } else {
      const existing = mergedMap.get(dedupeKey);
      const existingWeight = SEVERITY_WEIGHT[existing.severity] || 0;
      const currentWeight = SEVERITY_WEIGHT[item.severity] || 0;
      if (currentWeight > existingWeight) {
        existing.severity = item.severity;
      }
      if (item.evidence && existing.evidence && !existing.evidence.includes(item.evidence)) {
        existing.evidence = `${existing.evidence}\n[${item.tool}] ${item.evidence}`.slice(0, 800);
      }
      if (!existing.tool.includes(item.tool)) {
        existing.tool = `${existing.tool}, ${item.tool}`;
      }
    }
  }

  return Array.from(mergedMap.values());
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

// Eksekusi biner eksternal dengan Array arguments (Anti Command Injection)
function runSafeBinary(command, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: timeoutMs }, (error, stdout, stderr) => {
      if (error && error.killed) {
        return reject(new Error(`Command timed out after ${timeoutMs}ms`));
      }
      resolve({ stdout, stderr, error });
    });
  });
}

async function main() {
  const scanId = process.env.TARGET_SCAN_ID;
  const rawHostname = process.env.TARGET_HOSTNAME;
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const webhookUrl = process.env.SCAN_WEBHOOK_URL;
  const webhookSecret = process.env.SCAN_WEBHOOK_SECRET;

  if (!scanId || !rawHostname || !supabaseUrl || !serviceRoleKey || !webhookUrl || !webhookSecret) {
    console.error("❌ Variabel lingkungan worker belum lengkap!");
    process.exit(1);
  }

  // Sanitasi hostname ketat dengan whitelist
  const hostname = rawHostname.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  const hostnameRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/;
  if (!hostnameRegex.test(hostname)) {
    console.error(`❌ Hostname tidak valid: ${hostname}`);
    process.exit(1);
  }

  console.log(`[Worker] Memulai pemindaian: Scan ID=${scanId}, Target Hostname=${hostname}`);
  const startTime = Date.now();
  let allFindings = [];

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
        matched_url: `https://${hostname}/`,
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
        matched_url: `https://${hostname}/`,
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
        matched_url: `https://${hostname}/`,
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
            matched_url: `https://${hostname}${item.path}`,
          });
        }
      }
    } catch {
      // Abaikan error individual
    }
  }

  // 5. NUCLEI SCANNER (MENGGUNAKAN EXECFILE + ARG ARRAY TANPA STRING CONCATENATION)
  console.log("[Worker] 5. Menjalankan Nuclei Scanner (Exposures, Misconfigurations, Technologies)...");
  try {
    const nucleiArgs = [
      "-u", `https://${hostname}`,
      "-tags", "exposure,misconfiguration,tech",
      "-rate-limit", "15",
      "-c", "5",
      "-timeout", "5",
      "-silent",
      "-jsonl",
      "-o", "nuclei_out.jsonl",
    ];

    await runSafeBinary("nuclei", nucleiArgs, 300000);

    if (fs.existsSync("nuclei_out.jsonl")) {
      const nucleiContent = fs.readFileSync("nuclei_out.jsonl", "utf8");
      const lines = nucleiContent.split("\n");

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const item = JSON.parse(line.trim());
          const ruleId = item["template-id"] || item.templateID || "nuclei-finding";
          const info = item.info || {};
          const rawSev = (info.severity || "info").toLowerCase();
          const matchedAt = item["matched-at"] || item.matchedAt || item.host || `https://${hostname}`;

          let severity = "info";
          if (rawSev === "critical") severity = "critical";
          else if (rawSev === "high") severity = "high";
          else if (rawSev === "medium") severity = "medium";
          else if (rawSev === "low") severity = "low";

          allFindings.push({
            tool: "nuclei",
            rule_id: ruleId,
            title: info.name || ruleId,
            severity: severity,
            description: info.description || `Nuclei mendeteksi indikasi temuan ${ruleId}.`,
            evidence: `Matched: ${matchedAt}`.slice(0, 500),
            remediation: info.remediation || "Tinjau konfigurasi komponen terkait dan perbarui ke versi yang aman.",
            matched_url: matchedAt,
          });
        } catch {
          // Abaikan baris parse error
        }
      }
    }
  } catch (err) {
    console.warn("[Worker] Nuclei execution notice:", err.message);
  }

  // 6. TESTSSL.SH SCANNER (MENGGUNAKAN EXECFILE + ARG ARRAY)
  console.log("[Worker] 6. Menjalankan testssl.sh...");
  try {
    if (fs.existsSync("./testssl-tool/testssl.sh")) {
      const testsslArgs = ["--quiet", "--fast", "--jsonfile-pretty", "testssl_out.json", hostname];
      await runSafeBinary("./testssl-tool/testssl.sh", testsslArgs, 180000);

      if (fs.existsSync("testssl_out.json")) {
        const testsslData = JSON.parse(fs.readFileSync("testssl_out.json", "utf8"));
        if (Array.isArray(testsslData)) {
          for (const row of testsslData) {
            if (row.severity === "CRITICAL" || row.severity === "HIGH" || row.severity === "MEDIUM") {
              allFindings.push({
                tool: "testssl.sh",
                rule_id: `testssl-${row.id || "vuln"}`,
                title: `Kerentanan TLS: ${row.id || "Issue"}`,
                severity: row.severity.toLowerCase(),
                description: row.finding || "Masalah konfigurasi SSL/TLS terdeteksi.",
                evidence: `Severity: ${row.severity}, Detail: ${row.finding}`,
                remediation: "Perbarui cipher suite dan konfigurasi SSL/TLS web server Anda.",
                matched_url: `https://${hostname}:443`,
              });
            }
          }
        }
      }
    }
  } catch (err) {
    console.warn("[Worker] testssl.sh notice:", err.message);
  }

  // 7. DEDUPLIKASI TEMUAN (RULE_ID + MATCHED_URL)
  console.log(`[Worker] 7. Melakukan deduplikasi pada ${allFindings.length} temuan mentah...`);
  const deduplicatedFindings = deduplicateFindings(allFindings);
  console.log(`[Worker] Total temuan setelah deduplikasi: ${deduplicatedFindings.length}`);

  // 8. KIRIM HASIL KE WEBHOOK
  const finalSummary = {
    total_findings: deduplicatedFindings.length,
    duration_ms: Date.now() - startTime,
    scanned_at: new Date().toISOString(),
    scanners_executed: ["custom_headers", "file_exposure", "nuclei", "testssl"],
  };

  await sendWebhookResult(webhookUrl, webhookSecret, {
    scan_id: scanId,
    status: "done",
    summary: finalSummary,
    findings: deduplicatedFindings,
  });

  console.log("[Worker] Seluruh alur pemindaian selesai 100%!");
}

main().catch(async (err) => {
  console.error("❌ Worker fatal error:", err);
  process.exit(1);
});
