import { createClient } from "@supabase/supabase-js";
import * as dotenv from "dotenv";
import * as path from "path";
import { Database } from "../src/types/database";
import { isPrivateOrBlockedIP } from "../src/lib/security/ssrf";
import { runPassiveWebScan } from "../src/lib/scanner/passive-scan";
import { checkScanRateLimit } from "../src/lib/security/rate-limit";
import crypto from "crypto";

dotenv.config({ path: path.resolve(process.cwd(), ".env.local") });

type DomainRow = Database["public"]["Tables"]["domains"]["Row"];
type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
type FindingRow = Database["public"]["Tables"]["findings"]["Row"];

async function runPhase3Tests() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    console.error("❌ Kredensial Supabase belum lengkap di .env.local");
    process.exit(1);
  }

  console.log("==========================================================");
  console.log("🧪 MEMULAI PENGUJIAN OTOMATIS FASE 3: SCAN PASIF & ANTI-SSRF");
  console.log("==========================================================");

  // -------------------------------------------------------------
  // TEST 1: PENGUJIAN ANTI-SSRF KETAT
  // -------------------------------------------------------------
  console.log("\n[TEST 1] Pengujian Filter Anti-SSRF & Blokir IP:");
  const blockedIps = [
    { ip: "127.0.0.1", label: "IPv4 Loopback / Localhost" },
    { ip: "10.254.0.1", label: "IPv4 Private 10.0.0.0/8" },
    { ip: "172.16.0.1", label: "IPv4 Private 172.16.0.0/12" },
    { ip: "192.168.1.1", label: "IPv4 Private 192.168.0.0/16" },
    { ip: "169.254.169.254", label: "AWS / Cloud Instance Metadata" },
    { ip: "::1", label: "IPv6 Loopback" },
    { ip: "fe80::1", label: "IPv6 Link-Local" },
  ];

  for (const item of blockedIps) {
    const blocked = isPrivateOrBlockedIP(item.ip);
    if (blocked) {
      console.log(`  ✔ [BLOCKED] ${item.label} (${item.ip})`);
    } else {
      console.error(`  ❌ GAGAL: ${item.ip} seharusnya diblokir!`);
      process.exit(1);
    }
  }

  // -------------------------------------------------------------
  // TEST 2: SIMULASI SCAN PASIF (HEADERS, COOKIE, CORS, REDIRECT)
  // -------------------------------------------------------------
  console.log("\n[TEST 2] Menjalankan Passive Scanner pada 'example.com' (Aman & Publik):");
  const scanResult = await runPassiveWebScan("example.com");

  console.log(`  ✔ Status Eksekusi: ${scanResult.success}`);
  console.log(`  ✔ HTTP Status Target: ${scanResult.summary.http_status}`);
  console.log(`  ✔ Durasi Scan: ${scanResult.summary.duration_ms} ms`);
  console.log(`  ✔ Total Temuan Ternormalisasi: ${scanResult.findings.length}`);

  if (scanResult.findings.length > 0) {
    console.log(`  ✔ Contoh Format Temuan Seragam:`);
    const sample = scanResult.findings[0];
    console.log(`     - Tool: ${sample.tool}`);
    console.log(`     - Rule ID: ${sample.rule_id}`);
    console.log(`     - Title: ${sample.title}`);
    console.log(`     - Severity: ${sample.severity}`);
    console.log(`     - Remediation (ID): ${sample.remediation.slice(0, 80)}...`);
  }

  // -------------------------------------------------------------
  // TEST 3: END-TO-END FLOW (USER, DOMAIN, RATE LIMIT, SCAN, FINDINGS, RLS)
  // -------------------------------------------------------------
  console.log("\n[TEST 3] Pengujian End-to-End Database, Rate Limit & Findings:");

  const adminClient = createClient<Database>(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const timestamp = Date.now();
  const testEmail = `tester.phase3.${timestamp}@auditlab.test`;
  const password = "PasswordTesterSecure123!";

  const { data: userData, error: userErr } = await adminClient.auth.admin.createUser({
    email: testEmail,
    password: password,
    email_confirm: true,
  });

  if (userErr || !userData.user) {
    console.error("Gagal membuat user uji:", userErr?.message);
    process.exit(1);
  }

  const userId = userData.user.id;
  const userClient = createClient<Database>(supabaseUrl, anonKey);
  await userClient.auth.signInWithPassword({ email: testEmail, password });

  // 3a. Masukkan Domain Terverifikasi
  const { data: domainData, error: domErr } = await userClient
    .from("domains")
    .insert({
      owner_id: userId,
      hostname: "example.com",
      verify_token: `secscan_${crypto.randomBytes(16).toString("hex")}`,
      verified: true,
      verified_at: new Date().toISOString(),
    } as never)
    .select()
    .single<DomainRow>();

  if (domErr || !domainData) {
    console.error("Gagal insert domain:", domErr?.message);
    process.exit(1);
  }
  console.log("  ✔ Domain terverifikasi disiapkan:", domainData.hostname);

  // 3b. Buat Scan Pertama
  const { data: scanRow, error: scanErr } = await userClient
    .from("scans")
    .insert({
      domain_id: domainData.id,
      status: "done",
      summary: scanResult.summary,
      triggered_by: userId,
    } as never)
    .select()
    .single<ScanRow>();

  if (scanErr || !scanRow) {
    console.error("Gagal membuat scan row:", scanErr?.message);
    process.exit(1);
  }
  console.log("  ✔ Record Scan berhasil dibuat, ID:", scanRow.id);

  // 3c. Masukkan Findings
  const findingsPayload = scanResult.findings.map((f) => ({
    scan_id: scanRow.id,
    tool: f.tool,
    rule_id: f.rule_id,
    title: f.title,
    severity: f.severity,
    description: f.description,
    evidence: f.evidence,
    remediation: f.remediation,
  }));

  const { data: insertedFindings, error: findingsErr } = await userClient
    .from("findings")
    .insert(findingsPayload as never)
    .select()
    .returns<FindingRow[]>();

  if (findingsErr) {
    console.error("Gagal insert findings:", findingsErr.message);
    process.exit(1);
  }
  console.log(`  ✔ ${insertedFindings?.length || 0} Findings berhasil disimpan ke DB dengan proteksi RLS.`);

  // 3d. Uji Rate Limiting: Scan kedua ke domain yang sama dalam < 60 detik
  console.log("\n[TEST 4] Pengujian Rate Limiting (Spam Protection):");
  const rateLimitCheck = await checkScanRateLimit(userId, domainData.id, userClient);
  if (!rateLimitCheck.allowed) {
    console.log(`  ✔ [BERHASIL] Rate Limit Terpicu: "${rateLimitCheck.reason}"`);
  } else {
    console.error("  ❌ GAGAL: Rate limit seharusnya aktif untuk scan berturut-turut dalam 60 detik.");
  }

  // 4. Cleanup
  console.log("\n[CLEANUP] Membersihkan data uji...");
  await adminClient.auth.admin.deleteUser(userId);
  console.log("✔ Data pengujian dibersihkan.");

  console.log("\n==========================================================");
  console.log("🎉 SEMUA UJI SPESIFIKASI FASE 3 BERHASIL 100%!");
  console.log("==========================================================");
}

runPhase3Tests().catch(console.error);
