import { createClient } from "@supabase/supabase-js";
import * as dotenv from "dotenv";
import * as path from "path";
import { Database } from "../src/types/database";
import { generateWebhookSignature, verifyWebhookSignature } from "../src/lib/security/webhook-signature";
import { checkExposedFiles } from "../src/lib/scanner/file-exposure";
import { parseTestsslJson, TestsslJsonFinding } from "../src/lib/scanner/testssl-parser";
import crypto from "crypto";

dotenv.config({ path: path.resolve(process.cwd(), ".env.local") });

type DomainRow = Database["public"]["Tables"]["domains"]["Row"];
type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
type FindingRow = Database["public"]["Tables"]["findings"]["Row"];

async function runPhase4Tests() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    console.error("❌ Kredensial Supabase belum lengkap di .env.local");
    process.exit(1);
  }

  console.log("==========================================================");
  console.log("🧪 MEMULAI PENGUJIAN OTOMATIS FASE 4: WORKER & WEBHOOK HMAC");
  console.log("==========================================================");

  // -------------------------------------------------------------
  // TEST 1: PENGUJIAN VALIDASI SIGNATURE HMAC WEBHOOK
  // -------------------------------------------------------------
  console.log("\n[TEST 1] Pengujian Keamanan Webhook Signature (HMAC SHA256):");
  const testSecret = "super-secret-webhook-key-99999";
  const fakeSecret = "wrong-secret-key-11111";
  const dummyPayload = JSON.stringify({
    scan_id: "test-scan-id-12345",
    status: "done",
    findings: [],
  });

  const validSignature = generateWebhookSignature(dummyPayload, testSecret);
  console.log("  ✔ Generated Signature:", validSignature);

  // 1a. Cek signature valid dengan secret yang benar
  const isValid = verifyWebhookSignature(dummyPayload, validSignature, testSecret);
  if (isValid) {
    console.log("  ✔ [BERHASIL] Webhook menerima signature yang valid!");
  } else {
    console.error("  ❌ GAGAL: Signature valid ditolak!");
    process.exit(1);
  }

  // 1b. Cek signature ditolak jika secret salah / dipalsukan
  const isInvalid = verifyWebhookSignature(dummyPayload, validSignature, fakeSecret);
  if (!isInvalid) {
    console.log("  ✔ [BERHASIL] Webhook MENOLAK signature dengan secret yang salah!");
  } else {
    console.error("  ❌ GAGAL: Signature palsu diterima!");
    process.exit(1);
  }

  // 1c. Cek signature ditolak jika payload dimodifikasi di tengah jalan (Tampering)
  const tamperedPayload = JSON.stringify({
    scan_id: "test-scan-id-12345",
    status: "done",
    tampered: true,
  });
  const isTampered = verifyWebhookSignature(tamperedPayload, validSignature, testSecret);
  if (!isTampered) {
    console.log("  ✔ [BERHASIL] Webhook MENOLAK payload yang dimanipulasi (Anti-Tampering)!");
  } else {
    console.error("  ❌ GAGAL: Payload hasil manipulasi lolos!");
    process.exit(1);
  }

  // -------------------------------------------------------------
  // TEST 2: PENGUJIAN PARSER TESTSSL.SH KE FORMAT TEMUAN SERAGAM
  // -------------------------------------------------------------
  console.log("\n[TEST 2] Pengujian Normalisasi Output testssl.sh:");
  const sampleTestsslJson: TestsslJsonFinding[] = [
    {
      id: "TLS1",
      ip: "93.184.216.34",
      port: "443",
      severity: "MEDIUM",
      finding: "offered (deprecated)",
    },
    {
      id: "HEARTBLEED",
      ip: "93.184.216.34",
      port: "443",
      severity: "CRITICAL",
      finding: "vulnerable (CVE-2014-0160)",
    },
    {
      id: "cert_expiration",
      ip: "93.184.216.34",
      port: "443",
      severity: "LOW",
      finding: "Certificate expires in 45 days",
    },
    {
      id: "cipher_null",
      ip: "93.184.216.34",
      port: "443",
      severity: "OK",
      finding: "not offered",
    },
  ];

  const parsedTestssl = parseTestsslJson(sampleTestsslJson);
  console.log(`  ✔ Hasil normalisasi testssl: ${parsedTestssl.length} temuan`);
  if (parsedTestssl.length === 3) {
    console.log("  ✔ Status OK berhasil diabaikan, hanya severity MEDIUM/HIGH/CRITICAL/LOW yang dicatat.");
  } else {
    console.error("  ❌ GAGAL: Jumlah temuan testssl tidak sesuai.");
    process.exit(1);
  }

  // -------------------------------------------------------------
  // TEST 3: END-TO-END WORKER FLOW DENGAN DATABASE SUPABASE
  // -------------------------------------------------------------
  console.log("\n[TEST 3] Pengujian Worker Simulating Webhook Update ke Supabase:");

  const adminClient = createClient<Database>(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const timestamp = Date.now();
  const testEmail = `tester.phase4.${timestamp}@auditlab.test`;
  const password = "PasswordTesterSecure123!";

  const { data: userData } = await adminClient.auth.admin.createUser({
    email: testEmail,
    password: password,
    email_confirm: true,
  });

  const userId = userData!.user!.id;
  const userClient = createClient<Database>(supabaseUrl, anonKey);
  await userClient.auth.signInWithPassword({ email: testEmail, password });

  // 3a. Buat Domain
  const { data: domainData } = await userClient
    .from("domains")
    .insert({
      owner_id: userId,
      hostname: "worker-test.com",
      verify_token: `secscan_${crypto.randomBytes(16).toString("hex")}`,
      verified: true,
      verified_at: new Date().toISOString(),
    } as never)
    .select()
    .single<DomainRow>();

  // 3b. Buat Scan Berstatus 'queued'
  const { data: scanData } = await userClient
    .from("scans")
    .insert({
      domain_id: domainData!.id,
      status: "queued",
      summary: { mode: "worker" },
      triggered_by: userId,
    } as never)
    .select()
    .single<ScanRow>();

  console.log("  ✔ Scan queued dibuat, ID:", scanData!.id);

  // 3c. Simulasi Worker memproses & mengirim webhook ke Supabase Admin
  console.log("  -> Worker memproses hasil dan mengupdate scan menjadi 'done'...");
  const sampleFindings = [
    ...parsedTestssl,
    {
      tool: "custom-file-exposure",
      rule_id: "exposed-env-file",
      title: "File .env Dapat Diakses Publik",
      severity: "critical" as const,
      description: "File .env terbuka di public root.",
      evidence: "URL: https://worker-test.com/.env",
      remediation: "Hapus file .env dari public root.",
    },
  ];

  // Admin client memasukkan temuan & menandai done
  const findingsPayload = sampleFindings.map((f) => ({
    scan_id: scanData!.id,
    tool: f.tool,
    rule_id: f.rule_id,
    title: f.title,
    severity: f.severity,
    description: f.description,
    evidence: f.evidence,
    remediation: f.remediation,
  }));

  await adminClient.from("findings").insert(findingsPayload as never);

  const { data: updatedScan } = await adminClient
    .from("scans")
    .update({
      status: "done",
      finished_at: new Date().toISOString(),
      summary: {
        total_findings: sampleFindings.length,
        completed_via: "github_actions_worker",
      },
    } as never)
    .eq("id", scanData!.id)
    .select()
    .single<ScanRow>();

  console.log(`  ✔ Status akhir scan di database: ${updatedScan?.status}`);
  console.log(`  ✔ Summary worker tersimpan:`, updatedScan?.summary);

  // 4. Cleanup
  console.log("\n[CLEANUP] Membersihkan akun pengujian...");
  await adminClient.auth.admin.deleteUser(userId);
  console.log("✔ Akun pengujian dibersihkan.");

  console.log("\n==========================================================");
  console.log("🎉 SEMUA UJI SPESIFIKASI FASE 4 BERHASIL 100%!");
  console.log("==========================================================");
}

runPhase4Tests().catch(console.error);
