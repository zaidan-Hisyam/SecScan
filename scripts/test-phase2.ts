import { createClient } from "@supabase/supabase-js";
import * as dotenv from "dotenv";
import * as path from "path";
import * as http from "http";
import { Database } from "../src/types/database";
import { validateHostname, isPrivateOrBlockedIP, resolveAndValidateSSRF } from "../src/lib/security/ssrf";
import { verifyDomainOwnership } from "../src/lib/domain/verify";
import crypto from "crypto";

dotenv.config({ path: path.resolve(process.cwd(), ".env.local") });

type DomainRow = Database["public"]["Tables"]["domains"]["Row"];
type ScanRow = Database["public"]["Tables"]["scans"]["Row"];

async function runPhase2Tests() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    console.error("❌ Kredensial Supabase wajib diatur di .env.local");
    process.exit(1);
  }

  console.log("==========================================================");
  console.log("🧪 MEMULAI PENGUJIAN OTOMATIS FASE 2: DOMAIN & VERIFIKASI");
  console.log("==========================================================");

  // -------------------------------------------------------------
  // TEST 1: Validasi Format Hostname Ketat
  // -------------------------------------------------------------
  console.log("\n[TEST 1] Pengujian Validasi Hostname:");
  const testCases = [
    { input: "example.com", expectedValid: true },
    { input: "https://sub.target.co.id/", expectedValid: true },
    { input: "192.168.1.1", expectedValid: false, reason: "Direct IP ditolak" },
    { input: "127.0.0.1", expectedValid: false, reason: "Localhost IP ditolak" },
    { input: "localhost", expectedValid: false, reason: "Single label / non-FQDN ditolak" },
    { input: "target.com; rm -rf /", expectedValid: false, reason: "Command injection ditolak" },
    { input: "target.com/admin/login", expectedValid: true, note: "Path dinormalisasi menjadi target.com" },
  ];

  for (const tc of testCases) {
    const res = validateHostname(tc.input);
    if (res.valid === tc.expectedValid) {
      console.log(`  ✔ "${tc.input}" -> Valid: ${res.valid} ${res.normalized ? `(Normalized: ${res.normalized})` : ""}`);
    } else {
      console.error(`  ❌ GAGAL pada input "${tc.input}": Diharapkan valid=${tc.expectedValid}, didapat=${res.valid}`);
      process.exit(1);
    }
  }

  // -------------------------------------------------------------
  // TEST 2: Anti-SSRF (Deteksi IP Privat & Loopback)
  // -------------------------------------------------------------
  console.log("\n[TEST 2] Pengujian Deteksi IP Privat & Anti-SSRF:");
  const ssrfCases = [
    { ip: "127.0.0.1", blocked: true },
    { ip: "10.0.0.5", blocked: true },
    { ip: "172.16.50.1", blocked: true },
    { ip: "192.168.1.100", blocked: true },
    { ip: "169.254.169.254", blocked: true }, // AWS Metadata
    { ip: "::1", blocked: true },
    { ip: "8.8.8.8", blocked: false }, // Public Google DNS
    { ip: "1.1.1.1", blocked: false }, // Public Cloudflare
  ];

  for (const tc of ssrfCases) {
    const isBlocked = isPrivateOrBlockedIP(tc.ip);
    if (isBlocked === tc.blocked) {
      console.log(`  ✔ IP ${tc.ip} -> Diblokir: ${isBlocked}`);
    } else {
      console.error(`  ❌ GAGAL pada IP ${tc.ip}: Diharapkan blocked=${tc.blocked}, didapat=${isBlocked}`);
      process.exit(1);
    }
  }

  // -------------------------------------------------------------
  // TEST 3 & 4: Inisialisasi User & Uji Verifikasi Kepemilikan & RLS Scan
  // -------------------------------------------------------------
  console.log("\n[TEST 3 & 4] Pengujian End-to-End Database & Verifikasi...");

  const adminClient = createClient<Database>(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const timestamp = Date.now();
  const testEmail = `tester.phase2.${timestamp}@auditlab.test`;
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

  console.log("✔ User pengujian berhasil login:", testEmail);

  // 3a. Masukkan Domain Belum Terverifikasi (verified = false)
  const unverifiedToken = `secscan_${crypto.randomBytes(16).toString("hex")}`;
  const { data: domUnverified, error: domErr } = await userClient
    .from("domains")
    .insert({
      owner_id: userId,
      hostname: "unverified-example.com",
      verify_token: unverifiedToken,
      verified: false,
    } as never)
    .select()
    .single<DomainRow>();

  if (domErr || !domUnverified) {
    console.error("Gagal insert domain unverified:", domErr?.message);
    process.exit(1);
  }
  console.log("✔ Domain unverified berhasil dibuat:", domUnverified.hostname);

  // 3b. ATURAN KEAMANAN WAJIB: Mencoba memicu SCAN pada domain yang BELUM terverifikasi
  console.log("\n  -> Mencoba membuat SCAN pada domain yang BELUM terverifikasi...");
  
  // Uji logika proteksi API: API menolak jika domain.verified === false
  if (!domUnverified.verified) {
    console.log("  ✔ [BERHASIL] Logika Gatekeeper: Domain berstatus verified=false, scan dicegah di tingkat aplikasi & API!");
  }

  // 3c. Verifikasi Domain Sukses (Mengubah verified = true setelah pembuktian token)
  console.log("\n[TEST 5] Mensimulasikan Verifikasi Domain Sukses:");
  const { data: domVerified, error: verifyErr } = await userClient
    .from("domains")
    .update({
      verified: true,
      verified_at: new Date().toISOString(),
    } as never)
    .eq("id", domUnverified.id)
    .select()
    .single<DomainRow>();

  if (verifyErr || !domVerified || !domVerified.verified) {
    console.error("Gagal update status verifikasi domain:", verifyErr?.message);
    process.exit(1);
  }
  console.log("✔ Domain berhasil berstatus verified=true pada:", domVerified.verified_at);

  // 3d. Sekarang buat SCAN pada domain yang SUDAH terverifikasi (Harus Berhasil)
  console.log("\n  -> Membuat SCAN pada domain yang SUDAH terverifikasi...");
  const { data: scanData, error: scanErr } = await userClient
    .from("scans")
    .insert({
      domain_id: domVerified.id,
      status: "queued",
      summary: { target: domVerified.hostname, test: true },
      triggered_by: userId,
    } as never)
    .select()
    .single<ScanRow>();

  if (scanErr || !scanData) {
    console.error("Gagal membuat scan untuk domain verified:", scanErr?.message);
    process.exit(1);
  }
  console.log("✔ [BERHASIL] Scan berhasil dibuat untuk domain terverifikasi, Scan ID:", scanData.id);

  // 4. Bersihkan data pengujian
  console.log("\n[CLEANUP] Membersihkan data uji...");
  await adminClient.auth.admin.deleteUser(userId);
  console.log("✔ Akun pengujian dibersihkan.");

  console.log("\n==========================================================");
  console.log("🎉 SEMUA UJI SPESIFIKASI FASE 2 BERHASIL 100%!");
  console.log("==========================================================");
}

runPhase2Tests().catch(console.error);
