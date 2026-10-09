import { createClient } from "@supabase/supabase-js";
import * as dotenv from "dotenv";
import * as path from "path";
import { Database } from "../src/types/database";
import { parseNucleiOutput, mapNucleiSeverity } from "../src/lib/scanner/nuclei-parser";
import { deduplicateFindings, UnifiedFinding } from "../src/lib/scanner/deduplicate";
import crypto from "crypto";

dotenv.config({ path: path.resolve(process.cwd(), ".env.local") });

type DomainRow = Database["public"]["Tables"]["domains"]["Row"];
type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
type FindingRow = Database["public"]["Tables"]["findings"]["Row"];

async function runPhase5Tests() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    console.error("❌ Kredensial Supabase belum lengkap di .env.local");
    process.exit(1);
  }

  console.log("==========================================================");
  console.log("🧪 MEMULAI PENGUJIAN OTOMATIS FASE 5: NUCLEI & DEDUPLIKASI");
  console.log("==========================================================");

  // -------------------------------------------------------------
  // TEST 1: PENGUJIAN PEMETAAN SEVERITY NUCLEI
  // -------------------------------------------------------------
  console.log("\n[TEST 1] Pengujian Pemetaan Severity Nuclei:");
  const severityTests = [
    { input: "critical", expected: "critical" },
    { input: "CRITICAL", expected: "critical" },
    { input: "high", expected: "high" },
    { input: "medium", expected: "medium" },
    { input: "low", expected: "low" },
    { input: "info", expected: "info" },
    { input: "unknown", expected: "info" },
  ];

  for (const st of severityTests) {
    const mapped = mapNucleiSeverity(st.input);
    if (mapped === st.expected) {
      console.log(`  ✔ Severity '${st.input}' -> '${mapped}' (Valid)`);
    } else {
      console.error(`  ❌ GAGAL: Mapped '${st.input}' menghasilkan '${mapped}', diharapkan '${st.expected}'`);
      process.exit(1);
    }
  }

  // -------------------------------------------------------------
  // TEST 2: PENGUJIAN PARSER OUTPUT JSON NUCLEI
  // -------------------------------------------------------------
  console.log("\n[TEST 2] Pengujian Parsing Output JSONL Nuclei:");
  const sampleNucleiJsonl = `
{"template-id":"exposed-git-config","info":{"name":"Git Config Disclosure","author":["geeknik"],"severity":"high","description":"Git configuration file was exposed publicly."},"type":"http","host":"https://target.com","matched-at":"https://target.com/.git/config","extracted-results":["[core]","repositoryformatversion = 0"]}
{"template-id":"tech-detect-react","info":{"name":"React Framework Detection","author":["pdteam"],"severity":"info","description":"Target web application uses React."},"type":"http","host":"https://target.com","matched-at":"https://target.com/"}
{"template-id":"cors-misconfiguration","info":{"name":"CORS Wildcard with Credentials","author":["null"],"severity":"high","description":"CORS misconfiguration detected."},"type":"http","host":"https://target.com","matched-at":"https://target.com/api"}
`;

  const parsedNuclei = parseNucleiOutput(sampleNucleiJsonl);
  console.log(`  ✔ Berhasil mem-parse ${parsedNuclei.length} temuan dari output JSONL Nuclei.`);

  if (parsedNuclei.length === 3) {
    console.log("  ✔ Sample 1 Title:", parsedNuclei[0].title);
    console.log("  ✔ Sample 1 Severity:", parsedNuclei[0].severity);
    console.log("  ✔ Sample 1 Remediation (ID):", parsedNuclei[0].remediation);
  } else {
    console.error("  ❌ GAGAL: Jumlah parse temuan Nuclei tidak sesuai!");
    process.exit(1);
  }

  // -------------------------------------------------------------
  // TEST 3: PENGUJIAN DEDUPLIKASI (RULE_ID + URL)
  // -------------------------------------------------------------
  console.log("\n[TEST 3] Pengujian Engine Deduplikasi Temuan (Rule ID + URL):");
  const rawFindingsList: UnifiedFinding[] = [
    // 2 temuan identik dari tool berbeda (Custom scanner vs Nuclei)
    {
      tool: "custom-file-exposure",
      rule_id: "exposed-git-config",
      title: "File Konfigurasi Git (.git/config) Terekspos",
      severity: "medium",
      description: "Git config file ditemukan di /.git/config",
      evidence: "Custom scanner found [core]",
      remediation: "Blokir folder /.git/",
      matched_url: "https://target.com/.git/config",
    },
    {
      tool: "nuclei",
      rule_id: "exposed-git-config",
      title: "Git Config Disclosure",
      severity: "high", // Severity lebih tinggi
      description: "Git configuration file was exposed publicly.",
      evidence: "Nuclei extracted repositoryformatversion=0",
      remediation: "Batasi akses ke file atau direktori tersebut.",
      matched_url: "https://target.com/.git/config",
    },
    // 1 temuan berbeda
    {
      tool: "nuclei",
      rule_id: "tech-detect-react",
      title: "React Framework Detection",
      severity: "info",
      description: "React detected",
      evidence: "React DOM",
      remediation: "Sembunyikan banner versi server.",
      matched_url: "https://target.com/",
    },
  ];

  const deduped = deduplicateFindings(rawFindingsList);
  console.log(`  ✔ Jumlah temuan sebelum deduplikasi: ${rawFindingsList.length}`);
  console.log(`  ✔ Jumlah temuan setelah deduplikasi: ${deduped.length}`);

  if (deduped.length === 2) {
    const mergedItem = deduped.find((d) => d.rule_id === "exposed-git-config");
    console.log("  ✔ Item hasil penggabungan:");
    console.log("     - Sumber tool:", mergedItem?.tool); // Harus 'custom-file-exposure, nuclei'
    console.log("     - Severity terpilih:", mergedItem?.severity); // Harus 'high'
    console.log("     - Bukti gabungan:", mergedItem?.evidence?.replace(/\n/g, " | "));

    if (mergedItem?.severity === "high" && mergedItem.tool.includes("nuclei") && mergedItem.tool.includes("custom-file-exposure")) {
      console.log("  ✔ [BERHASIL] Logika deduplikasi mempertahankan severity tertinggi dan menggabungkan evidence!");
    } else {
      console.error("  ❌ GAGAL: Logika merge deduplikasi tidak bekerja dengan benar.");
      process.exit(1);
    }
  } else {
    console.error("  ❌ GAGAL: Duplikat tidak berhasil digabungkan.");
    process.exit(1);
  }

  // -------------------------------------------------------------
  // TEST 4: INTEGRASI DATABASE LENGKAP DENGAN NUCLEI FINDINGS & RLS
  // -------------------------------------------------------------
  console.log("\n[TEST 4] Pengujian End-to-End Simpan Temuan Nuclei ke Supabase:");

  const adminClient = createClient<Database>(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const timestamp = Date.now();
  const testEmail = `tester.phase5.${timestamp}@auditlab.test`;
  const password = "PasswordTesterSecure123!";

  const { data: userData } = await adminClient.auth.admin.createUser({
    email: testEmail,
    password: password,
    email_confirm: true,
  });

  const userId = userData!.user!.id;
  const userClient = createClient<Database>(supabaseUrl, anonKey);
  await userClient.auth.signInWithPassword({ email: testEmail, password });

  // Buat Domain & Scan
  const { data: domainData } = await userClient
    .from("domains")
    .insert({
      owner_id: userId,
      hostname: "juice-shop-mock.local",
      verify_token: `secscan_${crypto.randomBytes(16).toString("hex")}`,
      verified: true,
      verified_at: new Date().toISOString(),
    } as never)
    .select()
    .single<DomainRow>();

  const { data: scanData } = await userClient
    .from("scans")
    .insert({
      domain_id: domainData!.id,
      status: "done",
      summary: { scanner: "nuclei+passive", total_findings: deduped.length },
      triggered_by: userId,
    } as never)
    .select()
    .single<ScanRow>();

  // Simpan Temuan Ter-deduplikasi
  const findingsPayload = deduped.map((f) => ({
    scan_id: scanData!.id,
    tool: f.tool,
    rule_id: f.rule_id,
    title: f.title,
    severity: f.severity,
    description: f.description,
    evidence: f.evidence,
    remediation: f.remediation,
  }));

  const { data: savedFindings, error: saveErr } = await userClient
    .from("findings")
    .insert(findingsPayload as never)
    .select()
    .returns<FindingRow[]>();

  if (saveErr) {
    console.error("Gagal simpan temuan ke database:", saveErr.message);
    process.exit(1);
  }

  console.log(`  ✔ Berhasil menyimpan ${savedFindings?.length} temuan Nuclei ternormalisasi ke Supabase (RLS Passed).`);

  // Cleanup
  console.log("\n[CLEANUP] Membersihkan akun pengujian...");
  await adminClient.auth.admin.deleteUser(userId);
  console.log("✔ Akun pengujian dibersihkan.");

  console.log("\n==========================================================");
  console.log("🎉 SEMUA UJI SPESIFIKASI FASE 5 BERHASIL 100%!");
  console.log("==========================================================");
}

runPhase5Tests().catch(console.error);
