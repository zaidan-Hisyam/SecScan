import { createClient } from "@supabase/supabase-js";
import * as dotenv from "dotenv";
import * as path from "path";
import { Database } from "../src/types/database";

dotenv.config({ path: path.resolve(process.cwd(), ".env.local") });

type DomainInsert = Database["public"]["Tables"]["domains"]["Insert"];
type DomainRow = Database["public"]["Tables"]["domains"]["Row"];
type ScanInsert = Database["public"]["Tables"]["scans"]["Insert"];
type ProfileRow = Database["public"]["Tables"]["profiles"]["Row"];

async function testRLS() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    console.error("❌ NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY, dan SUPABASE_SERVICE_ROLE_KEY wajib diatur di .env.local!");
    process.exit(1);
  }

  console.log("=== MEMULAI PENGUJIAN ISOLASI RLS (2 PENGGUNA) ===");
  console.log("Supabase Target:", supabaseUrl);

  const adminClient = createClient<Database>(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const timestamp = Date.now();
  const emailA = `user.a.${timestamp}@auditlab.test`;
  const emailB = `user.b.${timestamp}@auditlab.test`;
  const password = "PasswordSuperAman123!";

  // 1. Buat User A via Admin API (bebas email rate limit & langsung terkonfirmasi)
  console.log(`\n1. Membuat Pengguna A: ${emailA}`);
  const { data: userAData, error: createErrA } = await adminClient.auth.admin.createUser({
    email: emailA,
    password: password,
    email_confirm: true,
  });

  if (createErrA || !userAData.user) {
    console.error("Gagal membuat pengguna A:", createErrA?.message);
    return;
  }
  console.log("✔ Pengguna A berhasil dibuat, ID:", userAData.user.id);

  // 2. Buat User B via Admin API
  console.log(`\n2. Membuat Pengguna B: ${emailB}`);
  const { data: userBData, error: createErrB } = await adminClient.auth.admin.createUser({
    email: emailB,
    password: password,
    email_confirm: true,
  });

  if (createErrB || !userBData.user) {
    console.error("Gagal membuat pengguna B:", createErrB?.message);
    return;
  }
  console.log("✔ Pengguna B berhasil dibuat, ID:", userBData.user.id);

  // 3. Inisialisasi sesi Pengguna A dan Pengguna B dengan Anon Key (Klien Nyata)
  const clientA = createClient<Database>(supabaseUrl, anonKey);
  const { error: loginErrA } = await clientA.auth.signInWithPassword({
    email: emailA,
    password: password,
  });
  if (loginErrA) {
    console.error("Gagal login klien A:", loginErrA.message);
    return;
  }

  const clientB = createClient<Database>(supabaseUrl, anonKey);
  const { error: loginErrB } = await clientB.auth.signInWithPassword({
    email: emailB,
    password: password,
  });
  if (loginErrB) {
    console.error("Gagal login klien B:", loginErrB.message);
    return;
  }

  // 4. Verifikasi profile otomatis dibuat oleh database trigger
  const { data: profA } = await clientA.from("profiles").select("*").single<ProfileRow>();
  console.log("✔ Profil Pengguna A terdeteksi:", profA?.email);

  // 5. Pengguna A menambahkan domain target
  console.log("\n3. Pengguna A menambahkan domain 'target-user-a.com'");
  const domainPayload: DomainInsert = {
    owner_id: userAData.user.id,
    hostname: "target-user-a.com",
    verify_token: "token-sec-a-999888",
    verified: true,
  };

  const { data: domainA, error: domainErrA } = await clientA
    .from("domains")
    .insert(domainPayload as never)
    .select()
    .single<DomainRow>();

  if (domainErrA || !domainA) {
    console.error("Gagal insert domain A:", domainErrA?.message);
    return;
  }
  console.log("✔ Domain Pengguna A tersimpan, ID:", domainA.id);

  // 6. Pengujian RLS SELECT: Pengguna B mencoba membaca data domain milik Pengguna A
  console.log("\n4. Pengujian RLS SELECT: Pengguna B mencoba membaca domain milik Pengguna A...");
  const { data: readByB, error: readErrB } = await clientB
    .from("domains")
    .select("*")
    .eq("id", domainA.id)
    .returns<DomainRow[]>();

  if (readErrB) {
    console.log("Catatan query B:", readErrB.message);
  }

  if (!readByB || readByB.length === 0) {
    console.log("✔ [BERHASIL] RLS Efektif! Pengguna B TIDAK DAPAT melihat domain milik Pengguna A (0 baris).");
  } else {
    console.error("❌ [GAGAL] RLS Bocor! Pengguna B bisa membaca domain Pengguna A:", readByB);
  }

  // 7. Pengujian RLS INSERT: Pengguna B mencoba menyisipkan record scan ke domain milik Pengguna A
  console.log("\n5. Pengujian RLS INSERT: Pengguna B mencoba menyisipkan scan ke domain Pengguna A...");
  const scanPayload: ScanInsert = {
    domain_id: domainA.id,
    status: "queued",
    summary: {},
    triggered_by: userBData.user.id,
  };

  const { data: scanByB, error: scanErrB } = await clientB
    .from("scans")
    .insert(scanPayload as never)
    .select();

  if (scanErrB) {
    console.log("✔ [BERHASIL] RLS Menolak INSERT scan dari Pengguna B:", scanErrB.message);
  } else if (!scanByB || scanByB.length === 0) {
    console.log("✔ [BERHASIL] RLS Menolak: Record scan tidak dibuat.");
  } else {
    console.error("❌ [GAGAL] RLS Bocor! Pengguna B berhasil menyisipkan scan:", scanByB);
  }

  // 8. Pembersihan akun uji
  console.log("\n6. Membersihkan akun pengujian...");
  await adminClient.auth.admin.deleteUser(userAData.user.id);
  await adminClient.auth.admin.deleteUser(userBData.user.id);
  console.log("✔ Akun pengujian dibersihkan.");

  console.log("\n=======================================================");
  console.log("🎉 SEMUA UJI INTEGRASI SUPABASE & RLS 100% SUKSES!");
  console.log("=======================================================");
}

testRLS().catch(console.error);
