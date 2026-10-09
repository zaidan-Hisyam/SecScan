import { createClient } from "@supabase/supabase-js";
import * as dotenv from "dotenv";
import * as path from "path";
import { Database } from "../src/types/database";

dotenv.config({ path: path.resolve(process.cwd(), ".env.local") });

async function createAdminUser() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("❌ NEXT_PUBLIC_SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY belum diatur di .env.local");
    process.exit(1);
  }

  const args = process.argv.slice(2);
  const email = args[0] || "admin@secscan.lab";
  const password = args[1] || "AdminSecScan2026!";

  const adminClient = createClient<Database>(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  console.log(`Membuat akun admin di Supabase...`);
  console.log(`Email: ${email}`);

  const { data, error } = await adminClient.auth.admin.createUser({
    email,
    password,
    email_confirm: true, // Otomatis aktif tanpa perlu klik verifikasi email
  });

  if (error) {
    if (error.message.includes("already registered") || error.message.includes("duplicate")) {
      console.log(`ℹ️ Akun dengan email ${email} sudah terdaftar. Anda bisa langsung login dengan password yang sudah dibuat.`);
    } else {
      console.error(`❌ Gagal membuat user: ${error.message}`);
    }
    return;
  }

  console.log(`\n🎉 AKUN ADMIN BERHASIL DIBUAT!`);
  console.log(`─────────────────────────────────────────────`);
  console.log(`Email    : ${email}`);
  console.log(`Password : ${password}`);
  console.log(`UID      : ${data.user?.id}`);
  console.log(`Status   : Email Terkonfirmasi (Siap Login)`);
  console.log(`─────────────────────────────────────────────`);
}

createAdminUser().catch(console.error);
