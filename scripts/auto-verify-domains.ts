import { createClient } from "@supabase/supabase-js";
import * as dotenv from "dotenv";
import * as path from "path";
import { Database } from "../src/types/database";

dotenv.config({ path: path.resolve(process.cwd(), ".env.local") });

async function autoVerifyExistingDomains() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("❌ Kredensial Supabase belum lengkap di .env.local");
    process.exit(1);
  }

  const adminClient = createClient<Database>(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  console.log("Mengupdate seluruh domain yang ada agar langsung berstatus verified=true...");

  const { data, error } = await adminClient
    .from("domains")
    .update({
      verified: true,
      verified_at: new Date().toISOString(),
    } as never)
    .eq("verified", false)
    .select();

  if (error) {
    console.error("Gagal update domain:", error.message);
  } else {
    console.log(`✔ Berhasil memverifikasi otomatis ${data?.length || 0} domain.`);
  }
}

autoVerifyExistingDomains().catch(console.error);
