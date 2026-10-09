import { Client } from "pg";
import * as dotenv from "dotenv";
import * as path from "path";
import * as fs from "fs";

dotenv.config({ path: path.resolve(process.cwd(), ".env.local") });

async function runDirectMigration() {
  const dbUrl = process.env.DATABASE_URL;

  if (!dbUrl) {
    console.log("DATABASE_URL belum diatur di .env.local.");
    return;
  }

  const client = new Client({
    connectionString: dbUrl,
    ssl: { rejectUnauthorized: false }
  });

  try {
    await client.connect();
    console.log("Terhubung langsung ke PostgreSQL Supabase!");

    const sqlPath = path.resolve(process.cwd(), "supabase/migrations/20261009000000_phase1_foundation.sql");
    const sql = fs.readFileSync(sqlPath, "utf-8");

    await client.query(sql);
    console.log("✔ Migrasi SQL berhasil dieksekusi 100%!");
  } catch (err: unknown) {
    console.error("Gagal menjalankan migrasi:", err instanceof Error ? err.message : err);
  } finally {
    await client.end();
  }
}

runDirectMigration();
