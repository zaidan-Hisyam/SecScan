import { createClient } from "../supabase/server";
import { SupabaseClient } from "@supabase/supabase-js";
import { Database } from "../../types/database";

export interface RateLimitCheckResult {
  allowed: boolean;
  reason?: string;
  retryAfterSeconds?: number;
}

/**
 * Memeriksa batas frekuensi pemindaian:
 * 1. Batas per pengguna: Maksimal 20 scan per hari (24 jam terakhir)
 * 2. Batas per domain: Minimal jeda 60 detik antar scan untuk domain yang sama
 */
export async function checkScanRateLimit(
  userId: string,
  domainId: string,
  customClient?: SupabaseClient<Database>
): Promise<RateLimitCheckResult> {
  const supabase = customClient || (await createClient());

  const now = new Date();
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const oneMinuteAgo = new Date(now.getTime() - 60 * 1000).toISOString();

  // 1. Cek scan domain yang sama dalam 60 detik terakhir (Cegah spam request ke target yang sama)
  const { data: recentDomainScans, error: domainScanErr } = await supabase
    .from("scans")
    .select("id, created_at")
    .eq("domain_id", domainId)
    .gte("created_at", oneMinuteAgo);

  if (domainScanErr) {
    console.error("Gagal memeriksa rate limit domain:", domainScanErr.message);
  } else if (recentDomainScans && recentDomainScans.length > 0) {
    return {
      allowed: false,
      reason: "Rate limit domain: Harap tunggu minimal 1 menit sebelum memindai ulang domain yang sama.",
      retryAfterSeconds: 60,
    };
  }

  // 2. Cek kuota harian pengguna (Maksimal 20 scan dalam 24 jam)
  const { count: userDailyScanCount, error: userScanErr } = await supabase
    .from("scans")
    .select("*", { count: "exact", head: true })
    .eq("triggered_by", userId)
    .gte("created_at", oneDayAgo);

  if (userScanErr) {
    console.error("Gagal memeriksa rate limit pengguna:", userScanErr.message);
  } else if (userDailyScanCount !== null && userDailyScanCount >= 20) {
    return {
      allowed: false,
      reason: "Batas kuota harian tercapai: Maksimal 20 scan per hari per akun.",
      retryAfterSeconds: 3600,
    };
  }

  return { allowed: true };
}
