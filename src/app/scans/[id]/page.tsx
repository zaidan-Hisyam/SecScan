import { redirect, notFound } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { ScanReportClient } from "@/components/scans/ScanReportClient";
import { Database } from "@/types/database";

type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
type FindingRow = Database["public"]["Tables"]["findings"]["Row"];
type DomainRow = Database["public"]["Tables"]["domains"]["Row"];

interface ScanDetailPageProps {
  params: Promise<{ id: string }>;
}

export default async function ScanReportPage({ params }: ScanDetailPageProps) {
  const { id } = await params;
  const supabase = await createClient();

  // 1. Cek Autentikasi Pengguna
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  // 2. Ambil detail scan beserta domain terkait (Dilindungi RLS)
  const { data: scan, error: scanErr } = await supabase
    .from("scans")
    .select("*, domains(*)")
    .eq("id", id)
    .single<ScanRow & { domains: DomainRow | null }>();

  if (scanErr || !scan) {
    notFound();
  }

  // 3. Ambil temuan (findings) untuk scan ini
  const { data: findings, error: findingsErr } = await supabase
    .from("findings")
    .select("*")
    .eq("scan_id", id)
    .order("created_at", { ascending: true })
    .returns<FindingRow[]>();

  if (findingsErr) {
    console.error("Gagal mengambil findings:", findingsErr.message);
  }

  // 4. Ambil riwayat pemindaian lain pada domain yang sama untuk konteks perbandingan
  let historyScans: ScanRow[] = [];
  if (scan.domain_id) {
    const { data: domainScans } = await supabase
      .from("scans")
      .select("*")
      .eq("domain_id", scan.domain_id)
      .order("created_at", { ascending: false })
      .limit(6)
      .returns<ScanRow[]>();

    historyScans = domainScans || [];
  }

  return (
    <ScanReportClient
      scan={scan}
      findings={findings || []}
      historyScans={historyScans}
    />
  );
}
