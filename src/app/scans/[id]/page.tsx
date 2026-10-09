import { redirect, notFound } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  ArrowLeft,
  AlertTriangle,
  Info,
  CheckCircle2,
  Clock,
  Globe,
  Terminal,
  FileCheck,
} from "lucide-react";
import { createClient } from "@/lib/supabase/server";
import { Database, SeverityLevel } from "@/types/database";

type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
type FindingRow = Database["public"]["Tables"]["findings"]["Row"];
type DomainRow = Database["public"]["Tables"]["domains"]["Row"];

interface ScanDetailPageProps {
  params: Promise<{ id: string }>;
}

export default async function ScanReportPage({ params }: ScanDetailPageProps) {
  const { id } = await params;
  const supabase = await createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  // Ambil detail scan beserta data domain terkait
  const { data: scan, error: scanErr } = await supabase
    .from("scans")
    .select("*, domains(*)")
    .eq("id", id)
    .single<ScanRow & { domains: DomainRow }>();

  if (scanErr || !scan) {
    notFound();
  }

  // Ambil temuan (findings)
  const { data: findings } = await supabase
    .from("findings")
    .select("*")
    .eq("scan_id", id)
    .order("created_at", { ascending: true })
    .returns<FindingRow[]>();

  const findingList = findings || [];

  // Severity count badges
  const severityBreakdown: Record<SeverityLevel, number> = {
    critical: findingList.filter((f) => f.severity === "critical").length,
    high: findingList.filter((f) => f.severity === "high").length,
    medium: findingList.filter((f) => f.severity === "medium").length,
    low: findingList.filter((f) => f.severity === "low").length,
    info: findingList.filter((f) => f.severity === "info").length,
  };

  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case "critical":
        return "bg-rose-950/80 text-rose-300 border-rose-500/40";
      case "high":
        return "bg-red-950/80 text-red-300 border-red-500/40";
      case "medium":
        return "bg-amber-950/80 text-amber-300 border-amber-500/40";
      case "low":
        return "bg-yellow-950/80 text-yellow-300 border-yellow-500/40";
      case "info":
        return "bg-cyan-950/80 text-cyan-300 border-cyan-500/40";
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0c10] text-[#e6edf3] flex flex-col">
      {/* Top Navbar */}
      <header className="border-b border-[#1b2230] bg-[#0d1117]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link
              href="/dashboard"
              className="p-2 text-slate-400 hover:text-white rounded border border-[#1b2230] bg-[#11141c] hover:bg-[#1b2230] transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
            </Link>
            <div>
              <span className="font-mono font-semibold tracking-wider text-sm text-slate-200">
                LAPORAN AUDIT KEAMANAN
              </span>
              <span className="ml-2 px-2 py-0.5 text-[10px] font-mono rounded bg-cyan-950/50 text-cyan-400 border border-cyan-500/30">
                SCAN ID: {scan.id.slice(0, 8)}...
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span
              className={`px-2.5 py-1 text-xs font-mono font-semibold rounded border uppercase ${
                scan.status === "done"
                  ? "bg-emerald-950/50 text-emerald-400 border-emerald-500/30"
                  : scan.status === "failed"
                  ? "bg-red-950/50 text-red-400 border-red-500/30"
                  : "bg-cyan-950/50 text-cyan-400 border-cyan-500/30"
              }`}
            >
              STATUS: {scan.status}
            </span>
          </div>
        </div>
      </header>

      {/* Main Report Container */}
      <main className="max-w-6xl mx-auto px-6 py-8 flex-1 w-full space-y-6">
        {/* Domain & Target Header */}
        <div className="p-6 rounded-lg border border-[#1b2230] bg-[#0d1117]/60 backdrop-blur-sm">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
                <Globe className="w-3.5 h-3.5" />
                <span>DOMAIN TARGET AUDIT</span>
              </div>
              <h1 className="text-2xl font-mono font-bold text-white tracking-wide">
                {scan.domains?.hostname || "Target Hostname"}
              </h1>
              <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400 mt-2">
                <span className="flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-slate-500" />
                  Waktu: {new Date(scan.created_at).toLocaleString("id-ID")}
                </span>
                <span className="flex items-center gap-1.5">
                  <FileCheck className="w-3.5 h-3.5 text-emerald-400" />
                  Pemeriksaan Pasif & Non-Destruktif
                </span>
              </div>
            </div>

            {/* Severity Pill Counts */}
            <div className="flex items-center gap-2 flex-wrap">
              <div className="px-3 py-1.5 rounded border border-rose-500/30 bg-rose-950/30 text-center">
                <div className="text-[10px] font-mono text-rose-400 uppercase">Kritis</div>
                <div className="text-sm font-mono font-bold text-rose-300">{severityBreakdown.critical}</div>
              </div>
              <div className="px-3 py-1.5 rounded border border-red-500/30 bg-red-950/30 text-center">
                <div className="text-[10px] font-mono text-red-400 uppercase">Tinggi</div>
                <div className="text-sm font-mono font-bold text-red-300">{severityBreakdown.high}</div>
              </div>
              <div className="px-3 py-1.5 rounded border border-amber-500/30 bg-amber-950/30 text-center">
                <div className="text-[10px] font-mono text-amber-400 uppercase">Sedang</div>
                <div className="text-sm font-mono font-bold text-amber-300">{severityBreakdown.medium}</div>
              </div>
              <div className="px-3 py-1.5 rounded border border-yellow-500/30 bg-yellow-950/30 text-center">
                <div className="text-[10px] font-mono text-yellow-400 uppercase">Rendah</div>
                <div className="text-sm font-mono font-bold text-yellow-300">{severityBreakdown.low}</div>
              </div>
              <div className="px-3 py-1.5 rounded border border-cyan-500/30 bg-cyan-950/30 text-center">
                <div className="text-[10px] font-mono text-cyan-400 uppercase">Info</div>
                <div className="text-sm font-mono font-bold text-cyan-300">{severityBreakdown.info}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Findings List */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-mono font-bold text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              DAFTAR TEMUAN AUDIT KEAMANAN ({findingList.length})
            </h2>
          </div>

          {findingList.length === 0 ? (
            <div className="p-8 rounded-lg border border-dashed border-[#21262d] bg-[#0d1117]/30 text-center">
              <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
              <h3 className="font-mono font-semibold text-sm text-slate-200">
                Tidak Ada Kerentanan Terdeteksi
              </h3>
              <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto font-sans">
                Seluruh security headers, kebijakan cookie, dan konfigurasi CORS berada dalam kondisi aman pada pengujian pasif ini.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {findingList.map((item, index) => (
                <div
                  key={item.id || index}
                  className="p-5 rounded-lg border border-[#1b2230] bg-[#0d1117]/90 hover:border-[#2a3447] transition-all space-y-3"
                >
                  {/* Finding Title & Severity Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <span
                        className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded border uppercase ${getSeverityBadge(
                          item.severity
                        )}`}
                      >
                        {item.severity}
                      </span>
                      <h3 className="text-sm font-mono font-semibold text-white tracking-wide">
                        {item.title}
                      </h3>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">
                      Rule: {item.rule_id}
                    </span>
                  </div>

                  {/* Description */}
                  <div className="text-xs text-slate-300 leading-relaxed font-sans">
                    {item.description}
                  </div>

                  {/* Evidence Box */}
                  {item.evidence && (
                    <div className="p-3 rounded border border-[#1b2230] bg-[#06080b] font-mono text-xs text-slate-400">
                      <div className="text-[10px] uppercase text-slate-500 mb-1">Bukti Temuan (Evidence):</div>
                      <div className="break-all text-cyan-300/90">{item.evidence}</div>
                    </div>
                  )}

                  {/* Remediation Box */}
                  <div className="p-3.5 rounded border border-emerald-500/20 bg-emerald-950/20 text-xs">
                    <div className="text-[10px] font-mono uppercase text-emerald-400 font-bold mb-1 flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5" />
                      Saran Perbaikan (Remediation):
                    </div>
                    <div className="text-slate-200 font-sans leading-relaxed">
                      {item.remediation}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1b2230] py-4 text-center text-xs font-mono text-slate-600">
        SecScan Lab • Confidential Security Report • RLS Enforced
      </footer>
    </div>
  );
}
