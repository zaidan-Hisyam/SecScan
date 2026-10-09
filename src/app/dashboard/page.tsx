import { redirect } from "next/navigation";
import { Shield, Terminal, Globe, Activity, CheckCircle2 } from "lucide-react";
import { createClient } from "@/lib/supabase/server";
import { LogoutButton } from "@/components/auth/LogoutButton";
import { DomainManager } from "@/components/domains/DomainManager";
import { Database } from "@/types/database";

type DomainRow = Database["public"]["Tables"]["domains"]["Row"];
type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
type ProfileRow = Database["public"]["Tables"]["profiles"]["Row"];

export default async function DashboardPage() {
  const supabase = await createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  // Mengambil profile user
  const { data: profile } = await supabase
    .from("profiles")
    .select("*")
    .eq("id", user.id)
    .single<ProfileRow>();

  // Mengambil daftar domain milik user (dilindungi RLS)
  const { data: domains } = await supabase
    .from("domains")
    .select("*")
    .order("created_at", { ascending: false })
    .returns<DomainRow[]>();

  // Mengambil daftar scans milik user (dilindungi RLS)
  const { data: scans } = await supabase
    .from("scans")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(10)
    .returns<ScanRow[]>();

  const domainList = domains || [];
  const scanList = scans || [];

  return (
    <div className="min-h-screen bg-[#0a0c10] text-[#e6edf3] flex flex-col">
      {/* Top Navbar */}
      <header className="border-b border-[#1b2230] bg-[#0d1117]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded border border-cyan-500/30 bg-cyan-950/40 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.15)]">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <span className="font-mono font-semibold tracking-wider text-sm text-slate-200">
                SECSCAN<span className="text-cyan-400">.LAB</span>
              </span>
              <span className="ml-2 px-2 py-0.5 text-[10px] font-mono rounded bg-cyan-950/50 text-cyan-400 border border-cyan-500/30">
                CONTROL CENTER
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-right hidden sm:block">
              <div className="text-xs font-mono text-slate-300">{profile?.email || user.email}</div>
              <div className="text-[10px] font-mono text-slate-500">UID: {user.id.slice(0, 8)}...</div>
            </div>
            <div className="h-4 w-px bg-[#1b2230] hidden sm:block" />
            <LogoutButton />
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-6 py-8 flex-1 w-full space-y-8">
        {/* Status Header */}
        <div className="p-6 rounded-lg border border-[#1b2230] bg-[#0d1117]/60 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-full bg-gradient-to-l from-cyan-500/5 to-transparent pointer-events-none" />
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
                <Terminal className="w-5 h-5 text-cyan-400" />
                STATUS KONSOL PEMINDAIAN
              </h1>
              <p className="text-xs text-slate-400 mt-1 font-sans">
                Selamat datang kembali, <span className="text-slate-200">{profile?.email || user.email}</span>. Sistem siap melakukan audit keamanan pasif.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="flex h-2.5 w-2.5 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              </span>
              <span className="text-xs font-mono text-emerald-400">RLS ACTIVE • PASSIVE ENGINE READY</span>
            </div>
          </div>
        </div>

        {/* Metrics Overview */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="p-5 rounded-lg border border-[#1b2230] bg-[#0d1117]/40">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400 uppercase">Domain Terdaftar</span>
              <Globe className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-mono font-bold text-white">{domainList.length}</div>
            <div className="text-[11px] font-mono text-slate-500 mt-1">
              {domainList.filter((d) => d.verified).length} terverifikasi
            </div>
          </div>

          <div className="p-5 rounded-lg border border-[#1b2230] bg-[#0d1117]/40">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400 uppercase">Total Pemindaian</span>
              <Activity className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-mono font-bold text-white">{scanList.length}</div>
            <div className="text-[11px] font-mono text-slate-500 mt-1">Audit pasif tersimpan</div>
          </div>

          <div className="p-5 rounded-lg border border-[#1b2230] bg-[#0d1117]/40">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400 uppercase">Status Scanner</span>
              <CheckCircle2 className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-mono font-bold text-emerald-400">AKTIF</div>
            <div className="text-[11px] font-mono text-slate-500 mt-1">Headers, Cookies, CORS & SSL</div>
          </div>
        </div>

        {/* Domain Management Component */}
        <DomainManager initialDomains={domainList} initialScans={scanList} />
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1b2230] py-4 text-center text-xs font-mono text-slate-600">
        SecScan Engine • RLS Enabled • Zero Trust Architecture
      </footer>
    </div>
  );
}
