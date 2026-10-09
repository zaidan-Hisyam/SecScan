import Link from "next/link";
import { Shield, Lock, Terminal, CheckCircle2, ArrowRight } from "lucide-react";
import { createClient } from "@/lib/supabase/server";

export default async function HomePage() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  return (
    <main className="min-h-screen flex flex-col justify-between bg-[#0a0c10] bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(0,240,255,0.08),rgba(255,255,255,0))]">
      {/* Header */}
      <header className="border-b border-[#1b2230] bg-[#0d1117]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded border border-cyan-500/30 bg-cyan-950/40 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.15)]">
              <Shield className="w-4 h-4" />
            </div>
            <span className="font-mono font-semibold tracking-wider text-sm text-slate-200">
              SECSCAN<span className="text-cyan-400">.LAB</span>
            </span>
          </div>

          <div className="flex items-center gap-4">
            {user ? (
              <Link
                href="/dashboard"
                className="px-4 py-1.5 text-xs font-mono font-medium rounded border border-cyan-500/40 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-900/40 transition-all flex items-center gap-2 shadow-[0_0_15px_rgba(0,240,255,0.1)]"
              >
                Buka Dashboard
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            ) : (
              <>
                <Link
                  href="/login"
                  className="px-3.5 py-1.5 text-xs font-mono text-slate-300 hover:text-white transition-colors"
                >
                  Masuk
                </Link>
                <Link
                  href="/register"
                  className="px-4 py-1.5 text-xs font-mono font-medium rounded border border-cyan-500/40 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-900/40 transition-all shadow-[0_0_15px_rgba(0,240,255,0.1)]"
                >
                  Daftar
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="max-w-4xl mx-auto px-6 py-20 text-center flex-1 flex flex-col justify-center items-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded border border-slate-800 bg-slate-900/60 font-mono text-[11px] tracking-wider text-slate-400 mb-6">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>PEMINDAI KERENTANAN PASIF & NON-DESTRUKTIF</span>
        </div>

        <h1 className="text-4xl md:text-5xl font-mono font-bold tracking-tight text-white mb-6">
          Audit Keamanan Web <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-emerald-400 to-cyan-200">
            Khusus Domain Milik Sendiri
          </span>
        </h1>

        <p className="text-slate-400 text-sm md:text-base max-w-2xl mb-10 leading-relaxed font-sans">
          SecScan dirancang untuk memindai miskonfigurasi, headers, SSL/TLS, dan eksposur file sensitif
          tanpa risiko merusak sistem target. Wajib verifikasi kepemilikan sebelum pemindaian.
        </p>

        <div className="flex flex-col sm:flex-row items-center gap-4">
          <Link
            href={user ? "/dashboard" : "/register"}
            className="w-full sm:w-auto px-6 py-2.5 rounded text-xs font-mono font-semibold tracking-wider border border-cyan-500 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60 hover:shadow-[0_0_20px_rgba(0,240,255,0.25)] transition-all flex items-center justify-center gap-2"
          >
            {user ? "Masuk ke Dashboard" : "Mulai Pemindaian"}
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>

        {/* Feature Highlights */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-20 text-left w-full">
          <div className="p-5 rounded border border-[#1b2230] bg-[#0d1117]/60 backdrop-blur-sm">
            <Lock className="w-5 h-5 text-cyan-400 mb-3" />
            <h3 className="font-mono font-semibold text-sm text-slate-200 mb-1">Verifikasi Kepemilikan</h3>
            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              Scan hanya diizinkan jika DNS TXT atau token file telah tervalidasi secara sah.
            </p>
          </div>

          <div className="p-5 rounded border border-[#1b2230] bg-[#0d1117]/60 backdrop-blur-sm">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 mb-3" />
            <h3 className="font-mono font-semibold text-sm text-slate-200 mb-1">Pemeriksaan Pasif</h3>
            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              Hanya menggunakan metode GET, HEAD, OPTIONS. Tanpa payload eksploitasi dan tanpa beban berat.
            </p>
          </div>

          <div className="p-5 rounded border border-[#1b2230] bg-[#0d1117]/60 backdrop-blur-sm">
            <Shield className="w-5 h-5 text-purple-400 mb-3" />
            <h3 className="font-mono font-semibold text-sm text-slate-200 mb-1">RLS & Data Terisolasi</h3>
            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              Laporan temuan bersifat privat dan dilindungi Row Level Security ketat pada level basis data.
            </p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[#1b2230] py-6 text-center text-xs font-mono text-slate-500">
        SecScan Lab • Security Research & Passive Scanner
      </footer>
    </main>
  );
}
