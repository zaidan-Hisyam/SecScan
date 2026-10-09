import Link from "next/link";
import { ShieldAlert, ArrowLeft } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-[#0a0c10] text-[#e6edf3] flex items-center justify-center p-6">
      <div className="max-w-md w-full p-8 rounded-lg border border-[#1b2230] bg-[#0d1117] text-center space-y-4">
        <div className="w-12 h-12 rounded-full border border-red-500/40 bg-red-950/40 text-red-400 flex items-center justify-center mx-auto">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <h1 className="text-xl font-mono font-bold text-white">404 - Laporan Tidak Ditemukan</h1>
        <p className="text-xs text-slate-400 font-sans leading-relaxed">
          Sesi pemindaian tidak ditemukan di basis data atau Anda tidak memiliki hak akses (RLS) untuk melihat laporan audit ini.
        </p>
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-2 px-4 py-2 rounded border border-cyan-500 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60 text-xs font-mono transition-all"
        >
          <ArrowLeft className="w-4 h-4" />
          Kembali ke Dashboard
        </Link>
      </div>
    </div>
  );
}
