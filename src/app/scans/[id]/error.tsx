"use client";

import Link from "next/link";
import { AlertCircle, RotateCcw, ArrowLeft } from "lucide-react";

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="min-h-screen bg-[#0a0c10] text-[#e6edf3] flex items-center justify-center p-6">
      <div className="max-w-md w-full p-8 rounded-lg border border-red-500/30 bg-[#0d1117] text-center space-y-4">
        <div className="w-12 h-12 rounded-full border border-red-500/40 bg-red-950/40 text-red-400 flex items-center justify-center mx-auto">
          <AlertCircle className="w-6 h-6" />
        </div>
        <h1 className="text-lg font-mono font-bold text-white">Gagal Memuat Laporan</h1>
        <p className="text-xs text-red-300/80 font-mono bg-red-950/20 p-2.5 rounded border border-red-500/20 break-all">
          {error.message || "Terjadi kesalahan sistem saat memproses data laporan audit."}
        </p>
        <div className="flex items-center justify-center gap-3 pt-2">
          <button
            onClick={() => reset()}
            className="px-4 py-2 rounded border border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700 text-xs font-mono transition-all flex items-center gap-1.5"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Coba Lagi
          </button>
          <Link
            href="/dashboard"
            className="px-4 py-2 rounded border border-cyan-500 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60 text-xs font-mono transition-all flex items-center gap-1.5"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
