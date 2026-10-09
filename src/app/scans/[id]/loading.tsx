import { Loader2 } from "lucide-react";

export default function LoadingPage() {
  return (
    <div className="min-h-screen bg-[#0a0c10] text-[#e6edf3] flex items-center justify-center p-6">
      <div className="text-center space-y-3">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
        <div className="text-sm font-mono text-slate-300">Memuat Laporan Audit Keamanan...</div>
        <div className="text-xs font-mono text-slate-500">Mengambil data temuan dari database aman</div>
      </div>
    </div>
  );
}
