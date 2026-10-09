"use client";

import { useState } from "react";
import { Globe, Plus, AlertCircle, CheckCircle2, ArrowRight } from "lucide-react";
import { Database } from "@/types/database";

type DomainRow = Database["public"]["Tables"]["domains"]["Row"];

interface AddDomainModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (newDomain: DomainRow) => void;
}

export function AddDomainModal({ isOpen, onClose, onSuccess }: AddDomainModalProps) {
  const [hostname, setHostname] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/domains", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Gagal menambahkan domain");
        return;
      }

      onSuccess(data.domain);
      setHostname("");
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Terjadi kesalahan jaringan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-lg p-6 rounded-lg border border-[#1b2230] bg-[#0d1117] shadow-2xl relative">
        <div className="flex items-center justify-between pb-4 border-b border-[#1b2230] mb-5">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded border border-cyan-500/30 bg-cyan-950/40 flex items-center justify-center text-cyan-400">
              <Plus className="w-4 h-4" />
            </div>
            <h2 className="font-mono font-bold text-sm text-white tracking-wide">
              TAMBAH DOMAIN TARGET
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 font-mono text-sm px-2 py-1"
          >
            ✕
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded border border-red-500/30 bg-red-950/30 text-red-300 text-xs flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1.5 uppercase tracking-wider">
              Nama Host / Domain (FQDN)
            </label>
            <div className="relative">
              <Globe className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                required
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                placeholder="contoh: mysite.com atau app.myproject.id"
                className="w-full pl-9 pr-3 py-2 text-sm bg-[#06080b] border border-[#21262d] rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
              />
            </div>
            <p className="text-[11px] text-slate-500 mt-1.5 font-sans leading-relaxed">
              Hanya masukkan nama domain atau subdomain milik Anda sendiri. Skema (https://) dan path akan dinormalisasi secara otomatis.
            </p>
          </div>

          <div className="p-3 rounded border border-cyan-500/20 bg-cyan-950/20 text-slate-300 text-xs flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <span>
              Sistem akan membuat token unik untuk memverifikasi kepemilikan Anda melalui DNS TXT atau file HTTP.
            </span>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="px-4 py-2 text-xs font-mono text-slate-400 hover:text-white rounded border border-[#21262d] bg-[#11141c] hover:bg-[#1b2230] transition-colors"
            >
              Batal
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2 rounded border border-cyan-500 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60 hover:shadow-[0_0_15px_rgba(0,240,255,0.2)] text-xs font-mono font-semibold tracking-wider transition-all flex items-center gap-2 disabled:opacity-50"
            >
              {loading ? "Menyimpan..." : "Simpan Domain"}
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
