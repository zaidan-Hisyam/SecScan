"use client";

import { useState } from "react";
import { Copy, Check, FileText, Server, AlertCircle, RefreshCw, CheckCircle2, ShieldAlert } from "lucide-react";
import { Database } from "@/types/database";

type DomainRow = Database["public"]["Tables"]["domains"]["Row"];

interface DomainVerificationModalProps {
  domain: DomainRow | null;
  isOpen: boolean;
  onClose: () => void;
  onVerified: (updatedDomain: DomainRow) => void;
}

export function DomainVerificationModal({
  domain,
  isOpen,
  onClose,
  onVerified,
}: DomainVerificationModalProps) {
  const [activeTab, setActiveTab] = useState<"dns" | "file">("dns");
  const [verifying, setVerifying] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  if (!isOpen || !domain) return null;

  const copyToClipboard = (text: string, fieldId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldId);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleVerify = async () => {
    setVerifying(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`/api/domains/${domain.id}/verify`, {
        method: "POST",
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Verifikasi kepemilikan gagal.");
        return;
      }

      setSuccessMsg(data.message || "Domain berhasil diverifikasi!");
      onVerified(data.domain);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Terjadi kesalahan jaringan");
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-2xl p-6 rounded-lg border border-[#1b2230] bg-[#0d1117] shadow-2xl relative">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-[#1b2230] mb-5">
          <div>
            <span className="text-[10px] font-mono tracking-widest text-cyan-400 uppercase">
              VERIFIKASI KEPEMILIKAN DOMAIN
            </span>
            <h2 className="font-mono font-bold text-base text-white tracking-wide mt-0.5">
              {domain.hostname}
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
            <div className="flex-1">
              <span className="font-semibold block font-mono">Verifikasi Gagal:</span>
              <span>{error}</span>
            </div>
          </div>
        )}

        {successMsg && (
          <div className="mb-4 p-3 rounded border border-emerald-500/30 bg-emerald-950/30 text-emerald-300 text-xs flex items-start gap-2.5">
            <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-400" />
            <div>
              <span className="font-semibold block font-mono">Berhasil:</span>
              <span>{successMsg}</span>
            </div>
          </div>
        )}

        {/* Tab Selection */}
        <div className="flex border-b border-[#1b2230] mb-5 gap-2">
          <button
            onClick={() => setActiveTab("dns")}
            className={`pb-2.5 px-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-all ${
              activeTab === "dns"
                ? "border-cyan-400 text-cyan-300 bg-cyan-950/20"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            Metode 1: DNS TXT Record (Rekomendasi)
          </button>
          <button
            onClick={() => setActiveTab("file")}
            className={`pb-2.5 px-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-all ${
              activeTab === "file"
                ? "border-cyan-400 text-cyan-300 bg-cyan-950/20"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            Metode 2: File Token HTTP
          </button>
        </div>

        {/* Method 1: DNS TXT */}
        {activeTab === "dns" && (
          <div className="space-y-4 text-xs">
            <p className="text-slate-400 leading-relaxed font-sans">
              Tambahkan DNS TXT Record pada penyedia domain Anda (Cloudflare, Namecheap, Niagahoster, dll.) dengan konfigurasi berikut:
            </p>

            <div className="p-4 rounded border border-[#1b2230] bg-[#06080b] space-y-3 font-mono">
              <div className="flex items-center justify-between border-b border-[#1b2230] pb-2">
                <span className="text-slate-500">Tipe Record:</span>
                <span className="text-cyan-400 font-bold">TXT</span>
              </div>

              <div className="flex items-center justify-between border-b border-[#1b2230] pb-2">
                <span className="text-slate-500">Nama Host / Name:</span>
                <div className="flex items-center gap-2">
                  <span className="text-slate-200">@</span>
                  <span className="text-slate-500">atau</span>
                  <span className="text-slate-200">_secscan-challenge</span>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between text-slate-500 mb-1">
                  <span>Isi / Nilai (TXT Value):</span>
                  <button
                    onClick={() => copyToClipboard(domain.verify_token, "txt_val")}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px]"
                  >
                    {copiedField === "txt_val" ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" />
                        <span className="text-emerald-400">Tersalin</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Salin Token</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="p-2 rounded bg-[#0d1117] border border-[#21262d] text-emerald-400 break-all select-all font-mono">
                  {domain.verify_token}
                </div>
              </div>
            </div>

            <div className="text-[11px] text-slate-500 font-sans">
              Catatan: Propagasi DNS umumnya berlangsung 1–5 menit tergantung TTL domain Anda.
            </div>
          </div>
        )}

        {/* Method 2: File Token */}
        {activeTab === "file" && (
          <div className="space-y-4 text-xs">
            <p className="text-slate-400 leading-relaxed font-sans">
              Unggah file teks sederhana ke web server Anda pada jalur (path) publik berikut:
            </p>

            <div className="p-4 rounded border border-[#1b2230] bg-[#06080b] space-y-3 font-mono">
              <div>
                <div className="flex items-center justify-between text-slate-500 mb-1">
                  <span>Jalur URL File (Path):</span>
                  <button
                    onClick={() =>
                      copyToClipboard(
                        `https://${domain.hostname}/.well-known/secscan-challenge.txt`,
                        "file_path"
                      )
                    }
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px]"
                  >
                    {copiedField === "file_path" ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" />
                        <span className="text-emerald-400">Tersalin</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Salin URL</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="p-2 rounded bg-[#0d1117] border border-[#21262d] text-cyan-300 break-all select-all font-mono">
                  https://{domain.hostname}/.well-known/secscan-challenge.txt
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between text-slate-500 mb-1">
                  <span>Isi File Teks (File Content):</span>
                  <button
                    onClick={() => copyToClipboard(domain.verify_token, "file_val")}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px]"
                  >
                    {copiedField === "file_val" ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" />
                        <span className="text-emerald-400">Tersalin</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Salin Isi</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="p-2 rounded bg-[#0d1117] border border-[#21262d] text-emerald-400 break-all select-all font-mono">
                  {domain.verify_token}
                </div>
              </div>
            </div>

            <div className="text-[11px] text-slate-500 font-sans">
              Pastikan file dapat diakses secara publik dan mengembalikan status HTTP 200 OK.
            </div>
          </div>
        )}

        {/* Security Rule Reminder */}
        <div className="mt-5 p-3 rounded border border-amber-500/20 bg-amber-950/10 text-amber-300/90 text-xs flex items-start gap-2">
          <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <span>
            Aturan Keamanan Wajib: Tombol pemindaian hanya akan aktif setelah domain berstatus TERVERIFIKASI.
          </span>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-between pt-5 mt-4 border-t border-[#1b2230]">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-mono text-slate-400 hover:text-white rounded border border-[#21262d] bg-[#11141c] hover:bg-[#1b2230] transition-colors"
          >
            Tutup
          </button>
          <button
            onClick={handleVerify}
            disabled={verifying}
            className="px-5 py-2 rounded border border-cyan-500 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60 hover:shadow-[0_0_15px_rgba(0,240,255,0.2)] text-xs font-mono font-semibold tracking-wider transition-all flex items-center gap-2 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${verifying ? "animate-spin" : ""}`} />
            {verifying ? "Memeriksa DNS & File..." : "Verifikasi Sekarang"}
          </button>
        </div>
      </div>
    </div>
  );
}
