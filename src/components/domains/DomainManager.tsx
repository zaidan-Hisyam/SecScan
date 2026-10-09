"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  Globe,
  Plus,
  ShieldCheck,
  ShieldAlert,
  Play,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  Trash2,
  FileText,
  Loader2,
} from "lucide-react";
import Link from "next/link";
import { Database } from "@/types/database";
import { AddDomainModal } from "@/components/domains/AddDomainModal";
import { DomainVerificationModal } from "@/components/domains/DomainVerificationModal";

type DomainRow = Database["public"]["Tables"]["domains"]["Row"];
type ScanRow = Database["public"]["Tables"]["scans"]["Row"];

interface DomainManagerProps {
  initialDomains: DomainRow[];
  initialScans: ScanRow[];
}

export function DomainManager({ initialDomains, initialScans }: DomainManagerProps) {
  const router = useRouter();
  const [domains, setDomains] = useState<DomainRow[]>(initialDomains);
  const [scans, setScans] = useState<ScanRow[]>(initialScans);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [selectedVerifyDomain, setSelectedVerifyDomain] = useState<DomainRow | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: "success" | "error"; message: string } | null>(null);

  const showNotification = (type: "success" | "error", message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 5000);
  };

  const handleDomainAdded = (newDomain: DomainRow) => {
    setDomains((prev) => [newDomain, ...prev]);
    showNotification("success", `Domain ${newDomain.hostname} berhasil ditambahkan! Silakan verifikasi.`);
    setSelectedVerifyDomain(newDomain);
  };

  const handleDomainVerified = (updatedDomain: DomainRow) => {
    setDomains((prev) =>
      prev.map((d) => (d.id === updatedDomain.id ? updatedDomain : d))
    );
    showNotification("success", `Domain ${updatedDomain.hostname} telah berhasil TERVERIFIKASI!`);
  };

  const handleTriggerScan = async (domain: DomainRow) => {
    if (!domain.verified) {
      showNotification(
        "error",
        `Gagal: Domain ${domain.hostname} belum terverifikasi. Anda wajib memverifikasi domain terlebih dahulu.`
      );
      return;
    }

    setActionLoading(domain.id);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain_id: domain.id }),
      });

      const data = await res.json();

      if (!res.ok) {
        showNotification("error", data.error || "Gagal memulai scan");
        return;
      }

      showNotification(
        "success",
        `Pemindaian pasif untuk ${domain.hostname} selesai! Ditemukan ${data.findings_count} temuan.`
      );

      if (data.scan) {
        setScans((prev) => [data.scan, ...prev]);
        // Buka otomatis laporan scan
        router.push(`/scans/${data.scan.id}`);
      }
    } catch (err: unknown) {
      showNotification("error", err instanceof Error ? err.message : "Kesalahan jaringan");
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteDomain = async (domain: DomainRow) => {
    if (!confirm(`Hapus domain ${domain.hostname} beserta riwayat pemindaiannya?`)) {
      return;
    }

    try {
      const res = await fetch(`/api/domains`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: domain.id }),
      });

      if (!res.ok) {
        const data = await res.json();
        showNotification("error", data.error || "Gagal menghapus domain");
        return;
      }

      setDomains((prev) => prev.filter((d) => d.id !== domain.id));
      showNotification("success", `Domain ${domain.hostname} berhasil dihapus.`);
    } catch (err: unknown) {
      showNotification("error", err instanceof Error ? err.message : "Gagal menghapus domain");
    }
  };

  return (
    <div className="space-y-8">
      {/* Toast Notification */}
      {notification && (
        <div
          className={`p-4 rounded-lg border text-xs flex items-center justify-between font-mono animate-in slide-in-from-top-2 duration-200 ${
            notification.type === "success"
              ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-300"
              : "bg-red-950/40 border-red-500/40 text-red-300"
          }`}
        >
          <div className="flex items-center gap-2.5">
            {notification.type === "success" ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            )}
            <span>{notification.message}</span>
          </div>
          <button
            onClick={() => setNotification(null)}
            className="text-slate-400 hover:text-white px-2"
          >
            ✕
          </button>
        </div>
      )}

      {/* Top Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-mono font-bold text-white flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" />
            DAFTAR DOMAIN TARGET
          </h2>
          <p className="text-xs text-slate-400 font-sans mt-0.5">
            Kelola domain milik Anda dan lakukan audit keamanan pasif sekali klik.
          </p>
        </div>

        <button
          onClick={() => setIsAddModalOpen(true)}
          className="px-4 py-2 rounded border border-cyan-500 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60 hover:shadow-[0_0_15px_rgba(0,240,255,0.2)] text-xs font-mono font-semibold tracking-wider transition-all flex items-center justify-center gap-2 self-start sm:self-auto"
        >
          <Plus className="w-3.5 h-3.5" />
          Tambah Domain
        </button>
      </div>

      {/* Domain Cards / Table */}
      {domains.length === 0 ? (
        <div className="p-8 rounded-lg border border-dashed border-[#21262d] bg-[#0d1117]/20 text-center">
          <Globe className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="font-mono font-semibold text-sm text-slate-300 mb-1">
            Belum Ada Domain Terdaftar
          </h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto mb-4 font-sans">
            Tambahkan nama host situs web milik Anda sendiri untuk memulai pengujian keamanan pasif.
          </p>
          <button
            onClick={() => setIsAddModalOpen(true)}
            className="px-4 py-2 rounded border border-cyan-500/40 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-900/40 text-xs font-mono font-medium transition-all"
          >
            + Tambah Domain Pertama
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {domains.map((dom) => (
            <div
              key={dom.id}
              className="p-4 rounded-lg border border-[#1b2230] bg-[#0d1117]/80 hover:border-[#2b3548] transition-all flex flex-col md:flex-row md:items-center justify-between gap-4"
            >
              {/* Domain Info */}
              <div className="space-y-1">
                <div className="flex items-center gap-2.5">
                  <span className="font-mono font-bold text-sm text-white">{dom.hostname}</span>
                  {dom.verified ? (
                    <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-emerald-950/60 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3" />
                      TERVERIFIKASI
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-amber-950/60 text-amber-400 border border-amber-500/30 flex items-center gap-1">
                      <ShieldAlert className="w-3 h-3" />
                      BELUM TERVERIFIKASI
                    </span>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] font-mono text-slate-500">
                  <span>Ditambahkan: {new Date(dom.created_at).toLocaleDateString("id-ID")}</span>
                  {dom.verified_at && (
                    <span>
                      Diverifikasi: {new Date(dom.verified_at).toLocaleDateString("id-ID")}
                    </span>
                  )}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2.5 self-end md:self-auto">
                {!dom.verified ? (
                  <button
                    onClick={() => setSelectedVerifyDomain(dom)}
                    className="px-3.5 py-1.5 rounded border border-amber-500/50 bg-amber-950/30 text-amber-300 hover:bg-amber-900/40 text-xs font-mono font-medium transition-all flex items-center gap-1.5"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    Instruksi Verifikasi
                  </button>
                ) : (
                  <button
                    onClick={() => handleTriggerScan(dom)}
                    disabled={actionLoading === dom.id}
                    className="px-4 py-1.5 rounded border border-cyan-500 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60 hover:shadow-[0_0_15px_rgba(0,240,255,0.2)] text-xs font-mono font-semibold tracking-wider transition-all flex items-center gap-1.5 disabled:opacity-50"
                  >
                    {actionLoading === dom.id ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Play className="w-3.5 h-3.5 fill-current" />
                    )}
                    {actionLoading === dom.id ? "Memindai..." : "Mulai Scan"}
                  </button>
                )}

                <button
                  onClick={() => handleDeleteDomain(dom)}
                  className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-950/20 border border-transparent hover:border-red-500/30 rounded transition-all"
                  title="Hapus domain"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Riwayat Pemindaian */}
      {scans.length > 0 && (
        <div className="space-y-3 pt-4 border-t border-[#1b2230]">
          <h3 className="text-sm font-mono font-bold text-white flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            RIWAYAT PEMINDAIAN TERAKHIR
          </h3>

          <div className="space-y-2">
            {scans.map((s) => (
              <div
                key={s.id}
                className="p-3.5 rounded-lg border border-[#1b2230] bg-[#0d1117]/50 flex items-center justify-between"
              >
                <div className="flex items-center gap-3">
                  <span
                    className={`px-2 py-0.5 text-[10px] font-mono rounded border uppercase ${
                      s.status === "done"
                        ? "bg-emerald-950/60 text-emerald-400 border-emerald-500/30"
                        : s.status === "failed"
                        ? "bg-red-950/60 text-red-400 border-red-500/30"
                        : "bg-cyan-950/60 text-cyan-400 border-cyan-500/30"
                    }`}
                  >
                    {s.status}
                  </span>
                  <span className="font-mono text-xs text-slate-300">
                    Scan ID: {s.id.slice(0, 8)}...
                  </span>
                  <span className="text-[11px] font-mono text-slate-500">
                    {new Date(s.created_at).toLocaleString("id-ID")}
                  </span>
                </div>

                <Link
                  href={`/scans/${s.id}`}
                  className="px-3 py-1 rounded border border-cyan-500/40 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-900/40 text-xs font-mono transition-all flex items-center gap-1"
                >
                  Buka Laporan
                </Link>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Modals */}
      <AddDomainModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSuccess={handleDomainAdded}
      />

      <DomainVerificationModal
        domain={selectedVerifyDomain}
        isOpen={!!selectedVerifyDomain}
        onClose={() => setSelectedVerifyDomain(null)}
        onVerified={handleDomainVerified}
      />
    </div>
  );
}
