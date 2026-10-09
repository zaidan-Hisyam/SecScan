"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import {
  Shield,
  ArrowLeft,
  Printer,
  Search,
  Filter,
  ArrowUpDown,
  CheckCircle2,
  Clock,
  Globe,
  Terminal,
  FileCheck,
  AlertOctagon,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronUp,
  History,
} from "lucide-react";
import { Database, SeverityLevel } from "@/types/database";

type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
type FindingRow = Database["public"]["Tables"]["findings"]["Row"];
type DomainRow = Database["public"]["Tables"]["domains"]["Row"];

interface ScanReportClientProps {
  scan: ScanRow & { domains: DomainRow | null };
  findings: FindingRow[];
  historyScans: ScanRow[];
}

const SEVERITY_WEIGHT: Record<SeverityLevel, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function ScanReportClient({
  scan,
  findings,
  historyScans,
}: ScanReportClientProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [selectedTool, setSelectedTool] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"severity-desc" | "severity-asc" | "title" | "date">("severity-desc");
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  // Breakdown severity count
  const severityCount: Record<SeverityLevel, number> = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  // Daftar tool unik untuk filter
  const toolsList = useMemo(() => {
    const set = new Set<string>();
    findings.forEach((f) => {
      f.tool.split(",").forEach((t) => set.add(t.trim()));
    });
    return Array.from(set);
  }, [findings]);

  // Toggle accordion expand
  const toggleExpand = (id: string) => {
    setExpandedFindings((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const expandAll = () => {
    const allExpanded: Record<string, boolean> = {};
    findings.forEach((f) => (allExpanded[f.id] = true));
    setExpandedFindings(allExpanded);
  };

  const collapseAll = () => {
    setExpandedFindings({});
  };

  // Filter & Sort Findings
  const filteredFindings = useMemo(() => {
    return findings
      .filter((item) => {
        // Filter Severity
        if (selectedSeverity !== "all" && item.severity !== selectedSeverity) {
          return false;
        }
        // Filter Tool
        if (selectedTool !== "all" && !item.tool.includes(selectedTool)) {
          return false;
        }
        // Filter Search (Title, Description, Rule ID, Evidence)
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchTitle = item.title.toLowerCase().includes(q);
          const matchDesc = item.description.toLowerCase().includes(q);
          const matchRule = item.rule_id.toLowerCase().includes(q);
          const matchEvidence = (item.evidence || "").toLowerCase().includes(q);
          if (!matchTitle && !matchDesc && !matchRule && !matchEvidence) {
            return false;
          }
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === "severity-desc") {
          return SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity];
        }
        if (sortBy === "severity-asc") {
          return SEVERITY_WEIGHT[a.severity] - SEVERITY_WEIGHT[b.severity];
        }
        if (sortBy === "title") {
          return a.title.localeCompare(b.title);
        }
        if (sortBy === "date") {
          return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
        }
        return 0;
      });
  }, [findings, selectedSeverity, selectedTool, searchQuery, sortBy]);

  const getSeverityBadgeClass = (sev: SeverityLevel) => {
    switch (sev) {
      case "critical":
        return "bg-rose-950/80 text-rose-300 border-rose-500/50";
      case "high":
        return "bg-red-950/80 text-red-300 border-red-500/50";
      case "medium":
        return "bg-amber-950/80 text-amber-300 border-amber-500/50";
      case "low":
        return "bg-yellow-950/80 text-yellow-300 border-yellow-500/50";
      case "info":
        return "bg-cyan-950/80 text-cyan-300 border-cyan-500/50";
    }
  };

  const getSeverityIcon = (sev: SeverityLevel) => {
    switch (sev) {
      case "critical":
        return <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />;
      case "high":
        return <AlertTriangle className="w-3.5 h-3.5 text-red-400" />;
      case "medium":
        return <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />;
      case "low":
        return <Info className="w-3.5 h-3.5 text-yellow-400" />;
      case "info":
        return <Info className="w-3.5 h-3.5 text-cyan-400" />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0c10] text-[#e6edf3] flex flex-col print:bg-white print:text-black">
      {/* Top Navbar */}
      <header className="border-b border-[#1b2230] bg-[#0d1117]/80 backdrop-blur-md sticky top-0 z-50 no-print">
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
                ID: {scan.id.slice(0, 8)}...
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => window.print()}
              className="px-3.5 py-1.5 rounded border border-cyan-500/40 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-900/40 text-xs font-mono font-medium transition-all flex items-center gap-1.5 shadow-[0_0_10px_rgba(0,240,255,0.1)]"
            >
              <Printer className="w-3.5 h-3.5" />
              Cetak / Ekspor PDF
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-6xl mx-auto px-6 py-8 flex-1 w-full space-y-6 print-page-container">
        {/* Header Metadata Target */}
        <div className="p-6 rounded-lg border border-[#1b2230] bg-[#0d1117]/70 backdrop-blur-sm print-card">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1 print-text-muted">
                <Globe className="w-3.5 h-3.5" />
                <span>DOMAIN TARGET AUDIT (TERVERIFIKASI)</span>
              </div>
              <h1 className="text-2xl font-mono font-bold text-white tracking-wide print-text-dark">
                {scan.domains?.hostname || "Hostname Target"}
              </h1>
              <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400 mt-2 print-text-muted">
                <span className="flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-slate-500" />
                  Waktu Scan: {new Date(scan.created_at).toLocaleString("id-ID")}
                </span>
                <span className="flex items-center gap-1.5">
                  <FileCheck className="w-3.5 h-3.5 text-emerald-400" />
                  Audit Pasif & Non-Destruktif
                </span>
                <span
                  className={`px-2 py-0.5 text-[10px] rounded uppercase font-bold border ${
                    scan.status === "done"
                      ? "bg-emerald-950/60 text-emerald-400 border-emerald-500/30"
                      : "bg-red-950/60 text-red-400 border-red-500/30"
                  }`}
                >
                  Status: {scan.status}
                </span>
              </div>
            </div>

            {/* Severity Breakdown Counter Cards */}
            <div className="flex items-center gap-2 flex-wrap">
              <div
                onClick={() => setSelectedSeverity(selectedSeverity === "critical" ? "all" : "critical")}
                className={`px-3.5 py-2 rounded border cursor-pointer transition-all text-center ${
                  selectedSeverity === "critical"
                    ? "border-rose-500 bg-rose-950/80 shadow-[0_0_10px_rgba(244,63,94,0.3)]"
                    : "border-rose-500/30 bg-rose-950/20 hover:bg-rose-950/40"
                }`}
              >
                <div className="text-[10px] font-mono text-rose-400 uppercase">Kritis</div>
                <div className="text-base font-mono font-bold text-rose-300">{severityCount.critical}</div>
              </div>

              <div
                onClick={() => setSelectedSeverity(selectedSeverity === "high" ? "all" : "high")}
                className={`px-3.5 py-2 rounded border cursor-pointer transition-all text-center ${
                  selectedSeverity === "high"
                    ? "border-red-500 bg-red-950/80 shadow-[0_0_10px_rgba(239,68,68,0.3)]"
                    : "border-red-500/30 bg-red-950/20 hover:bg-red-950/40"
                }`}
              >
                <div className="text-[10px] font-mono text-red-400 uppercase">Tinggi</div>
                <div className="text-base font-mono font-bold text-red-300">{severityCount.high}</div>
              </div>

              <div
                onClick={() => setSelectedSeverity(selectedSeverity === "medium" ? "all" : "medium")}
                className={`px-3.5 py-2 rounded border cursor-pointer transition-all text-center ${
                  selectedSeverity === "medium"
                    ? "border-amber-500 bg-amber-950/80 shadow-[0_0_10px_rgba(245,158,11,0.3)]"
                    : "border-amber-500/30 bg-amber-950/20 hover:bg-amber-950/40"
                }`}
              >
                <div className="text-[10px] font-mono text-amber-400 uppercase">Sedang</div>
                <div className="text-base font-mono font-bold text-amber-300">{severityCount.medium}</div>
              </div>

              <div
                onClick={() => setSelectedSeverity(selectedSeverity === "low" ? "all" : "low")}
                className={`px-3.5 py-2 rounded border cursor-pointer transition-all text-center ${
                  selectedSeverity === "low"
                    ? "border-yellow-500 bg-yellow-950/80 shadow-[0_0_10px_rgba(234,179,8,0.3)]"
                    : "border-yellow-500/30 bg-yellow-950/20 hover:bg-yellow-950/40"
                }`}
              >
                <div className="text-[10px] font-mono text-yellow-400 uppercase">Rendah</div>
                <div className="text-base font-mono font-bold text-yellow-300">{severityCount.low}</div>
              </div>

              <div
                onClick={() => setSelectedSeverity(selectedSeverity === "info" ? "all" : "info")}
                className={`px-3.5 py-2 rounded border cursor-pointer transition-all text-center ${
                  selectedSeverity === "info"
                    ? "border-cyan-500 bg-cyan-950/80 shadow-[0_0_10px_rgba(6,182,212,0.3)]"
                    : "border-cyan-500/30 bg-cyan-950/20 hover:bg-cyan-950/40"
                }`}
              >
                <div className="text-[10px] font-mono text-cyan-400 uppercase">Info</div>
                <div className="text-base font-mono font-bold text-cyan-300">{severityCount.info}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Filter & Toolbar Area (Disembunyikan saat dicetak) */}
        <div className="p-4 rounded-lg border border-[#1b2230] bg-[#0d1117]/50 space-y-3 no-print">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            {/* Search Box */}
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Cari temuan (judul, deskripsi, rule_id, evidence)..."
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-[#06080b] border border-[#21262d] rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-sans"
              />
            </div>

            {/* Controls */}
            <div className="flex flex-wrap items-center gap-2.5">
              {/* Severity Filter */}
              <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
                <Filter className="w-3.5 h-3.5 text-cyan-400" />
                <select
                  value={selectedSeverity}
                  onChange={(e) => setSelectedSeverity(e.target.value)}
                  className="bg-[#06080b] border border-[#21262d] rounded px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="all">Semua Severity</option>
                  <option value="critical">Kritis ({severityCount.critical})</option>
                  <option value="high">Tinggi ({severityCount.high})</option>
                  <option value="medium">Sedang ({severityCount.medium})</option>
                  <option value="low">Rendah ({severityCount.low})</option>
                  <option value="info">Info ({severityCount.info})</option>
                </select>
              </div>

              {/* Tool Filter */}
              {toolsList.length > 1 && (
                <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
                  <select
                    value={selectedTool}
                    onChange={(e) => setSelectedTool(e.target.value)}
                    className="bg-[#06080b] border border-[#21262d] rounded px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="all">Semua Tool</option>
                    {toolsList.map((t) => (
                      <option key={t} value={t}>
                        Tool: {t}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Sort By */}
              <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
                <ArrowUpDown className="w-3.5 h-3.5 text-cyan-400" />
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as any)}
                  className="bg-[#06080b] border border-[#21262d] rounded px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="severity-desc">Severity (Tertinggi)</option>
                  <option value="severity-asc">Severity (Terendah)</option>
                  <option value="title">Judul (A-Z)</option>
                  <option value="date">Terbaru</option>
                </select>
              </div>

              {/* Expand / Collapse All */}
              <button
                onClick={expandAll}
                className="px-2.5 py-1 text-[11px] font-mono text-slate-400 hover:text-white rounded border border-[#21262d] bg-[#11141c]"
              >
                Buka Semua
              </button>
              <button
                onClick={collapseAll}
                className="px-2.5 py-1 text-[11px] font-mono text-slate-400 hover:text-white rounded border border-[#21262d] bg-[#11141c]"
              >
                Tutup Semua
              </button>
            </div>
          </div>
        </div>

        {/* Findings List Section */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-mono font-bold text-white flex items-center gap-2 print-text-dark">
              <Terminal className="w-4 h-4 text-cyan-400" />
              HASIL TEMUAN AUDIT ({filteredFindings.length} dari {findings.length})
            </h2>
          </div>

          {filteredFindings.length === 0 ? (
            <div className="p-8 rounded-lg border border-dashed border-[#21262d] bg-[#0d1117]/30 text-center print-card">
              <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
              <h3 className="font-mono font-semibold text-sm text-slate-200 print-text-dark">
                Tidak Ada Temuan yang Cocok
              </h3>
              <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto font-sans print-text-muted">
                {findings.length === 0
                  ? "Situs web target berada dalam konfigurasi aman pada cakupan audit pasif ini."
                  : "Tidak ada temuan yang sesuai dengan kata kunci atau filter yang Anda pilih."}
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredFindings.map((item) => {
                const isExpanded = expandedFindings[item.id] !== false; // Default expanded

                return (
                  <div
                    key={item.id}
                    className="p-4 rounded-lg border border-[#1b2230] bg-[#0d1117]/80 hover:border-[#2b3548] transition-all space-y-3 print-card"
                  >
                    {/* Header baris temuan */}
                    <div
                      onClick={() => toggleExpand(item.id)}
                      className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 cursor-pointer select-none"
                    >
                      <div className="flex items-center gap-2.5 flex-1">
                        <span
                          className={`px-2.5 py-0.5 text-[10px] font-mono font-bold rounded border uppercase flex items-center gap-1 shrink-0 ${getSeverityBadgeClass(
                            item.severity
                          )}`}
                        >
                          {getSeverityIcon(item.severity)}
                          {item.severity}
                        </span>
                        <h3 className="text-sm font-mono font-semibold text-white tracking-wide print-text-dark">
                          {item.title}
                        </h3>
                      </div>

                      <div className="flex items-center gap-3 self-end sm:self-auto shrink-0">
                        <span className="text-[11px] font-mono text-slate-500 print-text-muted">
                          Tool: {item.tool} • Rule: {item.rule_id}
                        </span>
                        <div className="text-slate-500 no-print">
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </div>
                      </div>
                    </div>

                    {/* Konten detail saat terbuka */}
                    {isExpanded && (
                      <div className="space-y-3 pt-2 border-t border-[#1b2230]/60">
                        {/* Deskripsi */}
                        <div className="text-xs text-slate-300 leading-relaxed font-sans print-text-dark">
                          {item.description}
                        </div>

                        {/* Evidence Box */}
                        {item.evidence && (
                          <div className="p-3 rounded border border-[#1b2230] bg-[#06080b] font-mono text-xs text-slate-400 print-box-evidence">
                            <div className="text-[10px] uppercase text-slate-500 mb-1 font-bold">
                              Bukti Temuan (Evidence):
                            </div>
                            <div className="break-all whitespace-pre-wrap text-cyan-300/90 print-text-dark font-mono">
                              {item.evidence}
                            </div>
                          </div>
                        )}

                        {/* Remediation Box */}
                        <div className="p-3.5 rounded border border-emerald-500/20 bg-emerald-950/20 text-xs print-box-remediation">
                          <div className="text-[10px] font-mono uppercase text-emerald-400 font-bold mb-1 flex items-center gap-1.5">
                            <Shield className="w-3.5 h-3.5" />
                            Saran Perbaikan (Remediation):
                          </div>
                          <div className="text-slate-200 font-sans leading-relaxed print-text-dark">
                            {item.remediation}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Riwayat Scan Domain Terkait (Disembunyikan saat dicetak) */}
        {historyScans.length > 1 && (
          <div className="p-6 rounded-lg border border-[#1b2230] bg-[#0d1117]/50 space-y-3 no-print">
            <h3 className="text-sm font-mono font-bold text-white flex items-center gap-2">
              <History className="w-4 h-4 text-cyan-400" />
              RIWAYAT SCAN PADA DOMAIN INI ({historyScans.length})
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {historyScans.map((h) => {
                const isCurrent = h.id === scan.id;
                return (
                  <Link
                    key={h.id}
                    href={`/scans/${h.id}`}
                    className={`p-3 rounded border transition-all block ${
                      isCurrent
                        ? "border-cyan-500 bg-cyan-950/30 text-cyan-200 pointer-events-none"
                        : "border-[#1b2230] bg-[#06080b] hover:border-[#2b3548] text-slate-300"
                    }`}
                  >
                    <div className="flex items-center justify-between text-[11px] font-mono mb-1">
                      <span className="font-bold">ID: {h.id.slice(0, 8)}...</span>
                      <span className="uppercase text-[10px] px-1.5 py-0.5 rounded bg-[#11141c] border border-[#21262d]">
                        {h.status}
                      </span>
                    </div>
                    <div className="text-[10px] font-mono text-slate-500">
                      {new Date(h.created_at).toLocaleString("id-ID")}
                    </div>
                    {isCurrent && (
                      <div className="text-[10px] font-mono text-cyan-400 mt-1 font-bold">
                        • Sedang Dibuka
                      </div>
                    )}
                  </Link>
                );
              })}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1b2230] py-4 text-center text-xs font-mono text-slate-600 no-print">
        SecScan Lab • Confidential Security Report • RLS Enforced • Zero Trust
      </footer>
    </div>
  );
}
