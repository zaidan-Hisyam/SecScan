import { SeverityLevel } from "../../types/database";

export interface NucleiRawFinding {
  "template-id"?: string;
  templateID?: string;
  info?: {
    name?: string;
    author?: string | string[];
    tags?: string | string[];
    description?: string;
    reference?: string | string[];
    severity?: string;
    remediation?: string;
    metadata?: Record<string, unknown>;
  };
  type?: string;
  host?: string;
  "matched-at"?: string;
  matchedAt?: string;
  extracted_results?: string[];
  "extracted-results"?: string[];
  request?: string;
  response?: string;
  ip?: string;
  timestamp?: string;
  curl_command?: string;
}

export interface NormalizedNucleiFinding {
  tool: string;
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  description: string;
  evidence: string;
  remediation: string;
  matched_url?: string;
}

/**
 * Petakan severity Nuclei ke skala baku SecScan:
 * 'info' | 'low' | 'medium' | 'high' | 'critical'
 */
export function mapNucleiSeverity(rawSeverity?: string): SeverityLevel {
  if (!rawSeverity) return "info";
  const lower = rawSeverity.toLowerCase().trim();

  switch (lower) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "info":
    default:
      return "info";
  }
}

/**
 * Buat saran perbaikan dalam bahasa Indonesia berdasarkan kategori template Nuclei jika tidak tersedia di metadata.
 */
function generateRemediationInIndonesian(
  ruleId: string,
  title: string,
  englishRemediation?: string
): string {
  if (englishRemediation && englishRemediation.trim().length > 0) {
    return `${englishRemediation.trim()} (Terapkan patch keamanan atau perbarui konfigurasi terkait).`;
  }

  const id = ruleId.toLowerCase();

  if (id.includes("exposure") || id.includes("env") || id.includes("git") || id.includes("backup")) {
    return "Batasi akses ke file atau direktori tersebut pada level web server (Nginx/Apache/Cloudflare) agar tidak dapat diakses publik.";
  }

  if (id.includes("misconfig") || id.includes("cors") || id.includes("header") || id.includes("debug")) {
    return "Tinjau kembali konfigurasi web server dan nonaktifkan mode debug/verbose pada lingkungan produksi.";
  }

  if (id.includes("tech") || id.includes("detect") || id.includes("version")) {
    return "Sembunyikan banner versi server (ServerTokens Prod / server_tokens off) untuk meminimalkan pengintaian teknologi oleh pihak luar.";
  }

  return `Periksa konfigurasi dan pastikan komponen '${title}' telah diperbarui ke versi stabil terbaru dan mengikuti panduan keamanan resmi.`;
}

/**
 * Parser hasil output Nuclei JSON (JSONL atau JSON Array) ke format temuan seragam SecScan.
 */
export function parseNucleiOutput(rawJsonText: string): NormalizedNucleiFinding[] {
  const findings: NormalizedNucleiFinding[] = [];
  if (!rawJsonText || typeof rawJsonText !== "string") return findings;

  const rawLines = rawJsonText.trim().split("\n");

  for (const line of rawLines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    try {
      const item: NucleiRawFinding = JSON.parse(trimmed);
      const ruleId = item["template-id"] || item.templateID || "nuclei-rule";
      const info = item.info || {};
      const title = info.name || ruleId;
      const severity = mapNucleiSeverity(info.severity);
      const matchedAt = item["matched-at"] || item.matchedAt || item.host || "";

      const description =
        info.description ||
        `Pemeriksaan Nuclei '${title}' menemukan indikasi miskonfigurasi atau informasi terekspos pada target.`;

      // Masking dan pembatasan panjang evidence
      let evidence = `Matched at: ${matchedAt}`;
      if (item["extracted-results"] && item["extracted-results"].length > 0) {
        evidence += `\nExtracted: ${item["extracted-results"].join(", ")}`;
      } else if (item.extracted_results && item.extracted_results.length > 0) {
        evidence += `\nExtracted: ${item.extracted_results.join(", ")}`;
      }

      // Potong dan samarkan nilai rahasia
      evidence = evidence
        .slice(0, 500)
        .replace(/(password|secret|key|token)=([^\s\n]+)/gi, "$1=********");

      const remediation = generateRemediationInIndonesian(ruleId, title, info.remediation);

      findings.push({
        tool: "nuclei",
        rule_id: ruleId,
        title: title,
        severity: severity,
        description: description,
        evidence: evidence,
        remediation: remediation,
        matched_url: matchedAt,
      });
    } catch {
      // Abaikan baris log non-JSON
    }
  }

  return findings;
}
