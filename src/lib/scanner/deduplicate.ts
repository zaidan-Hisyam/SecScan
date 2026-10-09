import { SeverityLevel } from "../../types/database";

export interface UnifiedFinding {
  tool: string;
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  description: string;
  evidence: string | null;
  remediation: string;
  matched_url?: string;
}

const SEVERITY_WEIGHT: Record<SeverityLevel, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * Normalisasi URL/Path untuk pengelompokan duplikat.
 */
function normalizeUrlKey(matchedUrl?: string): string {
  if (!matchedUrl) return "root";
  try {
    const parsed = new URL(matchedUrl);
    return `${parsed.host}${parsed.pathname}`.toLowerCase().replace(/\/+$/, "");
  } catch {
    return matchedUrl.toLowerCase().trim().replace(/\/+$/, "");
  }
}

/**
 * Menggabungkan temuan duplikat dari berbagai tool (Nuclei, testssl.sh, skrip sendiri)
 * berdasarkan kombinasi: rule_id + matched_url.
 * Jika ditemukan duplikat, pertahankan severity yang paling tinggi dan gabungkan bukti (evidence).
 */
export function deduplicateFindings(findings: UnifiedFinding[]): UnifiedFinding[] {
  const mergedMap = new Map<string, UnifiedFinding>();

  for (const item of findings) {
    const urlKey = normalizeUrlKey(item.matched_url || item.evidence || "");
    const dedupeKey = `${item.rule_id.toLowerCase()}::${urlKey}`;

    if (!mergedMap.has(dedupeKey)) {
      mergedMap.set(dedupeKey, { ...item });
    } else {
      const existing = mergedMap.get(dedupeKey)!;

      // Ambil tingkat keparahan yang lebih tinggi jika berbeda
      const existingWeight = SEVERITY_WEIGHT[existing.severity] || 0;
      const currentWeight = SEVERITY_WEIGHT[item.severity] || 0;
      if (currentWeight > existingWeight) {
        existing.severity = item.severity;
      }

      // Gabungkan bukti temuan (evidence) tanpa redundansi
      if (item.evidence && existing.evidence && !existing.evidence.includes(item.evidence)) {
        existing.evidence = `${existing.evidence}\n[${item.tool}] ${item.evidence}`.slice(0, 800);
      }

      // Gabungkan catatan tool sumber
      if (!existing.tool.includes(item.tool)) {
        existing.tool = `${existing.tool}, ${item.tool}`;
      }
    }
  }

  return Array.from(mergedMap.values());
}
