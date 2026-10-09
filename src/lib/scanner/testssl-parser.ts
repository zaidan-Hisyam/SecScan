import { SeverityLevel } from "../../types/database";

export interface TestsslJsonFinding {
  id: string;
  ip: string;
  port: string;
  severity: string;
  finding: string;
  cve?: string;
  cwe?: string;
}

export interface NormalizedTestsslFinding {
  tool: string;
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  description: string;
  evidence: string;
  remediation: string;
}

/**
 * Parser hasil testssl.sh JSON ke format temuan seragam SecScan
 */
export function parseTestsslJson(testsslJsonArray: TestsslJsonFinding[]): NormalizedTestsslFinding[] {
  const findings: NormalizedTestsslFinding[] = [];

  if (!Array.isArray(testsslJsonArray)) {
    return findings;
  }

  for (const item of testsslJsonArray) {
    const rawSeverity = (item.severity || "").toUpperCase();
    let severity: SeverityLevel = "info";

    if (rawSeverity === "CRITICAL") severity = "critical";
    else if (rawSeverity === "HIGH") severity = "high";
    else if (rawSeverity === "MEDIUM" || rawSeverity === "WARN") severity = "medium";
    else if (rawSeverity === "LOW") severity = "low";
    else if (rawSeverity === "INFO" || rawSeverity === "OK") continue; // Abaikan status OK / check biasa

    // Deteksi kerentanan SSL/TLS spesifik
    const findingText = item.finding || "";
    const id = item.id || "tls-issue";

    // Contoh: Protokol TLS 1.0 / 1.1 usang
    if (id.includes("SSLv2") || id.includes("SSLv3") || id.includes("TLS1_1") || id.includes("TLS1")) {
      if (findingText.toLowerCase().includes("offered") || findingText.toLowerCase().includes("vulnerable")) {
        findings.push({
          tool: "testssl.sh",
          rule_id: `outdated-protocol-${id}`,
          title: `Protokol Kriptografi Usang Aktif (${id})`,
          severity: severity,
          description: `Server mengaktifkan protokol ${id} yang sudah usang dan memiliki kerentanan kriptografis yang diketahui.`,
          evidence: findingText,
          remediation:
            "Nonaktifkan protokol SSLv2, SSLv3, TLS 1.0, dan TLS 1.1 pada konfigurasi web server. Hanya gunakan TLS 1.2 dan TLS 1.3.",
        });
      }
    }

    // Contoh: Heartbleed, POODLE, ROBOT, SWEET32
    else if (
      id.toLowerCase().includes("heartbleed") ||
      id.toLowerCase().includes("poodle") ||
      id.toLowerCase().includes("robot") ||
      id.toLowerCase().includes("sweet32")
    ) {
      if (findingText.toLowerCase().includes("vulnerable")) {
        findings.push({
          tool: "testssl.sh",
          rule_id: `cve-${id.toLowerCase()}`,
          title: `Kerentanan TLS: ${id}`,
          severity: "high",
          description: `Server terindikasi rentan terhadap serangan ${id}.`,
          evidence: findingText,
          remediation: `Perbarui library OpenSSL dan konfigurasikan cipher suite untuk memitigasi serangan ${id}.`,
        });
      }
    }

    // Contoh: Masa berlaku sertifikat / Expired
    else if (id.toLowerCase().includes("cert_expiration") || id.toLowerCase().includes("cert_validity")) {
      findings.push({
        tool: "testssl.sh",
        rule_id: "tls-cert-expiration-issue",
        title: "Peringatan Masa Berlaku Sertifikat SSL/TLS",
        severity: severity,
        description: `Informasi terkait validitas dan masa kedaluwarsa sertifikat SSL/TLS.`,
        evidence: findingText,
        remediation: "Pastikan sertifikat SSL/TLS diperbarui secara otomatis sebelum kedaluwarsa (misal via Certbot / Let's Encrypt).",
      });
    }
  }

  return findings;
}
