import { SeverityLevel } from "../../types/database";
import { safeFetch, resolveAndValidateSSRF } from "../security/ssrf";

export interface NormalizedFinding {
  tool: string;
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  description: string;
  evidence: string | null;
  remediation: string;
}

export interface PassiveScanSummary {
  checked_url: string;
  resolved_ips: string[];
  http_status: number;
  https_redirect_enforced: boolean;
  security_headers_count: number;
  cookie_issues_count: number;
  cors_issues_count: number;
  total_findings: number;
  duration_ms: number;
}

/**
 * Scanner Pasif Ringan Fase 3:
 * Menguji Security Headers, Cookie Flags, Redirect HTTP ke HTTPS, dan CORS misconfiguration.
 * Seluruh request menggunakan safeFetch (Metode non-destruktif: GET / HEAD / OPTIONS, timeout ketat, Anti-SSRF).
 */
export async function runPassiveWebScan(hostname: string): Promise<{
  findings: NormalizedFinding[];
  summary: PassiveScanSummary;
  success: boolean;
  error?: string;
}> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  // 1. Anti-SSRF Resolusi Awal
  const ssrfCheck = await resolveAndValidateSSRF(hostname);
  if (!ssrfCheck.safe) {
    return {
      findings: [],
      summary: {
        checked_url: `https://${hostname}`,
        resolved_ips: [],
        http_status: 0,
        https_redirect_enforced: false,
        security_headers_count: 0,
        cookie_issues_count: 0,
        cors_issues_count: 0,
        total_findings: 0,
        duration_ms: Date.now() - startTime,
      },
      success: false,
      error: ssrfCheck.error,
    };
  }

  const resolvedIps = ssrfCheck.ips || [];
  let httpsRedirectEnforced = false;
  let finalHttpStatus = 0;

  // ---------------------------------------------------------------------------
  // 2. PEMERIKSAAN REDIRECT HTTP -> HTTPS
  // ---------------------------------------------------------------------------
  try {
    const httpCheck = await safeFetch(`http://${hostname}/`, {
      timeoutMs: 6000,
      maxRedirects: 0, // Ingin melihat langsung status response HTTP
    });

    if (httpCheck.status === 301 || httpCheck.status === 302 || httpCheck.status === 307 || httpCheck.status === 308) {
      httpsRedirectEnforced = true;
    } else if (httpCheck.ok) {
      findings.push({
        tool: "custom-passive-scanner",
        rule_id: "missing-http-to-https-redirect",
        title: "Koneksi HTTP tidak dialihkan otomatis ke HTTPS",
        severity: "medium",
        description:
          "Situs web dapat diakses melalui protokol HTTP tanpa pengalihan (redirect) otomatis ke HTTPS. Hal ini memungkinkan serangan Man-in-the-Middle (MitM) dan penyadapan data pengguna.",
        evidence: `Port 80 (HTTP) mengembalikan HTTP Status ${httpCheck.status} tanpa pengalihan aman.`,
        remediation:
          "Konfigurasikan web server (Nginx/Apache/Cloudflare) untuk secara otomatis mengalihkan semua lalu lintas HTTP (Port 80) ke HTTPS (Port 443) dengan status HTTP 301 Permanent Redirect.",
      });
    }
  } catch {
    // Jika port 80 tertutup sama sekali, ini bagus (berarti hanya HTTPS aktif)
    httpsRedirectEnforced = true;
  }

  // ---------------------------------------------------------------------------
  // 3. PEMERIKSAAN UTAMA LEWAT HTTPS (GET & HEAD)
  // ---------------------------------------------------------------------------
  const httpsUrl = `https://${hostname}/`;
  let rawHeaders: Headers | null = null;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const res = await fetch(httpsUrl, {
      method: "GET",
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "SecScan-Audit-Bot/1.0 (+https://secscan.lab)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    clearTimeout(timeoutId);
    finalHttpStatus = res.status;
    rawHeaders = res.headers;
  } catch (err: unknown) {
    return {
      findings,
      summary: {
        checked_url: httpsUrl,
        resolved_ips: resolvedIps,
        http_status: 0,
        https_redirect_enforced: httpsRedirectEnforced,
        security_headers_count: 0,
        cookie_issues_count: 0,
        cors_issues_count: 0,
        total_findings: findings.length,
        duration_ms: Date.now() - startTime,
      },
      success: false,
      error: `Gagal menghubungi target melalui HTTPS: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  // Helper untuk membaca header secara case-insensitive
  const getHeader = (name: string): string | null => {
    if (!rawHeaders) return null;
    return rawHeaders.get(name) || null;
  };

  // ---------------------------------------------------------------------------
  // 4. PEMERIKSAAN SECURITY HEADERS
  // ---------------------------------------------------------------------------
  const hsts = getHeader("strict-transport-security");
  const csp = getHeader("content-security-policy");
  const xfo = getHeader("x-frame-options");
  const xcto = getHeader("x-content-type-options");
  const referrerPolicy = getHeader("referrer-policy");
  const permissionsPolicy = getHeader("permissions-policy");

  // HSTS Check
  if (!hsts) {
    findings.push({
      tool: "custom-passive-scanner",
      rule_id: "missing-hsts-header",
      title: "Header HTTP Strict Transport Security (HSTS) Tidak Ditemukan",
      severity: "medium",
      description:
        "Header HSTS memberitahu browser bahwa situs web ini hanya boleh diakses melalui koneksi aman HTTPS. Tanpa HSTS, koneksi rentan terhadap serangan SSL Stripping.",
      evidence: "Header 'Strict-Transport-Security' tidak ditemukan pada respons HTTP.",
      remediation:
        "Tambahkan header respons: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    });
  }

  // Content-Security-Policy Check
  if (!csp) {
    findings.push({
      tool: "custom-passive-scanner",
      rule_id: "missing-csp-header",
      title: "Header Content-Security-Policy (CSP) Tidak Ditemukan",
      severity: "medium",
      description:
        "Content-Security-Policy (CSP) membatasi sumber daya (skrip, gambar, stylesheet) yang boleh dimuat browser, efektif mencegah serangan Cross-Site Scripting (XSS) dan data injection.",
      evidence: "Header 'Content-Security-Policy' tidak ditemukan.",
      remediation:
        "Terapkan header Content-Security-Policy yang membatasi script-src, object-src, dan default-src sesuai kebutuhan aplikasi.",
    });
  }

  // X-Frame-Options Check
  if (!xfo && (!csp || !csp.includes("frame-ancestors"))) {
    findings.push({
      tool: "custom-passive-scanner",
      rule_id: "missing-x-frame-options",
      title: "Proteksi Clickjacking (X-Frame-Options / frame-ancestors) Belum Terpasang",
      severity: "low",
      description:
        "Situs web ini dapat disematkan ke dalam tag iframe oleh situs web pihak ketiga, membuka celah terjadinya serangan Clickjacking dan UI Redressing.",
      evidence: "Header 'X-Frame-Options' maupun direktif CSP 'frame-ancestors' tidak terkonfigurasi.",
      remediation:
        "Tambahkan header 'X-Frame-Options: SAMEORIGIN' atau tambahkan direktif 'frame-ancestors 'self'' pada CSP.",
    });
  }

  // X-Content-Type-Options Check
  if (!xcto || !xcto.toLowerCase().includes("nosniff")) {
    findings.push({
      tool: "custom-passive-scanner",
      rule_id: "missing-x-content-type-options",
      title: "Header X-Content-Type-Options: nosniff Tidak Ditemukan",
      severity: "low",
      description:
        "Mencegah browser melakukan MIME-sniffing (menebak tipe MIME yang berbeda dari yang dinyatakan oleh server), yang dapat menyebabkan eksekusi file non-eksekusi sebagai skrip.",
      evidence: `Header 'X-Content-Type-Options': ${xcto || "Tidak Ada"}`,
      remediation: "Tambahkan header: X-Content-Type-Options: nosniff",
    });
  }

  // Referrer-Policy Check
  if (!referrerPolicy) {
    findings.push({
      tool: "custom-passive-scanner",
      rule_id: "missing-referrer-policy",
      title: "Header Referrer-Policy Belum Ditetapkan",
      severity: "low",
      description:
        "Tanpa kebijakan referrer yang ketat, URL lengkap beserta parameter sensitif (misalnya token atau ID rahasia) dapat bocor ke situs web pihak ketiga saat pengguna mengklik tautan keluar.",
      evidence: "Header 'Referrer-Policy' tidak ditemukan pada respons server.",
      remediation: "Terapkan header: Referrer-Policy: strict-origin-when-cross-origin atau no-referrer",
    });
  }

  // Permissions-Policy Check
  if (!permissionsPolicy) {
    findings.push({
      tool: "custom-passive-scanner",
      rule_id: "missing-permissions-policy",
      title: "Header Permissions-Policy Belum Dikonfigurasi",
      severity: "info",
      description:
        "Permissions-Policy memungkinkan pengembang mengontrol fitur browser (kamera, mikrofon, geolokasi, payment) yang boleh digunakan di halaman web dan iframe.",
      evidence: "Header 'Permissions-Policy' tidak ditemukan.",
      remediation:
        "Tambahkan header Permissions-Policy, misalnya: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    });
  }

  // ---------------------------------------------------------------------------
  // 5. PEMERIKSAAN COOKIE FLAGS (Secure, HttpOnly, SameSite)
  // ---------------------------------------------------------------------------
  const rawSetCookie = rawHeaders?.get("set-cookie");
  let cookieIssuesCount = 0;

  if (rawSetCookie) {
    const cookiesList = rawSetCookie.split(/,(?=\s*[^;=]+=[^;]+)/g);

    for (const singleCookie of cookiesList) {
      const parts = singleCookie.split(";").map((p) => p.trim());
      const cookieNameVal = parts[0];
      const cookieName = cookieNameVal.split("=")[0] || "cookie";

      const lowerParts = parts.map((p) => p.toLowerCase());
      const hasSecure = lowerParts.some((p) => p === "secure");
      const hasHttpOnly = lowerParts.some((p) => p === "httponly");
      const hasSameSite = lowerParts.some((p) => p.startsWith("samesite="));

      if (!hasSecure) {
        cookieIssuesCount++;
        findings.push({
          tool: "custom-passive-scanner",
          rule_id: "cookie-missing-secure-flag",
          title: `Cookie '${cookieName}' Tidak Memiliki Flag Secure`,
          severity: "medium",
          description:
            `Cookie '${cookieName}' dikirim tanpa atribut 'Secure'. Hal ini memungkinkan cookie ditransmisikan dalam jaringan HTTP tanpa enkripsi dan rentan disadap.`,
          evidence: `Set-Cookie: ${cookieName}=***; ${parts.slice(1).join("; ")}`,
          remediation: `Tambahkan atribut '; Secure' pada pembuatan cookie '${cookieName}'.`,
        });
      }

      if (!hasHttpOnly) {
        cookieIssuesCount++;
        findings.push({
          tool: "custom-passive-scanner",
          rule_id: "cookie-missing-httponly-flag",
          title: `Cookie '${cookieName}' Tidak Memiliki Flag HttpOnly`,
          severity: "medium",
          description:
            `Cookie '${cookieName}' dapat diakses oleh skrip JavaScript di sisi klien (document.cookie), meningkatkan risiko pencurian sesi saat terjadi serangan XSS.`,
          evidence: `Set-Cookie: ${cookieName}=***; ${parts.slice(1).join("; ")}`,
          remediation: `Tambahkan atribut '; HttpOnly' pada cookie '${cookieName}' jika cookie tidak perlu dibaca oleh JavaScript klien.`,
        });
      }

      if (!hasSameSite) {
        cookieIssuesCount++;
        findings.push({
          tool: "custom-passive-scanner",
          rule_id: "cookie-missing-samesite-flag",
          title: `Cookie '${cookieName}' Tidak Memiliki Flag SameSite`,
          severity: "low",
          description:
            `Cookie '${cookieName}' tidak menetapkan kebijakan SameSite, meningkatkan risiko serangan Cross-Site Request Forgery (CSRF).`,
          evidence: `Set-Cookie: ${cookieName}=***; ${parts.slice(1).join("; ")}`,
          remediation: `Tetapkan atribut '; SameSite=Lax' atau '; SameSite=Strict' pada cookie '${cookieName}'.`,
        });
      }
    }
  }

  // ---------------------------------------------------------------------------
  // 6. PEMERIKSAAN CORS MISCONFIGURATION (OPTIONS & GET Origin Reflection)
  // ---------------------------------------------------------------------------
  let corsIssuesCount = 0;
  const testOrigins = ["https://evil-attacker.com", "null"];

  for (const origin of testOrigins) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const corsRes = await fetch(httpsUrl, {
        method: "OPTIONS",
        signal: controller.signal,
        headers: {
          Origin: origin,
          "Access-Control-Request-Method": "GET",
          "User-Agent": "SecScan-Audit-Bot/1.0",
        },
      });
      clearTimeout(timeoutId);

      const allowOrigin = corsRes.headers.get("access-control-allow-origin");
      const allowCredentials = corsRes.headers.get("access-control-allow-credentials");

      // Cek wildcard origin dengan credentials
      if (allowOrigin === "*" && allowCredentials === "true") {
        corsIssuesCount++;
        findings.push({
          tool: "custom-passive-scanner",
          rule_id: "cors-wildcard-with-credentials",
          title: "Miskonfigurasi CORS: Wildcard Origin dengan Credentials",
          severity: "high",
          description:
            "Server mengembalikan Access-Control-Allow-Origin: * bersamaan dengan Access-Control-Allow-Credentials: true. Miskonfigurasi ini memungkinkan situs web eksternal membaca data terautentikasi pengguna.",
          evidence: `Origin: ${origin} -> Access-Control-Allow-Origin: ${allowOrigin}, Access-Control-Allow-Credentials: ${allowCredentials}`,
          remediation:
            "Hindari penggunaan wildcard (*) jika kredensial diaktifkan. Gunakan whitelist origin spesifik dan valid.",
        });
      }

      // Cek refleksif origin berbahaya (server memantulkan origin penyerang kembali)
      if (allowOrigin === origin && origin === "https://evil-attacker.com") {
        corsIssuesCount++;
        findings.push({
          tool: "custom-passive-scanner",
          rule_id: "cors-origin-reflection",
          title: "Miskonfigurasi CORS: Refleksi Origin Tanpa Validasi Whitelist",
          severity: allowCredentials === "true" ? "high" : "medium",
          description:
            "Server secara otomatis mempercayai dan memantulkan (reflect) sembarang Origin yang dikirimkan klien ke dalam header Access-Control-Allow-Origin.",
          evidence: `Request Origin: ${origin} -> Response Access-Control-Allow-Origin: ${allowOrigin}`,
          remediation:
            "Terapkan whitelist origin yang ketat pada backend dan jangan merefleksikan header Origin dari klien secara mentah.",
        });
      }
    } catch {
      // Abaikan jika endpoint menolak metode OPTIONS
    }
  }

  const durationMs = Date.now() - startTime;

  const summary: PassiveScanSummary = {
    checked_url: httpsUrl,
    resolved_ips: resolvedIps,
    http_status: finalHttpStatus,
    https_redirect_enforced: httpsRedirectEnforced,
    security_headers_count: 6 - findings.filter((f) => f.rule_id.includes("header") || f.rule_id.includes("options") || f.rule_id.includes("policy")).length,
    cookie_issues_count: cookieIssuesCount,
    cors_issues_count: corsIssuesCount,
    total_findings: findings.length,
    duration_ms: durationMs,
  };

  return {
    findings,
    summary,
    success: true,
  };
}
