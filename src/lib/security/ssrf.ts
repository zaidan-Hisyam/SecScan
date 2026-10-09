import * as dns from "dns";
import * as net from "net";

/**
 * Validasi ketat format hostname:
 * - Hanya huruf kecil, angka, tanda hubung (-), dan titik (.)
 * - Panjang total max 253 karakter, per label max 63 karakter
 * - Tolak skema (http://, https://), port (:8080), path (/path), spasi, query string
 * - Tolak alamat IP langsung (karena kepemilikan domain harus lewat FQDN yang bisa diuji DNS/File)
 */
export function validateHostname(rawInput: string): { valid: boolean; normalized?: string; error?: string } {
  if (!rawInput || typeof rawInput !== "string") {
    return { valid: false, error: "Hostname tidak boleh kosong" };
  }

  let hostname = rawInput.trim().toLowerCase();

  // Hapus protokol jika pengguna salah menempelkan URL lengkap
  if (hostname.startsWith("http://")) {
    hostname = hostname.replace(/^http:\/\//, "");
  } else if (hostname.startsWith("https://")) {
    hostname = hostname.replace(/^https:\/\//, "");
  }

  // Hapus trailing slash atau path jika ada
  if (hostname.includes("/")) {
    hostname = hostname.split("/")[0];
  }

  // Hapus port jika ada
  if (hostname.includes(":")) {
    hostname = hostname.split(":")[0];
  }

  // Validasi panjang
  if (hostname.length === 0 || hostname.length > 253) {
    return { valid: false, error: "Panjang hostname harus antara 1 dan 253 karakter" };
  }

  // Tolak IP address (IPv4 / IPv6) langsung
  if (net.isIP(hostname) !== 0) {
    return { valid: false, error: "Alamat IP tidak diizinkan. Gunakan nama domain (FQDN) yang valid." };
  }

  // Whitelist karakter regex untuk hostname FQDN
  // Setiap label: mulai dan diakhiri huruf/angka, boleh ada tanda hubung di tengah
  const hostnameRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/;

  if (!hostnameRegex.test(hostname)) {
    return {
      valid: false,
      error: "Format domain tidak valid. Contoh valid: example.com atau sub.domain.org",
    };
  }

  return { valid: true, normalized: hostname };
}

/**
 * Memeriksa apakah IP masuk dalam rentang privat, loopback, link-local, multicast,
 * atau IP metadata server cloud (Anti-SSRF).
 */
export function isPrivateOrBlockedIP(ip: string): boolean {
  const cleanIp = ip.trim();

  // 1. Cek IPv4
  if (net.isIPv4(cleanIp)) {
    const parts = cleanIp.split(".").map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return true;

    const [a, b] = parts;

    // 0.0.0.0/8 (Broadcast/Current network)
    if (a === 0) return true;

    // 10.0.0.0/8 (Private network)
    if (a === 10) return true;

    // 127.0.0.0/8 (Loopback / Localhost)
    if (a === 127) return true;

    // 169.254.0.0/16 (Link-local, AWS/GCP/Azure Cloud Metadata: 169.254.169.254)
    if (a === 169 && b === 254) return true;

    // 172.16.0.0/12 (Private network: 172.16.0.0 - 172.31.255.255)
    if (a === 172 && b >= 16 && b <= 31) return true;

    // 192.168.0.0/16 (Private network)
    if (a === 192 && b === 168) return true;

    // 100.64.0.0/10 (Shared address space / Carrier Grade NAT)
    if (a === 100 && b >= 64 && b <= 127) return true;

    // 198.18.0.0/15 (Benchmarking)
    if (a === 198 && (b === 18 || b === 19)) return true;

    // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
    if (a >= 224) return true;

    return false;
  }

  // 2. Cek IPv6
  if (net.isIPv6(cleanIp)) {
    const lower = cleanIp.toLowerCase();

    // ::1 (Loopback)
    if (lower === "::1" || lower === "0:0:0:0:0:0:0:1") return true;

    // :: (Unspecified)
    if (lower === "::" || lower === "0:0:0:0:0:0:0:0") return true;

    // fc00::/7 (Unique local address / Private)
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true;

    // fe80::/10 (Link-local address)
    if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return true;

    // IPv4-mapped IPv6 (::ffff:127.0.0.1 dsb)
    if (lower.includes("::ffff:")) {
      const ipv4Part = lower.split("::ffff:")[1];
      if (ipv4Part && net.isIPv4(ipv4Part)) {
        return isPrivateOrBlockedIP(ipv4Part);
      }
    }

    return false;
  }

  // Format IP tidak dikenal -> tolak demi keamanan
  return true;
}

/**
 * Resolusi DNS dan validasi Anti-SSRF pada semua resolved IP
 */
export async function resolveAndValidateSSRF(hostname: string): Promise<{ safe: boolean; error?: string; ips?: string[] }> {
  try {
    const dnsPromises = dns.promises;
    const [ipv4Addresses, ipv6Addresses] = await Promise.allSettled([
      dnsPromises.resolve4(hostname),
      dnsPromises.resolve6(hostname),
    ]);

    const allIps: string[] = [];

    if (ipv4Addresses.status === "fulfilled") {
      allIps.push(...ipv4Addresses.value);
    }
    if (ipv6Addresses.status === "fulfilled") {
      allIps.push(...ipv6Addresses.value);
    }

    if (allIps.length === 0) {
      return { safe: false, error: `Domain ${hostname} tidak dapat di-resolve (DNS lookup gagal).` };
    }

    // Cek setiap IP yang dihasilkan
    for (const ip of allIps) {
      if (isPrivateOrBlockedIP(ip)) {
        return {
          safe: false,
          error: `Anti-SSRF Triggered: Domain ${hostname} mengarah ke IP terlarang/privat (${ip}).`,
          ips: allIps,
        };
      }
    }

    return { safe: true, ips: allIps };
  } catch (err: unknown) {
    return {
      safe: false,
      error: `Gagal melakukan resolusi DNS: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * Safe Fetch dengan Anti-SSRF, batas timeout, batas ukuran respons, dan proteksi redirect.
 */
export async function safeFetch(
  targetUrl: string,
  options: { timeoutMs?: number; maxRedirects?: number; maxSizeBytes?: number } = {}
): Promise<{ ok: boolean; status: number; text: string; error?: string }> {
  const { timeoutMs = 8000, maxRedirects = 3, maxSizeBytes = 50 * 1024 } = options;

  let currentUrl = targetUrl;
  let redirectsCount = 0;

  while (redirectsCount <= maxRedirects) {
    let parsed: URL;
    try {
      parsed = new URL(currentUrl);
    } catch {
      return { ok: false, status: 0, text: "", error: `URL tidak valid: ${currentUrl}` };
    }

    // Hanya izinkan skema HTTP / HTTPS
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { ok: false, status: 0, text: "", error: `Protokol tidak diizinkan: ${parsed.protocol}` };
    }

    // Validasi hostname ketat
    const hostValidation = validateHostname(parsed.hostname);
    if (!hostValidation.valid) {
      return { ok: false, status: 0, text: "", error: hostValidation.error || "Hostname tidak valid" };
    }

    // Anti-SSRF: Resolve DNS dan cek IP sebelum melakukan request
    const ssrfCheck = await resolveAndValidateSSRF(parsed.hostname);
    if (!ssrfCheck.safe) {
      return { ok: false, status: 0, text: "", error: ssrfCheck.error };
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(currentUrl, {
        method: "GET",
        signal: controller.signal,
        redirect: "manual", // Kelola redirect manual untuk cek SSRF ulang di setiap hop
        headers: {
          "User-Agent": "SecScan-Verification-Bot/1.0 (+https://secscan.lab)",
          Accept: "text/plain, */*",
        },
      });

      clearTimeout(timeoutId);

      // Tangani Redirect (301, 302, 307, 308)
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location) {
          return { ok: false, status: response.status, text: "", error: "Redirect tanpa header Location" };
        }

        const nextUrl = new URL(location, currentUrl).toString();
        currentUrl = nextUrl;
        redirectsCount++;
        continue;
      }

      // Ambil isi teks dengan batas ukuran (maxSizeBytes)
      const reader = response.body?.getReader();
      if (!reader) {
        const text = await response.text();
        return { ok: response.ok, status: response.status, text: text.slice(0, maxSizeBytes) };
      }

      const chunks: Uint8Array[] = [];
      let totalBytes = 0;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          totalBytes += value.length;
          if (totalBytes > maxSizeBytes) {
            reader.cancel();
            break;
          }
          chunks.push(value);
        }
      }

      const merged = new Uint8Array(totalBytes);
      let offset = 0;
      for (const chunk of chunks) {
        merged.set(chunk, offset);
        offset += chunk.length;
      }

      const text = new TextDecoder("utf-8").decode(merged);
      return { ok: response.ok, status: response.status, text };
    } catch (err: unknown) {
      clearTimeout(timeoutId);
      if (err instanceof Error && err.name === "AbortError") {
        return { ok: false, status: 0, text: "", error: "Request timeout saat verifikasi file token" };
      }
      return { ok: false, status: 0, text: "", error: err instanceof Error ? err.message : String(err) };
    }
  }

  return { ok: false, status: 0, text: "", error: "Terlalu banyak redirect (melebihi batas maxRedirects)" };
}
