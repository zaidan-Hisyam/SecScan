import * as dns from "dns";
import { safeFetch } from "@/lib/security/ssrf";

export interface VerificationResult {
  verified: boolean;
  method?: "dns_txt" | "file_token";
  message: string;
  details?: {
    dnsCheckedRecords?: string[];
    fileCheckedUrl?: string;
    fileStatusCode?: number;
  };
}

/**
 * Verifikasi kepemilikan domain melalui DNS TXT Record.
 * Memeriksa root domain (@) dan subdomain challenge (_secscan-challenge.<hostname>).
 */
export async function verifyDomainViaDNS(
  hostname: string,
  expectedToken: string
): Promise<{ success: boolean; records: string[]; message: string }> {
  const dnsPromises = dns.promises;
  const recordsFound: string[] = [];

  const targetsToCheck = [hostname, `_secscan-challenge.${hostname}`];

  for (const target of targetsToCheck) {
    try {
      const txtRecords = await dnsPromises.resolveTxt(target);
      const flattened = txtRecords.map((chunk) => chunk.join(""));
      recordsFound.push(...flattened);

      for (const record of flattened) {
        const trimmed = record.trim();
        // Cek kecocokan token langsung atau format key=value (secscan-token=...)
        if (
          trimmed === expectedToken ||
          trimmed === `secscan-verify=${expectedToken}` ||
          trimmed.includes(expectedToken)
        ) {
          return {
            success: true,
            records: recordsFound,
            message: `Verifikasi DNS TXT berhasil ditemukan pada ${target}`,
          };
        }
      }
    } catch {
      // Abaikan jika target DNS tidak memiliki TXT record, lanjutkan ke target berikutnya
    }
  }

  return {
    success: false,
    records: recordsFound,
    message: "Record DNS TXT yang cocok belum ditemukan.",
  };
}

/**
 * Verifikasi kepemilikan domain melalui File Token HTTP/HTTPS.
 * Path standar: https://<hostname>/.well-known/secscan-challenge.txt
 */
export async function verifyDomainViaFile(
  hostname: string,
  expectedToken: string
): Promise<{ success: boolean; url: string; status: number; message: string }> {
  // Coba HTTPS terlebih dahulu, lalu fallback ke HTTP jika gagal/timeout
  const protocols = ["https", "http"];

  for (const proto of protocols) {
    const targetUrl = `${proto}://${hostname}/.well-known/secscan-challenge.txt`;

    try {
      const response = await safeFetch(targetUrl, {
        timeoutMs: 6000,
        maxSizeBytes: 10 * 1024, // Max 10KB untuk file token
      });

      if (response.ok && response.text) {
        const content = response.text.trim();
        if (
          content === expectedToken ||
          content === `secscan-verify=${expectedToken}` ||
          content.includes(expectedToken)
        ) {
          return {
            success: true,
            url: targetUrl,
            status: response.status,
            message: `File token verifikasi valid ditemukan di ${targetUrl}`,
          };
        }
      }
    } catch {
      // Lanjutkan ke protokol berikutnya jika terjadi error
    }
  }

  return {
    success: false,
    url: `https://${hostname}/.well-known/secscan-challenge.txt`,
    status: 0,
    message: "File token verifikasi tidak ditemukan atau isi token tidak cocok.",
  };
}

/**
 * Fungsi orkestrasi verifikasi domain (Mencoba DNS TXT, jika gagal mencoba File Token)
 */
export async function verifyDomainOwnership(
  hostname: string,
  expectedToken: string
): Promise<VerificationResult> {
  // 1. Coba verifikasi DNS TXT
  const dnsResult = await verifyDomainViaDNS(hostname, expectedToken);
  if (dnsResult.success) {
    return {
      verified: true,
      method: "dns_txt",
      message: dnsResult.message,
      details: {
        dnsCheckedRecords: dnsResult.records,
      },
    };
  }

  // 2. Coba verifikasi File Token
  const fileResult = await verifyDomainViaFile(hostname, expectedToken);
  if (fileResult.success) {
    return {
      verified: true,
      method: "file_token",
      message: fileResult.message,
      details: {
        fileCheckedUrl: fileResult.url,
        fileStatusCode: fileResult.status,
      },
    };
  }

  return {
    verified: false,
    message:
      "Verifikasi gagal. Pastikan TXT record pada DNS Anda atau file token di /.well-known/secscan-challenge.txt telah aktif dan dapat diakses.",
    details: {
      dnsCheckedRecords: dnsResult.records,
      fileCheckedUrl: fileResult.url,
      fileStatusCode: fileResult.status,
    },
  };
}
