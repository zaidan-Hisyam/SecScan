import crypto from "crypto";

/**
 * Membuat HMAC SHA256 signature dari payload string.
 */
export function generateWebhookSignature(payload: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(payload, "utf8").digest("hex");
}

/**
 * Memverifikasi apakah signature dari header cocok dengan payload yang dihitung menggunakan secret.
 * Menggunakan crypto.timingSafeEqual untuk mencegah timing attack.
 */
export function verifyWebhookSignature(
  payload: string,
  signatureHeader: string | null,
  secret: string
): boolean {
  if (!signatureHeader || !secret) {
    return false;
  }

  // Format header: 'sha256=<hex>' atau langsung '<hex>'
  const expectedPrefix = "sha256=";
  const rawSignature = signatureHeader.startsWith(expectedPrefix)
    ? signatureHeader.slice(expectedPrefix.length)
    : signatureHeader;

  const expectedSignature = generateWebhookSignature(payload, secret);

  try {
    const signatureBuffer = Buffer.from(rawSignature, "hex");
    const expectedBuffer = Buffer.from(expectedSignature, "hex");

    if (signatureBuffer.length !== expectedBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(signatureBuffer, expectedBuffer);
  } catch {
    return false;
  }
}
