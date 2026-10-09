import { NextRequest, NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { verifyWebhookSignature } from "@/lib/security/webhook-signature";
import { Database, SeverityLevel, ScanStatus } from "@/types/database";

type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
type FindingInsert = Database["public"]["Tables"]["findings"]["Insert"];

interface WebhookFindingPayload {
  tool: string;
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  description: string;
  evidence: string | null;
  remediation: string;
}

interface WebhookScanResultBody {
  scan_id: string;
  status: "done" | "failed";
  error_message?: string;
  summary?: Record<string, unknown>;
  findings?: WebhookFindingPayload[];
}

export async function POST(request: NextRequest) {
  try {
    const webhookSecret = process.env.SCAN_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.error("SCAN_WEBHOOK_SECRET belum dikonfigurasi di environment server!");
      return NextResponse.json(
        { error: "Server misconfiguration: SCAN_WEBHOOK_SECRET is missing" },
        { status: 500 }
      );
    }

    // 1. Ambil signature dari header
    const signatureHeader =
      request.headers.get("x-secscan-signature") ||
      request.headers.get("x-hub-signature-256");

    // 2. Baca body mentah sebagai text untuk verifikasi HMAC
    const rawBody = await request.text();

    const isSignatureValid = verifyWebhookSignature(
      rawBody,
      signatureHeader,
      webhookSecret
    );

    if (!isSignatureValid) {
      return NextResponse.json(
        { error: "Forbidden: Signature HMAC webhook tidak valid atau secret salah." },
        { status: 403 }
      );
    }

    // 3. Parse JSON body
    let body: WebhookScanResultBody;
    try {
      body = JSON.parse(rawBody);
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    const { scan_id, status, error_message, summary, findings } = body;

    if (!scan_id || !status) {
      return NextResponse.json(
        { error: "scan_id dan status wajib disertakan" },
        { status: 400 }
      );
    }

    // 4. Gunakan Supabase Admin Client (Service Role) karena request berasal dari worker aman
    const adminSupabase = createAdminClient();

    // Verifikasi keberadaan scan
    const { data: existingScan, error: scanCheckErr } = await adminSupabase
      .from("scans")
      .select("id, domain_id, status")
      .eq("id", scan_id)
      .single<ScanRow>();

    if (scanCheckErr || !existingScan) {
      return NextResponse.json(
        { error: `Scan dengan ID ${scan_id} tidak ditemukan.` },
        { status: 404 }
      );
    }

    // 5. Simpan Findings jika ada
    if (findings && Array.isArray(findings) && findings.length > 0) {
      const findingsPayload: FindingInsert[] = findings.map((f) => ({
        scan_id: scan_id,
        tool: f.tool,
        rule_id: f.rule_id,
        title: f.title,
        severity: f.severity,
        description: f.description,
        evidence: f.evidence ? String(f.evidence).slice(0, 1000) : null, // Truncate evidence demi keamanan
        remediation: f.remediation,
      }));

      const { error: insertFindingsErr } = await adminSupabase
        .from("findings")
        .insert(findingsPayload as never);

      if (insertFindingsErr) {
        console.error("Gagal menyimpan findings:", insertFindingsErr.message);
      }
    }

    // 6. Hitung breakdown severity & simpan update status scan
    const finalStatus: ScanStatus = status === "done" ? "done" : "failed";
    const findingsList = findings || [];

    const severityBreakdown = {
      critical: findingsList.filter((f) => f.severity === "critical").length,
      high: findingsList.filter((f) => f.severity === "high").length,
      medium: findingsList.filter((f) => f.severity === "medium").length,
      low: findingsList.filter((f) => f.severity === "low").length,
      info: findingsList.filter((f) => f.severity === "info").length,
    };

    const finalSummary = {
      ...(summary || {}),
      severity_breakdown: severityBreakdown,
      total_findings: findingsList.length,
      ...(error_message ? { error: error_message } : {}),
      completed_via: "github_actions_worker",
    };

    const { error: updateScanErr } = await adminSupabase
      .from("scans")
      .update({
        status: finalStatus,
        finished_at: new Date().toISOString(),
        summary: finalSummary,
      } as never)
      .eq("id", scan_id);

    if (updateScanErr) {
      return NextResponse.json(
        { error: `Gagal memperbarui status scan: ${updateScanErr.message}` },
        { status: 500 }
      );
    }

    return NextResponse.json({
      success: true,
      message: `Hasil pemindaian untuk scan ${scan_id} berhasil diproses. Status: ${finalStatus}`,
      findings_saved: findingsList.length,
    });
  } catch (err: unknown) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}
