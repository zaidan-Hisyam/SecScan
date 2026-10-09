import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { checkScanRateLimit } from "@/lib/security/rate-limit";
import { runPassiveWebScan } from "@/lib/scanner/passive-scan";
import { checkExposedFiles } from "@/lib/scanner/file-exposure";
import { deduplicateFindings } from "@/lib/scanner/deduplicate";
import { triggerGitHubScanWorkflow } from "@/lib/github/dispatch";
import { Database } from "@/types/database";

type DomainRow = Database["public"]["Tables"]["domains"]["Row"];
type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
type ScanInsert = Database["public"]["Tables"]["scans"]["Insert"];
type FindingInsert = Database["public"]["Tables"]["findings"]["Insert"];

export async function GET(request: NextRequest) {
  try {
    const supabase = await createClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const domainId = searchParams.get("domain_id");

    let query = supabase
      .from("scans")
      .select("*, domains(hostname)")
      .order("created_at", { ascending: false });

    if (domainId) {
      query = query.eq("domain_id", domainId);
    }

    const { data: scans, error } = await query.returns<ScanRow[]>();

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    return NextResponse.json({ scans });
  } catch (err: unknown) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const supabase = await createClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    // 1. Cek Login
    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const { domain_id } = body;

    if (!domain_id) {
      return NextResponse.json(
        { error: "domain_id wajib disertakan" },
        { status: 400 }
      );
    }

    // 2. Cek Kepemilikan Domain (RLS)
    const { data: domain, error: domainError } = await supabase
      .from("domains")
      .select("*")
      .eq("id", domain_id)
      .single<DomainRow>();

    if (domainError || !domain) {
      return NextResponse.json(
        { error: "Domain tidak ditemukan atau bukan milik Anda" },
        { status: 404 }
      );
    }

    // 3. Cek Status Verified
    if (!domain.verified) {
      return NextResponse.json(
        {
          error: `Pemindaian DITOLAK: Domain '${domain.hostname}' belum terverifikasi.`,
          code: "DOMAIN_NOT_VERIFIED",
        },
        { status: 403 }
      );
    }

    // 4. Cek Rate Limit
    const rateLimit = await checkScanRateLimit(user.id, domain.id);
    if (!rateLimit.allowed) {
      return NextResponse.json(
        {
          error: rateLimit.reason,
          retryAfterSeconds: rateLimit.retryAfterSeconds,
          code: "RATE_LIMIT_EXCEEDED",
        },
        { status: 429 }
      );
    }

    // 5. Inisialisasi Record Scan dengan status 'running'
    const initialScanPayload: ScanInsert = {
      domain_id: domain.id,
      status: "running",
      started_at: new Date().toISOString(),
      summary: {
        target_hostname: domain.hostname,
        mode: "hybrid_instant_worker",
        stage: "executing",
      },
      triggered_by: user.id,
    };

    const { data: scan, error: scanCreateErr } = await supabase
      .from("scans")
      .insert(initialScanPayload as never)
      .select()
      .single<ScanRow>();

    if (scanCreateErr || !scan) {
      return NextResponse.json(
        { error: `Gagal membuat sesi pemindaian: ${scanCreateErr?.message}` },
        { status: 500 }
      );
    }

    // 6. Jalankan Pemindaian Pasif & File Exposure Langsung (Hasil Instan)
    const [passiveResult, exposedFilesResult] = await Promise.all([
      runPassiveWebScan(domain.hostname),
      checkExposedFiles(domain.hostname),
    ]);

    const combinedRawFindings = [
      ...(passiveResult.findings || []),
      ...(exposedFilesResult || []),
    ];

    // Deduplikasi temuan
    const dedupedFindings = deduplicateFindings(combinedRawFindings);

    // 7. Simpan Findings ke Database
    if (dedupedFindings.length > 0) {
      const findingsPayload: FindingInsert[] = dedupedFindings.map((f) => ({
        scan_id: scan.id,
        tool: f.tool,
        rule_id: f.rule_id,
        title: f.title,
        severity: f.severity,
        description: f.description,
        evidence: f.evidence,
        remediation: f.remediation,
      }));

      const { error: insertFindingsErr } = await supabase
        .from("findings")
        .insert(findingsPayload as never);

      if (insertFindingsErr) {
        console.error("Gagal menyimpan findings:", insertFindingsErr.message);
      }
    }

    // 8. Hitung Breakdown Severity & Update Status = 'done'
    const severityCount = {
      critical: dedupedFindings.filter((f) => f.severity === "critical").length,
      high: dedupedFindings.filter((f) => f.severity === "high").length,
      medium: dedupedFindings.filter((f) => f.severity === "medium").length,
      low: dedupedFindings.filter((f) => f.severity === "low").length,
      info: dedupedFindings.filter((f) => f.severity === "info").length,
    };

    const finalSummary = {
      ...passiveResult.summary,
      exposed_files_checked: true,
      severity_breakdown: severityCount,
      total_findings: dedupedFindings.length,
      completed_at: new Date().toISOString(),
    };

    const { data: finishedScan, error: updateScanErr } = await supabase
      .from("scans")
      .update({
        status: "done",
        finished_at: new Date().toISOString(),
        summary: finalSummary,
      } as never)
      .eq("id", scan.id)
      .select()
      .single<ScanRow>();

    // 9. Picu juga GitHub Actions Worker di background jika kredensial GitHub tersedia
    triggerGitHubScanWorkflow({
      scanId: scan.id,
      hostname: domain.hostname,
    }).catch(() => {});

    return NextResponse.json(
      {
        message: `Pemindaian untuk ${domain.hostname} selesai.`,
        scan: finishedScan || scan,
        findings_count: dedupedFindings.length,
        summary: finalSummary,
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}
