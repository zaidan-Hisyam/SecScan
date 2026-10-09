import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { checkScanRateLimit } from "@/lib/security/rate-limit";
import { triggerGitHubScanWorkflow } from "@/lib/github/dispatch";
import { Database } from "@/types/database";

type DomainRow = Database["public"]["Tables"]["domains"]["Row"];
type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
type ScanInsert = Database["public"]["Tables"]["scans"]["Insert"];

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

    // 3. Cek Status Verified (Aturan Keamanan Wajib)
    if (!domain.verified) {
      return NextResponse.json(
        {
          error: `Pemindaian DITOLAK: Domain '${domain.hostname}' belum terverifikasi. Anda wajib memverifikasi kepemilikan domain via DNS TXT atau File Token sebelum dapat melakukan scan.`,
          code: "DOMAIN_NOT_VERIFIED",
        },
        { status: 403 }
      );
    }

    // 4. Cek Rate Limit (Batas frekuensi per user & per domain)
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

    // 5. Inisialisasi Record Scan dengan status 'queued'
    const initialScanPayload: ScanInsert = {
      domain_id: domain.id,
      status: "queued",
      started_at: new Date().toISOString(),
      summary: {
        target_hostname: domain.hostname,
        mode: "github_actions_worker",
        dispatch_status: "pending",
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

    // 6. Memicu GitHub Actions Workflow via workflow_dispatch
    const dispatchResult = await triggerGitHubScanWorkflow({
      scanId: scan.id,
      hostname: domain.hostname,
    });

    if (!dispatchResult.success) {
      // Jika dispatch gagal (misal GITHUB_TOKEN belum diisi di dev lokal), tandai info di summary
      await supabase
        .from("scans")
        .update({
          summary: {
            target_hostname: domain.hostname,
            mode: "github_actions_worker",
            dispatch_status: "failed",
            dispatch_error: dispatchResult.error,
          },
        } as never)
        .eq("id", scan.id);

      return NextResponse.json(
        {
          message: `Scan dibuat (queued), namun pemicuan GitHub Actions gagal: ${dispatchResult.error}`,
          scan,
          dispatch_warning: dispatchResult.error,
        },
        { status: 202 }
      );
    }

    return NextResponse.json(
      {
        message: `Pemindaian untuk domain ${domain.hostname} berhasil diantrekan ke GitHub Actions Worker.`,
        scan,
      },
      { status: 201 }
    );
  } catch (err: unknown) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}
