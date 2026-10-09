import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { Database } from "@/types/database";

type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
type FindingRow = Database["public"]["Tables"]["findings"]["Row"];

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await context.params;
    const supabase = await createClient();

    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // 1. Ambil detail scan (RLS memastikan scan terkait domain milik user)
    const { data: scan, error: scanError } = await supabase
      .from("scans")
      .select("*, domains(*)")
      .eq("id", id)
      .single();

    if (scanError || !scan) {
      return NextResponse.json(
        { error: "Scan tidak ditemukan atau bukan milik Anda" },
        { status: 404 }
      );
    }

    // 2. Ambil temuan (findings) untuk scan ini (RLS otomatis memfilter)
    const { data: findings, error: findingsError } = await supabase
      .from("findings")
      .select("*")
      .eq("scan_id", id)
      .order("created_at", { ascending: true })
      .returns<FindingRow[]>();

    if (findingsError) {
      return NextResponse.json({ error: findingsError.message }, { status: 500 });
    }

    return NextResponse.json({
      scan,
      findings: findings || [],
    });
  } catch (err: unknown) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}
