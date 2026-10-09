import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { validateHostname } from "@/lib/security/ssrf";
import crypto from "crypto";
import { Database } from "@/types/database";

type DomainInsert = Database["public"]["Tables"]["domains"]["Insert"];
type DomainRow = Database["public"]["Tables"]["domains"]["Row"];

export async function GET() {
  try {
    const supabase = await createClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { data: domains, error } = await supabase
      .from("domains")
      .select("*")
      .order("created_at", { ascending: false })
      .returns<DomainRow[]>();

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    return NextResponse.json({ domains });
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

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const rawHostname = body.hostname;

    // 1. Validasi ketat format hostname
    const validation = validateHostname(rawHostname);
    if (!validation.valid || !validation.normalized) {
      return NextResponse.json(
        { error: validation.error || "Format hostname tidak valid" },
        { status: 400 }
      );
    }

    const hostname = validation.normalized;

    // 2. Generate token verifikasi kriptografis acak (24 bytes hex)
    const verifyToken = `secscan_${crypto.randomBytes(16).toString("hex")}`;

    // 3. Simpan domain ke Supabase (RLS memastikan owner_id = auth.uid())
    const insertPayload: DomainInsert = {
      owner_id: user.id,
      hostname: hostname,
      verify_token: verifyToken,
      verified: false,
    };

    const { data: domain, error } = await supabase
      .from("domains")
      .insert(insertPayload as never)
      .select()
      .single<DomainRow>();

    if (error) {
      if (error.code === "23505") {
        return NextResponse.json(
          { error: `Domain ${hostname} sudah pernah ditambahkan ke akun Anda.` },
          { status: 409 }
        );
      }
      return NextResponse.json({ error: error.message }, { status: 400 });
    }

    return NextResponse.json(
      {
        message: "Domain berhasil ditambahkan. Silakan lakukan verifikasi kepemilikan.",
        domain,
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

export async function DELETE(request: NextRequest) {
  try {
    const supabase = await createClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const { id } = body;

    if (!id) {
      return NextResponse.json({ error: "ID domain wajib disertakan" }, { status: 400 });
    }

    const { error } = await supabase.from("domains").delete().eq("id", id);

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }

    return NextResponse.json({ success: true, message: "Domain berhasil dihapus" });
  } catch (err: unknown) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}
