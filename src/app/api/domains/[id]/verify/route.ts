import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { verifyDomainOwnership } from "@/lib/domain/verify";
import { Database } from "@/types/database";

type DomainRow = Database["public"]["Tables"]["domains"]["Row"];
type DomainUpdate = Database["public"]["Tables"]["domains"]["Update"];

export async function POST(
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

    // 1. Ambil data domain milik user (dilindungi RLS)
    const { data: domain, error: fetchError } = await supabase
      .from("domains")
      .select("*")
      .eq("id", id)
      .single<DomainRow>();

    if (fetchError || !domain) {
      return NextResponse.json(
        { error: "Domain tidak ditemukan atau bukan milik Anda" },
        { status: 404 }
      );
    }

    if (domain.verified) {
      return NextResponse.json({
        verified: true,
        message: `Domain ${domain.hostname} sudah terverifikasi sebelumnya.`,
        domain,
      });
    }

    // 2. Jalankan pengecekan kepemilikan (DNS TXT & File Token)
    const verification = await verifyDomainOwnership(
      domain.hostname,
      domain.verify_token
    );

    if (!verification.verified) {
      return NextResponse.json(
        {
          verified: false,
          error: verification.message,
          details: verification.details,
        },
        { status: 400 }
      );
    }

    // 3. Jika berhasil, tandai verified = true dan simpan verified_at
    const updatePayload: DomainUpdate = {
      verified: true,
      verified_at: new Date().toISOString(),
    };

    const { data: updatedDomain, error: updateError } = await supabase
      .from("domains")
      .update(updatePayload as never)
      .eq("id", domain.id)
      .select()
      .single<DomainRow>();

    if (updateError || !updatedDomain) {
      return NextResponse.json(
        { error: "Gagal memperbarui status verifikasi domain di database" },
        { status: 500 }
      );
    }

    return NextResponse.json({
      verified: true,
      message: `Selamat! Domain ${domain.hostname} berhasil diverifikasi melalui ${
        verification.method === "dns_txt" ? "DNS TXT Record" : "File Token HTTP"
      }.`,
      domain: updatedDomain,
      method: verification.method,
    });
  } catch (err: unknown) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}
