-- ==============================================================================
-- MIGRASI BASIS DATA: FASE 1 - FONDASI (PROFILES, DOMAINS, SCANS, FINDINGS)
-- Keamanan: Row Level Security (RLS) diaktifkan untuk semua tabel.
-- Akses: Pengguna hanya berhak mengakses data miliknya sendiri.
-- ==============================================================================

-- 1. TABEL PROFILES (Dihubungkan ke auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- 2. TABEL DOMAINS
CREATE TABLE IF NOT EXISTS public.domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    verify_token TEXT NOT NULL,
    verified BOOLEAN DEFAULT FALSE NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL,
    CONSTRAINT unique_owner_hostname UNIQUE (owner_id, hostname)
);

-- 3. TABEL SCANS
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id UUID NOT NULL REFERENCES public.domains(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    summary JSONB DEFAULT '{}'::jsonb NOT NULL,
    triggered_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- 4. TABEL FINDINGS
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    description TEXT NOT NULL,
    evidence TEXT,
    remediation TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- 5. INDEXES UNTUK PERFORMA QUERY
CREATE INDEX IF NOT EXISTS idx_domains_owner_id ON public.domains(owner_id);
CREATE INDEX IF NOT EXISTS idx_scans_domain_id ON public.scans(domain_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON public.findings(scan_id);

-- 6. AKTIFKAN ROW LEVEL SECURITY (RLS) DI SEMUA TABEL
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

-- 7. ATURAN RLS UNTUK PROFILES
CREATE POLICY "Users can view own profile"
    ON public.profiles FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "Users can update own profile"
    ON public.profiles FOR UPDATE
    USING (auth.uid() = id);

-- 8. ATURAN RLS UNTUK DOMAINS
CREATE POLICY "Users can view own domains"
    ON public.domains FOR SELECT
    USING (auth.uid() = owner_id);

CREATE POLICY "Users can insert own domains"
    ON public.domains FOR INSERT
    WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "Users can update own domains"
    ON public.domains FOR UPDATE
    USING (auth.uid() = owner_id);

CREATE POLICY "Users can delete own domains"
    ON public.domains FOR DELETE
    USING (auth.uid() = owner_id);

-- 9. ATURAN RLS UNTUK SCANS (Cek kepemilikan melalui domains.owner_id)
CREATE POLICY "Users can view own scans"
    ON public.scans FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.domains
            WHERE public.domains.id = public.scans.domain_id
            AND public.domains.owner_id = auth.uid()
        )
    );

CREATE POLICY "Users can insert scans for own domains"
    ON public.scans FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.domains
            WHERE public.domains.id = public.scans.domain_id
            AND public.domains.owner_id = auth.uid()
        )
    );

CREATE POLICY "Users can update own scans"
    ON public.scans FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM public.domains
            WHERE public.domains.id = public.scans.domain_id
            AND public.domains.owner_id = auth.uid()
        )
    );

CREATE POLICY "Users can delete own scans"
    ON public.scans FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM public.domains
            WHERE public.domains.id = public.scans.domain_id
            AND public.domains.owner_id = auth.uid()
        )
    );

-- 10. ATURAN RLS UNTUK FINDINGS (Cek kepemilikan bertingkat scans -> domains.owner_id)
CREATE POLICY "Users can view own findings"
    ON public.findings FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.scans
            JOIN public.domains ON public.domains.id = public.scans.domain_id
            WHERE public.scans.id = public.findings.scan_id
            AND public.domains.owner_id = auth.uid()
        )
    );

CREATE POLICY "Users can insert findings for own scans"
    ON public.findings FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.scans
            JOIN public.domains ON public.domains.id = public.scans.domain_id
            WHERE public.scans.id = public.findings.scan_id
            AND public.domains.owner_id = auth.uid()
        )
    );

CREATE POLICY "Users can update own findings"
    ON public.findings FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM public.scans
            JOIN public.domains ON public.domains.id = public.scans.domain_id
            WHERE public.scans.id = public.findings.scan_id
            AND public.domains.owner_id = auth.uid()
        )
    );

CREATE POLICY "Users can delete own findings"
    ON public.findings FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM public.scans
            JOIN public.domains ON public.domains.id = public.scans.domain_id
            WHERE public.scans.id = public.findings.scan_id
            AND public.domains.owner_id = auth.uid()
        )
    );

-- 11. TRIGGER OTOMATIS PEMBUATAN PROFILES SAAT USER DAFTAR DI SUPABASE AUTH
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
    INSERT INTO public.profiles (id, email, created_at)
    VALUES (new.id, new.email, now())
    ON CONFLICT (id) DO NOTHING;
    RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
