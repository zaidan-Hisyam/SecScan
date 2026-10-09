"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Shield, KeyRound, Mail, AlertCircle, ArrowRight } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const supabase = createClient();
      const { error: signInError } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (signInError) {
        setError(signInError.message);
        return;
      }

      router.push("/dashboard");
      router.refresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Terjadi kesalahan saat login");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-[#0a0c10] bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(0,240,255,0.08),rgba(255,255,255,0))]">
      <div className="w-full max-w-md p-8 rounded-lg border border-[#1b2230] bg-[#0d1117]/90 backdrop-blur-xl shadow-2xl relative overflow-hidden">
        {/* Accent Glow */}
        <div className="absolute -top-10 -right-10 w-32 h-32 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded border border-cyan-500/40 bg-cyan-950/40 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.2)]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="font-mono font-bold text-lg text-white tracking-wide">
              MASUK <span className="text-cyan-400">PORTAL</span>
            </h1>
            <p className="text-xs text-slate-400 font-sans">
              Autentikasi akun pemindai keamanan
            </p>
          </div>
        </div>

        {error && (
          <div className="mb-6 p-3 rounded border border-red-500/30 bg-red-950/30 text-red-300 text-xs flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1.5 uppercase tracking-wider">
              Alamat Email
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="nama@domain.com"
                className="w-full pl-9 pr-3 py-2 text-sm bg-[#06080b] border border-[#21262d] rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-sans"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1.5 uppercase tracking-wider">
              Kata Sandi
            </label>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full pl-9 pr-3 py-2 text-sm bg-[#06080b] border border-[#21262d] rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-sans"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 mt-2 rounded border border-cyan-500 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60 hover:shadow-[0_0_20px_rgba(0,240,255,0.25)] text-xs font-mono font-semibold tracking-wider transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Memverifikasi..." : "Masuk ke Sistem"}
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <div className="mt-6 pt-5 border-t border-[#1b2230] text-center text-xs font-mono text-slate-400">
          Belum punya akun?{" "}
          <Link
            href="/register"
            className="text-cyan-400 hover:text-cyan-300 hover:underline"
          >
            Daftar di sini
          </Link>
        </div>
      </div>
    </div>
  );
}
