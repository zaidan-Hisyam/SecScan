"use client";

import { useRouter } from "next/navigation";
import { LogOut } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

export function LogoutButton() {
  const router = useRouter();

  const handleLogout = async () => {
    const supabase = createClient();
    await supabase.auth.signOut();
    router.push("/login");
    router.refresh();
  };

  return (
    <button
      onClick={handleLogout}
      className="px-3 py-1.5 text-xs font-mono text-slate-400 hover:text-red-400 hover:bg-red-950/20 border border-transparent hover:border-red-500/30 rounded transition-all flex items-center gap-1.5"
    >
      <LogOut className="w-3.5 h-3.5" />
      <span>Keluar</span>
    </button>
  );
}
