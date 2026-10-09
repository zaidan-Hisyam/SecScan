import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecScan - Platform Pemindai Keamanan Pribadi",
  description: "Pemindai kerentanan pasif & non-destruktif untuk domain terverifikasi",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="id">
      <body className="bg-[#0a0c10] text-[#e6edf3] antialiased selection:bg-cyan-500/20 selection:text-cyan-300">
        {children}
      </body>
    </html>
  );
}
