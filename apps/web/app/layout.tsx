import type { ReactNode } from "react";

import { AppShell } from "@/components/AppShell";
import "./globals.css";
import "./polish.css";

export const metadata = {
  title: "ThreatSight — Hybrid security readiness",
  description: "Synthetic reference environment. Know what matters. Prove you are ready. No customer systems are connected.",
  icons: { icon: "/favicon.svg" },
};

export const viewport = {
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
