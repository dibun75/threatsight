"use client";

import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { MatchList } from "@/components/exposure/Phase2";

function Matches() {
  const params = useSearchParams();
  return <MatchList cve={params.get("cve") || undefined} />;
}

export default function MatchesPage() {
  return (
    <Suspense fallback={<p>Loading matches</p>}>
      <Matches />
    </Suspense>
  );
}
