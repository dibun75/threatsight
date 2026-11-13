"use client";

import { useParams } from "next/navigation";

import { MatchDetail } from "@/components/exposure/Phase2";

export default function MatchPage() {
  const params = useParams<{ id: string }>();
  return <MatchDetail id={params.id} />;
}
