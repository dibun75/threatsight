"use client";

import { useParams } from "next/navigation";

import { AssetDetail } from "@/components/exposure/Phase2";

export default function AssetPage() {
  const params = useParams<{ id: string }>();
  return <AssetDetail id={params.id} />;
}
