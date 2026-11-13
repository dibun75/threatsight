"use client";

import { useParams } from "next/navigation";

import { ServiceDetail } from "@/components/exposure/Phase2";

export default function ServicePage() {
  const params = useParams<{ id: string }>();
  return <ServiceDetail id={params.id} />;
}
