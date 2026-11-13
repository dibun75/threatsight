"use client";

import { useParams } from "next/navigation";

import { PathDetail } from "@/components/exposure/Phase2";

export default function PathPage() {
  const params = useParams<{ id: string }>();
  return <PathDetail id={params.id} />;
}
