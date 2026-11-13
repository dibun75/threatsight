/** Turn source enum codes such as `researcher_observed` or `PERCENTAGE` into readable text. */
export function humanize(value: string | null | undefined): string {
  if (!value) return "";
  if (value.toUpperCase() === "PERCENTAGE") return "share of total";
  const text = value.replaceAll("_", " ").trim().toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}
