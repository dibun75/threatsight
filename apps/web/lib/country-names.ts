/** Public labels. ISO codes stay the stored identifiers. */
const PUBLIC_LABELS: Record<string, string> = {
  US: "United States",
};

const REGION_NAMES = typeof Intl !== "undefined" && "DisplayNames" in Intl ? new Intl.DisplayNames(["en"], { type: "region" }) : null;

export function publicCountryName(code: string, sourceName: string): string {
  if (PUBLIC_LABELS[code]) return PUBLIC_LABELS[code];
  if (sourceName === code && /^[A-Z]{2}$/.test(code)) {
    try {
      return REGION_NAMES?.of(code) ?? code;
    } catch {
      return code;
    }
  }
  return sourceName;
}
