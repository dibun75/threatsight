export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="ts-loading" role="status" aria-live="polite">
      <p className="ts-loading-label">{label}</p>
      <span className="ts-line" aria-hidden="true" />
      <span className="ts-line" aria-hidden="true" />
      <span className="ts-line" aria-hidden="true" />
    </div>
  );
}
