"use client";

import { useState } from "react";

export function ConfirmButton({
  label,
  confirmLabel,
  onConfirm,
  disabled,
  className = "btn",
}: {
  label: string;
  confirmLabel: string;
  onConfirm: () => void;
  disabled?: boolean;
  className?: string;
}) {
  const [armed, setArmed] = useState(false);
  if (!armed) {
    return (
      <button className={className} type="button" disabled={disabled} onClick={() => setArmed(true)}>
        {label}
      </button>
    );
  }
  return (
    <span className="confirm-pair">
      <button className="btn" type="button" disabled={disabled} onClick={() => { setArmed(false); onConfirm(); }}>
        {confirmLabel}
      </button>
      <button className="btn secondary" type="button" onClick={() => setArmed(false)}>
        Cancel
      </button>
    </span>
  );
}
