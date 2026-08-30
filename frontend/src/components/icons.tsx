/**
 * Shared inline icons, drawn in one consistent stroke style (viewBox 0-24,
 * currentColor stroke, 1.6 weight) so every hand-drawn glyph in the app
 * reads as one family, not several. No icon library dependency.
 */

import type { ReactNode } from "react";

const STROKE = { stroke: "currentColor", strokeWidth: 1.6, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };

function IconBase({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <svg className={className} width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      {children}
    </svg>
  );
}

/** The nav brand mark -- a shield with a checkmark. Doubles as "Sentinel" wherever the system itself needs a face. */
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg className={className} width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2.5 3 6.5v5.2c0 5.6 3.8 9.9 9 11.3 5.2-1.4 9-5.7 9-11.3V6.5L12 2.5Z" {...STROKE} />
      <path d="M8.4 12.1 11 14.7l4.6-5.4" {...STROKE} />
    </svg>
  );
}

/** A simple bot glyph representing the AI agent side of a session -- deliberately plain, not a mascot. */
export function AgentMark({ className }: { className?: string }) {
  return (
    <svg className={className} width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="5" y="8.5" width="14" height="10" rx="3" {...STROKE} />
      <circle cx="9.5" cy="13.5" r="1.1" fill="currentColor" stroke="none" />
      <circle cx="14.5" cy="13.5" r="1.1" fill="currentColor" stroke="none" />
      <path d="M12 8.5V5.5" {...STROKE} />
      <circle cx="12" cy="4.6" r="1" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function OverviewIcon({ className }: { className?: string }) {
  return (
    <IconBase className={className}>
      <rect x="3.5" y="3.5" width="7.5" height="7.5" rx="1.3" {...STROKE} />
      <rect x="13" y="3.5" width="7.5" height="4.5" rx="1.3" {...STROKE} />
      <rect x="13" y="10" width="7.5" height="10.5" rx="1.3" {...STROKE} />
      <rect x="3.5" y="13" width="7.5" height="7.5" rx="1.3" {...STROKE} />
    </IconBase>
  );
}

export function DecisionsIcon({ className }: { className?: string }) {
  return (
    <IconBase className={className}>
      <path d="M4 5.5h16v10H9l-4 3.5v-3.5H4z" {...STROKE} />
      <path d="M8 9.5h8M8 12.5h5" {...STROKE} />
    </IconBase>
  );
}

export function SandboxIcon({ className }: { className?: string }) {
  return (
    <IconBase className={className}>
      <rect x="4.5" y="10.5" width="15" height="10" rx="2" {...STROKE} />
      <path d="M8 10.5V7a4 4 0 0 1 8 0v3.5" {...STROKE} />
    </IconBase>
  );
}

export function OrganizationsIcon({ className }: { className?: string }) {
  return (
    <IconBase className={className}>
      <rect x="4" y="10" width="6" height="10" rx="1" {...STROKE} />
      <rect x="14" y="6" width="6" height="14" rx="1" {...STROKE} />
      <path d="M7 13.5h.01M7 16.5h.01M17 9.5h.01M17 12.5h.01M17 15.5h.01" {...STROKE} />
    </IconBase>
  );
}

export function ExplorerIcon({ className }: { className?: string }) {
  return (
    <IconBase className={className}>
      <path d="M4 20 9 9l4 5 3-4 4 10" {...STROKE} />
      <circle cx="9" cy="9" r="1.2" fill="currentColor" stroke="none" />
      <circle cx="13" cy="14" r="1.2" fill="currentColor" stroke="none" />
      <circle cx="16" cy="10" r="1.2" fill="currentColor" stroke="none" />
    </IconBase>
  );
}

export function EvaluationIcon({ className }: { className?: string }) {
  return (
    <IconBase className={className}>
      <path d="M3 12h4l2 6 4-14 2 8h6" {...STROKE} />
    </IconBase>
  );
}

export function AboutIcon({ className }: { className?: string }) {
  return (
    <IconBase className={className}>
      <circle cx="12" cy="12" r="8.5" {...STROKE} />
      <path d="M12 11v5.5" {...STROKE} />
      <circle cx="12" cy="7.8" r="1" fill="currentColor" stroke="none" />
    </IconBase>
  );
}
