/**
 * Shared inline icons, drawn in the same stroke style as the landing
 * page's layer icons (viewBox 0-24, currentColor stroke, 1.6 weight) so
 * every hand-drawn glyph in the app reads as one family, not several.
 */

const STROKE = { stroke: "currentColor", strokeWidth: 1.6, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };

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
