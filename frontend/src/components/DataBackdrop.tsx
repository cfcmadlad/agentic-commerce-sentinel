import { useEffect, useState } from "react";
import { colorForCategory, loadCollisionData, type CollisionData } from "../lib/collide";

/**
 * A faint, decorative scatter behind a hero/section, built from the same
 * real per-session scores `/collide` plots -- not a stock texture or a
 * generated pattern. Placement on the page (x, y) is a deterministic hash
 * of each point's index, carrying no meaning of its own, the same
 * disclosed convention `/collide`'s vertical jitter already uses; what IS
 * real is which points appear at all (a subsample of actual sessions) and
 * their color/size, driven by the real category and score. Purely
 * decorative and non-interactive: `pointer-events: none`, sits behind
 * page content via z-index.
 */

const MAX_POINTS = 220;

function hashUnit(seed: number): number {
  const x = Math.sin(seed * 78.233) * 43758.5453;
  return x - Math.floor(x);
}

function subsample<T>(items: T[], n: number): T[] {
  if (items.length <= n) return items;
  const step = items.length / n;
  const out: T[] = [];
  for (let i = 0; i < n; i++) out.push(items[Math.floor(i * step)]);
  return out;
}

export default function DataBackdrop({ className }: { className?: string }) {
  const [data, setData] = useState<CollisionData | null>(null);

  useEffect(() => {
    loadCollisionData()
      .then(setData)
      .catch(() => {
        /* Decorative only -- if collision.json isn't reachable, render nothing. */
      });
  }, []);

  if (!data) return null;
  const points = subsample(data.points, MAX_POINTS);

  return (
    <svg className={`data-backdrop ${className ?? ""}`} viewBox="0 0 1000 1000" preserveAspectRatio="none" aria-hidden="true">
      {points.map((p, i) => {
        const cx = hashUnit(i * 2.13) * 1000;
        const cy = hashUnit(i * 3.71 + 11) * 1000;
        const isChaining = p.category === "mandate_chaining";
        const r = isChaining ? 5 : 2.5 + p.score * 6;
        return <circle key={i} cx={cx} cy={cy} r={r} fill={colorForCategory(p.category)} />;
      })}
    </svg>
  );
}
