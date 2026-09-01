import { useMemo, useRef, useState } from "react";
import { colorForCategory, jitterFor, scoreToUnit, unitToScore, type CollisionData } from "../lib/collide";

/**
 * A compact, draggable-threshold view of the real per-session score
 * distribution (`public/collision.json`, fetched once by `Dashboard` and
 * passed in as `data` -- same math as `/explorer`), sized for the Overview
 * panel. The held-out-class finding made interactive at a glance rather
 * than only stated as a number.
 */

const WIDTH = 520;
const HEIGHT = 160;
const MARGIN = { top: 10, right: 10, bottom: 8, left: 10 };
const PLOT_W = WIDTH - MARGIN.left - MARGIN.right;
const PLOT_H = HEIGHT - MARGIN.top - MARGIN.bottom;

function scoreToX(score: number): number {
  return MARGIN.left + scoreToUnit(score) * PLOT_W;
}

function xToScore(x: number): number {
  return unitToScore((x - MARGIN.left) / PLOT_W);
}

function blockRate(points: CollisionData["points"], category: string, threshold: number): number {
  const matching = points.filter((p) => p.category === category);
  if (matching.length === 0) return 0;
  return (matching.filter((p) => p.score >= threshold).length / matching.length) * 100;
}

export default function ThresholdSparkline({ data }: { data: CollisionData }) {
  const [threshold, setThreshold] = useState(data.threshold);
  const [dragging, setDragging] = useState(false);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const rates = useMemo(
    () => ({
      legitimate: blockRate(data.points, "legitimate", threshold),
      chaining: blockRate(data.points, "mandate_chaining", threshold),
    }),
    [data, threshold],
  );

  function handlePointerMove(clientX: number) {
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const scaleX = WIDTH / rect.width;
    setThreshold(xToScore((clientX - rect.left) * scaleX));
  }

  const thresholdX = scoreToX(threshold);

  return (
    <div>
      <p className="section-note">
        {data.points.length.toLocaleString()} real scored sessions. Drag the line to test any
        threshold, including against the held-out attack class this system was never trained to
        catch.
      </p>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="sparkline__svg"
        onPointerDown={(e) => {
          setDragging(true);
          handlePointerMove(e.clientX);
        }}
        onPointerMove={(e) => {
          if (dragging) handlePointerMove(e.clientX);
        }}
        onPointerUp={() => setDragging(false)}
        onPointerLeave={() => setDragging(false)}
      >
        {data.points.map((p, i) => (
          <circle
            key={i}
            cx={scoreToX(p.score)}
            cy={MARGIN.top + jitterFor(i) * PLOT_H}
            r={p.category === "mandate_chaining" ? 2.6 : 1.9}
            fill={colorForCategory(p.category)}
            opacity={p.score >= threshold ? 0.9 : 0.3}
          />
        ))}
        <line
          x1={thresholdX}
          x2={thresholdX}
          y1={MARGIN.top}
          y2={HEIGHT - MARGIN.bottom}
          stroke="#9c6f1e"
          strokeWidth={2}
          style={{ cursor: "ew-resize" }}
        />
      </svg>
      <div className="sparkline__stats">
        <div>
          <span className="sparkline__stat-value">{rates.legitimate.toFixed(1)}%</span>
          <span className="sparkline__stat-label">legitimate blocked</span>
        </div>
        <div>
          <span className="sparkline__stat-value sparkline__stat-value--flag">
            {rates.chaining.toFixed(1)}%
          </span>
          <span className="sparkline__stat-label">mandate chaining caught</span>
        </div>
      </div>
    </div>
  );
}
