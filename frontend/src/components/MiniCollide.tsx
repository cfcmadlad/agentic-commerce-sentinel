import { useEffect, useMemo, useRef, useState } from "react";
import {
  colorForCategory,
  jitterFor,
  loadCollisionData,
  scoreToUnit,
  unitToScore,
  type CollisionData,
} from "../lib/collide";
import { Link } from "react-router-dom";

/**
 * A compact, draggable-threshold version of the /collide chart, embedded on
 * the landing page in place of a static quote. Same real data
 * (`public/collision.json`), same log-scale scoring math (`lib/collide.ts`),
 * just a smaller canvas and a two-number readout instead of the full
 * per-category table -- the held-out-class finding made interactive at a
 * glance, not asserted in a pull-quote.
 */

const WIDTH = 520;
const HEIGHT = 200;
const MARGIN = { top: 14, right: 12, bottom: 8, left: 12 };
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

export default function MiniCollide() {
  const [data, setData] = useState<CollisionData | null>(null);
  const [threshold, setThreshold] = useState<number | null>(null);
  const [dragging, setDragging] = useState(false);
  const svgRef = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    loadCollisionData()
      .then((d) => {
        setData(d);
        setThreshold(d.threshold);
      })
      .catch(() => {
        /* Landing page degrades gracefully: the widget simply doesn't render. */
      });
  }, []);

  const rates = useMemo(() => {
    if (!data || threshold === null) return null;
    return {
      legitimate: blockRate(data.points, "legitimate", threshold),
      chaining: blockRate(data.points, "mandate_chaining", threshold),
    };
  }, [data, threshold]);

  function handlePointerMove(clientX: number) {
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const scaleX = WIDTH / rect.width;
    setThreshold(xToScore((clientX - rect.left) * scaleX));
  }

  if (!data || threshold === null) return null;

  const thresholdX = scoreToX(threshold);

  return (
    <div className="mini-collide">
      <div className="mini-collide__label">Live data, not a quote</div>
      <p className="mini-collide__intro">
        {data.points.length.toLocaleString()} real scored sessions. Drag the line — try to find a
        threshold that catches the held-out attack class without blocking legitimate traffic.
      </p>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="mini-collide__svg"
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
          stroke="#17191c"
          strokeWidth={2}
          style={{ cursor: "ew-resize" }}
        />
      </svg>
      {rates && (
        <div className="mini-collide__stats">
          <div>
            <span className="mini-collide__stat-value">{rates.legitimate.toFixed(1)}%</span>
            <span className="mini-collide__stat-label">legitimate blocked</span>
          </div>
          <div>
            <span className="mini-collide__stat-value mini-collide__stat-value--accent">
              {rates.chaining.toFixed(1)}%
            </span>
            <span className="mini-collide__stat-label">mandate chaining caught</span>
          </div>
        </div>
      )}
      <Link to="/collide" className="mini-collide__cta">
        Open the full chart →
      </Link>
    </div>
  );
}
