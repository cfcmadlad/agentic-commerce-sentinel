import { useEffect, useMemo, useRef, useState } from "react";
import {
  CATEGORY_LABELS,
  colorForCategory,
  jitterFor,
  loadCollisionData,
  scoreToUnit,
  unitToScore,
  type CollisionData,
} from "../lib/collide";

/**
 * The collision chart.
 *
 * Every point here is one real session from `run_collision_export.py`'s
 * output (`public/collision.json`) -- its real ensemble score, from the
 * same frozen fit the full evaluation and the held-out evaluation report on. There
 * is no synthesized data in this file; only the horizontal position (a log
 * scale of the real score) carries meaning, vertical position is pure
 * jitter for visual separation, stated plainly in the caption rather than
 * left for a viewer to assume otherwise.
 *
 * Dragging the threshold line recomputes recall/false-positive-rate live,
 * directly from the exported per-point array -- not an animation, an
 * actual re-aggregation on every frame. The point of this page: you can
 * try, yourself, to find a threshold that catches `mandate_chaining`
 * without blocking most legitimate traffic. You won't find one, because
 * the scores are not separable in this dimension -- which is the real,
 * disclosed held-out-evaluation finding, made falsifiable instead of just
 * asserted.
 */

const WIDTH = 900;
const HEIGHT = 420;
const MARGIN = { top: 20, right: 24, bottom: 44, left: 24 };
const PLOT_W = WIDTH - MARGIN.left - MARGIN.right;
const PLOT_H = HEIGHT - MARGIN.top - MARGIN.bottom;

function scoreToX(score: number): number {
  return MARGIN.left + scoreToUnit(score) * PLOT_W;
}

function xToScore(x: number): number {
  return unitToScore((x - MARGIN.left) / PLOT_W);
}

export default function Collide() {
  const [data, setData] = useState<CollisionData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [threshold, setThreshold] = useState<number | null>(null);
  const [dragging, setDragging] = useState(false);
  const svgRef = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    loadCollisionData()
      .then((d) => {
        setData(d);
        setThreshold(d.threshold);
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  const stats = useMemo(() => {
    if (!data || threshold === null) return null;
    const byCategory: Record<string, { total: number; blocked: number }> = {};
    for (const p of data.points) {
      byCategory[p.category] ??= { total: 0, blocked: 0 };
      byCategory[p.category].total += 1;
      if (p.score >= threshold) byCategory[p.category].blocked += 1;
    }
    return byCategory;
  }, [data, threshold]);

  function handlePointerMove(clientX: number) {
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const scaleX = WIDTH / rect.width;
    const localX = (clientX - rect.left) * scaleX;
    setThreshold(xToScore(localX));
  }

  if (error) {
    return (
      <div className="error-state">
        Could not load collision.json: {error}
        <br />
        Generate it with: <code>python run_collision_export.py --json-out frontend/public/collision.json</code>
      </div>
    );
  }
  if (!data || threshold === null) {
    return <div className="loading-state">Loading collision.json…</div>;
  }

  const thresholdX = scoreToX(threshold);
  const realThresholdX = scoreToX(data.threshold);

  return (
    <>
      <div className="panel">
        <div className="page-intro">
          <span className="page-intro__eyebrow">New here?</span>
          <p>
            Every dot below is one real transaction this system already scored, positioned by how
            suspicious it looked — further right means a higher risk score. Drag the black line
            left or right to see what would happen at a different block threshold, including on an
            attack type ("mandate chaining") this system was never trained to catch.
          </p>
        </div>
        <h2 className="section-title">Collide</h2>
        <p className="section-note">
          {data.points.length.toLocaleString()} real sessions, each plotted at its real ensemble
          score (horizontal axis, logarithmic — most of this system's real decisions happen in a
          very narrow band near zero). Vertical position carries no meaning; it exists only so
          points don't stack directly on top of each other. Drag the line.
        </p>
      </div>

      <div className="panel">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          className="collide-svg"
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
          {[0.001, 0.01, 0.1, 1].map((tick) => (
            <g key={tick}>
              <line
                x1={scoreToX(tick)}
                x2={scoreToX(tick)}
                y1={MARGIN.top}
                y2={HEIGHT - MARGIN.bottom}
                stroke="#ececec"
              />
              <text x={scoreToX(tick)} y={HEIGHT - MARGIN.bottom + 18} fontSize={11} fill="#979799" textAnchor="middle">
                {tick}
              </text>
            </g>
          ))}

          {data.points.map((p, i) => (
            <circle
              key={i}
              cx={scoreToX(p.score)}
              cy={MARGIN.top + jitterFor(i) * PLOT_H}
              r={p.category === "mandate_chaining" ? 3.4 : 2.6}
              fill={colorForCategory(p.category)}
              opacity={p.score >= threshold ? 0.9 : 0.35}
            />
          ))}

          <line
            x1={realThresholdX}
            x2={realThresholdX}
            y1={MARGIN.top}
            y2={HEIGHT - MARGIN.bottom}
            stroke="#979799"
            strokeDasharray="3 3"
          />
          <text x={realThresholdX} y={MARGIN.top - 6} fontSize={10.5} fill="#979799" textAnchor="middle">
            deployed threshold
          </text>

          <line
            x1={thresholdX}
            x2={thresholdX}
            y1={MARGIN.top}
            y2={HEIGHT - MARGIN.bottom}
            stroke="#17191c"
            strokeWidth={2}
            style={{ cursor: "ew-resize" }}
          />
          <polygon
            points={`${thresholdX - 6},${MARGIN.top} ${thresholdX + 6},${MARGIN.top} ${thresholdX},${MARGIN.top + 10}`}
            fill="#17191c"
          />
        </svg>
        <p className="section-note" style={{ marginTop: 8, marginBottom: 0 }}>
          Your threshold: <strong>{threshold.toFixed(4)}</strong> · deployed threshold:{" "}
          {data.threshold.toFixed(4)}
        </p>
      </div>

      <div className="panel">
        <h3 className="section-title">At this threshold</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Category</th>
              <th>Sessions shown</th>
              <th>Would be blocked</th>
            </tr>
          </thead>
          <tbody>
            {stats &&
              Object.entries(stats).map(([category, s]) => (
                <tr key={category}>
                  <td>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                      <span
                        style={{
                          width: 9,
                          height: 9,
                          borderRadius: "50%",
                          background: colorForCategory(category),
                          display: "inline-block",
                        }}
                      />
                      {CATEGORY_LABELS[category] ?? category}
                    </span>
                  </td>
                  <td>{s.total}</td>
                  <td>{((s.blocked / s.total) * 100).toFixed(1)}%</td>
                </tr>
              ))}
          </tbody>
        </table>
        <p className="section-note" style={{ marginTop: 12, marginBottom: 0 }}>
          Try to find a threshold that catches most of "Mandate chaining" without blocking most of
          "Legitimate." There isn't one in this chart — the two distributions sit almost on top of
          each other near zero, which is the real, disclosed reason Layers 1–3 miss 99%+ of that
          class: nothing here reasons about a mandate's parent-child relationship at all.
        </p>
      </div>
    </>
  );
}
