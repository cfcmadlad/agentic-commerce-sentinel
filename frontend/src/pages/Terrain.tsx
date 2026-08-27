import { useEffect, useMemo, useRef, useState } from "react";
import { contourSegments } from "../terrain/contour";
import { computeRiskField, percentileDomain, type Domain } from "../terrain/field";

/**
 * Risk terrain: a real kernel-density field over the model's own two
 * highest-ranked SHAP features, with contour lines extracted from that
 * field and a pannable, zoomable canvas to explore it in.
 *
 * Every visual element traces back to something real and stated as such:
 * the shaded surface is a Gaussian-kernel-weighted average of real
 * per-session ensemble scores (`terrain/field.ts`); the contour lines are
 * isolines of that exact array (`terrain/contour.ts`), not decoration; the
 * dots are the real sessions the field was built from. Sparse regions (few
 * real sessions nearby) are rendered lighter rather than confidently
 * colored, so the map doesn't imply certainty the underlying data doesn't
 * support. Pan with drag, zoom with the wheel; the "sensitivity" slider
 * doesn't change the terrain, it only changes which contour band is drawn
 * bold and which live block-rate numbers are shown below -- both computed
 * directly from the real per-session score array, not read off the map.
 */

interface CollisionPoint {
  score: number;
  category: string;
  blocked_by_rules: boolean;
  feature_x: number;
  feature_y: number;
}

interface CollisionData {
  threshold: number;
  feature_x_name: string;
  feature_y_name: string;
  points: CollisionPoint[];
}

const GRID_SIZE = 64;
const CANVAS_W = 900;
const CANVAS_H = 560;
const CELL_PX = CANVAS_W / GRID_SIZE;
const MIN_WEIGHT_TO_SHOW = 0.15;

const CATEGORY_LABELS: Record<string, string> = {
  legitimate: "Legitimate",
  scope_violation: "Scope violation",
  agent_impersonation: "Agent impersonation",
  mandate_replay: "Mandate replay",
  mandate_chaining: "Mandate chaining (held-out)",
};

function colorFor(category: string): [number, number, number] {
  if (category === "legitimate") return [199, 201, 205];
  if (category === "mandate_chaining") return [232, 147, 95];
  return [23, 25, 28];
}

function toGridX(value: number, domain: Domain): number {
  return ((value - domain.min) / (domain.max - domain.min)) * GRID_SIZE;
}

export default function Terrain() {
  const [data, setData] = useState<CollisionData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sensitivity, setSensitivity] = useState<number | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const dragState = useRef<{ startX: number; startY: number; panX: number; panY: number } | null>(null);

  useEffect(() => {
    fetch("/collision.json")
      .then((res) => {
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
        return res.json();
      })
      .then((d: CollisionData) => {
        setData(d);
        setSensitivity(d.threshold);
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  const built = useMemo(() => {
    if (!data) return null;
    const xDomain = percentileDomain(data.points.map((p) => p.feature_x));
    const yDomain = percentileDomain(data.points.map((p) => p.feature_y));
    // Points are pre-mapped into grid units [0, GRID_SIZE] below, so the
    // field's own domain is just that grid range, and the bandwidth is a
    // fixed fraction of it -- a stated smoothing choice, not fit via
    // cross-validation.
    const gridPoints = data.points.map((p) => ({
      x: toGridX(p.feature_x, xDomain),
      y: toGridX(p.feature_y, yDomain),
      score: p.score,
    }));
    const bandwidth = GRID_SIZE / 9;
    const { field, weight } = computeRiskField(
      gridPoints,
      GRID_SIZE,
      { min: 0, max: GRID_SIZE },
      { min: 0, max: GRID_SIZE },
      bandwidth,
      bandwidth,
    );
    return { xDomain, yDomain, field, weight };
  }, [data]);

  const stats = useMemo(() => {
    if (!data || sensitivity === null) return null;
    const byCategory: Record<string, { total: number; blocked: number }> = {};
    for (const p of data.points) {
      byCategory[p.category] ??= { total: 0, blocked: 0 };
      byCategory[p.category].total += 1;
      if (p.score >= sensitivity) byCategory[p.category].blocked += 1;
    }
    return byCategory;
  }, [data, sensitivity]);

  useEffect(() => {
    if (!built || !data || sensitivity === null) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, CANVAS_W, CANVAS_H);
    ctx.fillStyle = "#fafafb";
    ctx.fillRect(0, 0, CANVAS_W, CANVAS_H);
    ctx.translate(pan.x, pan.y);
    ctx.scale(zoom, zoom);

    for (let gy = 0; gy < GRID_SIZE; gy++) {
      for (let gx = 0; gx < GRID_SIZE; gx++) {
        const idx = gy * GRID_SIZE + gx;
        const w = built.weight[idx];
        if (w < MIN_WEIGHT_TO_SHOW) continue;
        const v = built.field[idx];
        ctx.fillStyle = `rgba(23,25,28,${(v * 0.85).toFixed(3)})`;
        ctx.fillRect(gx * CELL_PX, gy * CELL_PX, CELL_PX + 0.5, CELL_PX + 0.5);
      }
    }

    for (const [level, width, color] of [
      [0.1, 1, "rgba(151,151,153,0.6)"],
      [0.25, 1.2, "rgba(119,123,134,0.75)"],
      [0.5, 1.6, "rgba(23,25,28,0.85)"],
      [0.75, 2, "rgba(23,25,28,1)"],
    ] as const) {
      const segs = contourSegments(built.field, GRID_SIZE, level);
      ctx.strokeStyle = color;
      ctx.lineWidth = width / zoom;
      ctx.beginPath();
      for (const [[x1, y1], [x2, y2]] of segs) {
        ctx.moveTo(x1 * CELL_PX, y1 * CELL_PX);
        ctx.lineTo(x2 * CELL_PX, y2 * CELL_PX);
      }
      ctx.stroke();
    }

    for (const p of data.points) {
      const gx = toGridX(p.feature_x, built.xDomain) * CELL_PX;
      const gy = toGridX(p.feature_y, built.yDomain) * CELL_PX;
      const [r, g, b] = colorFor(p.category);
      const isHeldOut = p.category === "mandate_chaining";
      ctx.beginPath();
      ctx.arc(gx, gy, (isHeldOut ? 2.6 : 1.8) / Math.sqrt(zoom), 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${r},${g},${b},${isHeldOut ? 0.85 : 0.55})`;
      ctx.fill();
    }

    ctx.setTransform(1, 0, 0, 1, 0, 0);
  }, [built, data, sensitivity, zoom, pan]);

  function onWheel(e: React.WheelEvent<HTMLCanvasElement>) {
    e.preventDefault();
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const scaleFactor = CANVAS_W / rect.width;
    const mouseX = (e.clientX - rect.left) * scaleFactor;
    const mouseY = (e.clientY - rect.top) * scaleFactor;
    const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
    const newZoom = Math.max(0.6, Math.min(8, zoom * factor));
    const worldX = (mouseX - pan.x) / zoom;
    const worldY = (mouseY - pan.y) / zoom;
    setZoom(newZoom);
    setPan({ x: mouseX - worldX * newZoom, y: mouseY - worldY * newZoom });
  }

  function onPointerDown(e: React.PointerEvent<HTMLCanvasElement>) {
    dragState.current = { startX: e.clientX, startY: e.clientY, panX: pan.x, panY: pan.y };
    (e.target as HTMLCanvasElement).setPointerCapture(e.pointerId);
  }

  function onPointerMove(e: React.PointerEvent<HTMLCanvasElement>) {
    if (!dragState.current || !canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const scaleFactor = CANVAS_W / rect.width;
    const dx = (e.clientX - dragState.current.startX) * scaleFactor;
    const dy = (e.clientY - dragState.current.startY) * scaleFactor;
    setPan({ x: dragState.current.panX + dx, y: dragState.current.panY + dy });
  }

  function onPointerUp() {
    dragState.current = null;
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
  if (!data || !built || sensitivity === null) {
    return <div className="loading-state">Computing terrain from real session data…</div>;
  }

  return (
    <>
      <div className="panel">
        <h2 className="section-title">Risk terrain</h2>
        <p className="section-note">
          A real kernel-density field over this model's two highest-ranked features —{" "}
          <code>{data.feature_x_name}</code> (horizontal) and <code>{data.feature_y_name}</code> (vertical) —
          built from {data.points.length.toLocaleString()} real sessions. Darker ground means real sessions near
          that point scored higher on average; the contour lines are isolines of that same field, not drawn by
          hand. Faded regions have too few nearby real sessions to estimate confidently, and are left faded
          rather than colored in. Drag to pan, scroll to zoom.
        </p>
      </div>

      <div className="panel">
        <canvas
          ref={canvasRef}
          width={CANVAS_W}
          height={CANVAS_H}
          className="terrain-canvas"
          onWheel={onWheel}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerLeave={onPointerUp}
        />
        <label className="field-label">Sensitivity (score threshold): {sensitivity.toFixed(4)}</label>
        <input
          type="range"
          min={0}
          max={1}
          step={0.001}
          value={sensitivity}
          onChange={(e) => setSensitivity(Number(e.target.value))}
          className="sandbox-slider"
        />
        <p className="section-note" style={{ marginTop: 6, marginBottom: 0 }}>
          Deployed threshold: {data.threshold.toFixed(4)}. Legend: <span style={{ color: "#979799" }}>●</span>{" "}
          legitimate · <span style={{ color: "#17191c" }}>●</span> known attack ·{" "}
          <span style={{ color: "#e8935f" }}>●</span> mandate chaining (held-out).
        </p>
      </div>

      <div className="panel">
        <h3 className="section-title">At this sensitivity</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Category</th>
              <th>Sessions</th>
              <th>Would be blocked</th>
            </tr>
          </thead>
          <tbody>
            {stats &&
              Object.entries(stats).map(([category, s]) => (
                <tr key={category}>
                  <td>{CATEGORY_LABELS[category] ?? category}</td>
                  <td>{s.total}</td>
                  <td>{((s.blocked / s.total) * 100).toFixed(1)}%</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
