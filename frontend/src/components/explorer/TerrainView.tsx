import { useEffect, useMemo, useRef, useState } from "react";
import type { CollisionData } from "../../lib/collide";
import { contourSegments } from "../../terrain/contour";
import { computeRiskField, percentileDomain, type Domain } from "../../terrain/field";

/**
 * A real kernel-density field over the model's own two highest-ranked SHAP
 * features, with contour lines extracted from that field, on a pannable,
 * zoomable canvas. The shaded surface is a Gaussian-kernel-weighted average
 * of real per-session ensemble scores (`terrain/field.ts`); the contour
 * lines are isolines of that exact array (`terrain/contour.ts`), not
 * decoration. Threshold is owned by the parent `Explorer` page (shared with
 * `ScatterView`) -- this view only reads it, to highlight the matching
 * contour band; it does not own a slider of its own.
 */

const GRID_SIZE = 64;
const CANVAS_W = 900;
const CANVAS_H = 460;
const CELL_PX = CANVAS_W / GRID_SIZE;
const MIN_WEIGHT_TO_SHOW = 0.15;

function colorFor(category: string): [number, number, number] {
  if (category === "legitimate") return [199, 201, 205];
  if (category === "mandate_chaining") return [232, 147, 95];
  return [23, 25, 28];
}

function toGridX(value: number, domain: Domain): number {
  return ((value - domain.min) / (domain.max - domain.min)) * GRID_SIZE;
}

interface Props {
  data: CollisionData;
  threshold: number;
}

export default function TerrainView({ data, threshold }: Props) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const dragState = useRef<{ startX: number; startY: number; panX: number; panY: number } | null>(null);

  const built = useMemo(() => {
    const xDomain = percentileDomain(data.points.map((p) => p.feature_x));
    const yDomain = percentileDomain(data.points.map((p) => p.feature_y));
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

  useEffect(() => {
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
      const isHighlighted = p.score >= threshold;
      ctx.beginPath();
      ctx.arc(gx, gy, (isHeldOut ? 2.6 : 1.8) / Math.sqrt(zoom), 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${r},${g},${b},${isHeldOut ? 0.85 : isHighlighted ? 0.7 : 0.4})`;
      ctx.fill();
    }

    ctx.setTransform(1, 0, 0, 1, 0, 0);
  }, [built, data, threshold, zoom, pan]);

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

  return (
    <>
      <canvas
        ref={canvasRef}
        width={CANVAS_W}
        height={CANVAS_H}
        className="explorer-canvas"
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={onPointerUp}
      />
      <p className="section-note" style={{ marginTop: 8, marginBottom: 0 }}>
        A real kernel-density field over <code>{data.feature_x_name}</code> (horizontal) and{" "}
        <code>{data.feature_y_name}</code> (vertical). Darker ground means real sessions near that
        point scored higher on average; faded regions have too few nearby sessions to estimate
        confidently. Drag to pan, scroll to zoom.
      </p>
    </>
  );
}
