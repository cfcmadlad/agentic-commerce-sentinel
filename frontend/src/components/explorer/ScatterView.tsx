import { useRef, useState } from "react";
import { colorForCategory, jitterFor, scoreToUnit, unitToScore, type CollisionData } from "../../lib/collide";

/**
 * Log-scale scatter of every real scored session -- horizontal position is
 * the real ensemble score (meaningful), vertical position is deterministic
 * jitter for visual separation (meaningless, stated in Explorer's own
 * intro copy). Threshold is owned by the parent `Explorer` page and shared
 * with `TerrainView`, so dragging here and switching tabs shows the same
 * operating point.
 */

const WIDTH = 900;
const HEIGHT = 360;
const MARGIN = { top: 20, right: 24, bottom: 36, left: 24 };
const PLOT_W = WIDTH - MARGIN.left - MARGIN.right;
const PLOT_H = HEIGHT - MARGIN.top - MARGIN.bottom;

function scoreToX(score: number): number {
  return MARGIN.left + scoreToUnit(score) * PLOT_W;
}

function xToScore(x: number): number {
  return unitToScore((x - MARGIN.left) / PLOT_W);
}

interface Props {
  data: CollisionData;
  threshold: number;
  onThresholdChange: (threshold: number) => void;
}

export default function ScatterView({ data, threshold, onThresholdChange }: Props) {
  const [dragging, setDragging] = useState(false);
  const svgRef = useRef<SVGSVGElement | null>(null);

  function handlePointerMove(clientX: number) {
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const scaleX = WIDTH / rect.width;
    const localX = (clientX - rect.left) * scaleX;
    onThresholdChange(xToScore(localX));
  }

  const thresholdX = scoreToX(threshold);
  const realThresholdX = scoreToX(data.threshold);

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      className="explorer-svg"
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
          <line x1={scoreToX(tick)} x2={scoreToX(tick)} y1={MARGIN.top} y2={HEIGHT - MARGIN.bottom} stroke="#ececec" />
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
  );
}
