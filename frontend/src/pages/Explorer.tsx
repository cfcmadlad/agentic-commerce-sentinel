import { useState } from "react";
import ScatterView from "../components/explorer/ScatterView";
import TerrainView from "../components/explorer/TerrainView";
import { CATEGORY_LABELS, colorForCategory, computeCategoryStats, type CollisionData } from "../lib/collide";

/**
 * Score exploration: the same real per-session data (`public/collision.json`,
 * fetched once by `Dashboard` and passed in as `data`) as either a log-scale
 * scatter (`ScatterView`) or a kernel-density terrain (`TerrainView`),
 * switched with a segmented control. Both were previously separate pages
 * with their own independent threshold controls over the identical domain
 * concept -- merged here into one shared `threshold` state, so dragging in
 * one view and switching tabs shows the same operating point in the other,
 * instead of two controls that could disagree.
 */

type View = "scatter" | "terrain";

export default function Explorer({ data }: { data: CollisionData }) {
  const [threshold, setThreshold] = useState(data.threshold);
  const [view, setView] = useState<View>("scatter");

  const stats = computeCategoryStats(data.points, threshold);

  return (
    <>
      <div className="panel">
        <div className="page-intro">
          <span className="page-intro__eyebrow">New here?</span>
          <p>
            {data.points.length.toLocaleString()} real transactions this system already scored,
            including the held-out mandate-chaining class it was never trained to catch. Drag the
            threshold in either view to see what block rate results — the operating point carries
            over when you switch views.
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
          <div>
            <h2 className="section-title">Explorer</h2>
            <p className="section-note" style={{ marginBottom: 0 }}>
              Your threshold: <strong>{threshold.toFixed(4)}</strong> · deployed threshold: {data.threshold.toFixed(4)}
            </p>
          </div>
          <div className="segmented-control">
            <button className={view === "scatter" ? "active" : ""} onClick={() => setView("scatter")}>
              Scatter
            </button>
            <button className={view === "terrain" ? "active" : ""} onClick={() => setView("terrain")}>
              Terrain
            </button>
          </div>
        </div>
      </div>

      <div className="panel">
        {view === "scatter" ? (
          <ScatterView data={data} threshold={threshold} onThresholdChange={setThreshold} />
        ) : (
          <TerrainView data={data} threshold={threshold} />
        )}
        <label className="field-label" htmlFor="explorer-threshold">
          Threshold (drag here, or drag the line in Scatter view)
        </label>
        <input
          id="explorer-threshold"
          type="range"
          min={0}
          max={1}
          step={0.0005}
          value={threshold}
          onChange={(e) => setThreshold(Number(e.target.value))}
          className="sandbox-slider"
        />
      </div>

      <div className="panel">
        <h3 className="section-title">At this threshold</h3>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Category</th>
                <th>Sessions</th>
                <th>Would be blocked</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(stats).map(([category, s]) => (
                <tr key={category}>
                  <td>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                      <span className="category-dot" style={{ background: colorForCategory(category) }} />
                      {CATEGORY_LABELS[category] ?? category}
                    </span>
                  </td>
                  <td className="mono">{s.total}</td>
                  <td className="mono">{((s.blocked / s.total) * 100).toFixed(1)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="section-note" style={{ marginTop: 12, marginBottom: 0 }}>
          There is no threshold in this real data that catches most of "Mandate chaining" without
          blocking most of "Legitimate" — the two distributions sit almost on top of each other
          near zero, the disclosed reason Layers 1–3 miss most of that class: nothing here reasons
          about a mandate's parent-child relationship at all.
        </p>
      </div>
    </>
  );
}
