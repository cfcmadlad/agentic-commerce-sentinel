/**
 * Kernel density estimation over real per-session scores.
 *
 * This is a real, if simple, machine-learning technique -- a Gaussian
 * kernel-weighted local average of the actual ensemble score exported by
 * `run_collision_export.py`, not a decorative gradient. Every grid cell's
 * value is a weighted mean of real sessions' real scores; the "terrain" the
 * frontend renders is this field, and the contour lines drawn over it (see
 * `contour.ts`) are isolines of this exact array, not an artist's
 * impression of one.
 */

export interface FieldPoint {
  x: number;
  y: number;
  score: number;
}

export interface Domain {
  min: number;
  max: number;
}

/**
 * Computes a percentile-based domain for an axis, so a handful of extreme
 * outliers don't compress the entire visible field into a corner.
 *
 * @param values - Real values to derive the domain from.
 * @param lowerPct - Lower percentile (0-1).
 * @param upperPct - Upper percentile (0-1).
 * @returns The [min, max] domain to render.
 */
export function percentileDomain(values: number[], lowerPct = 0.02, upperPct = 0.98): Domain {
  const sorted = [...values].sort((a, b) => a - b);
  const lo = sorted[Math.floor(lowerPct * (sorted.length - 1))];
  const hi = sorted[Math.floor(upperPct * (sorted.length - 1))];
  return { min: lo, max: hi === lo ? lo + 1 : hi };
}

/**
 * Computes a gridSize x gridSize risk field via Gaussian-kernel-weighted
 * averaging of real point scores -- a direct, standard KDE regression
 * (Nadaraya-Watson form), evaluated once over the full data.
 *
 * @param points - Real (feature_x, feature_y, score) triples.
 * @param gridSize - Grid resolution per axis.
 * @param xDomain - Value range mapped to grid columns.
 * @param yDomain - Value range mapped to grid rows.
 * @param bandwidthX - Gaussian kernel bandwidth in x's own units.
 * @param bandwidthY - Gaussian kernel bandwidth in y's own units.
 * @returns A flat Float32Array of length gridSize*gridSize, row-major, plus
 *   a parallel confidence array (total kernel weight per cell, so sparse
 *   regions can be rendered as unexplored rather than falsely confident).
 */
export function computeRiskField(
  points: FieldPoint[],
  gridSize: number,
  xDomain: Domain,
  yDomain: Domain,
  bandwidthX: number,
  bandwidthY: number,
): { field: Float32Array; weight: Float32Array } {
  const field = new Float32Array(gridSize * gridSize);
  const weight = new Float32Array(gridSize * gridSize);
  const xSpan = xDomain.max - xDomain.min;
  const ySpan = yDomain.max - yDomain.min;

  for (let gy = 0; gy < gridSize; gy++) {
    const cy = yDomain.min + ((gy + 0.5) / gridSize) * ySpan;
    for (let gx = 0; gx < gridSize; gx++) {
      const cx = xDomain.min + ((gx + 0.5) / gridSize) * xSpan;
      let wSum = 0;
      let valSum = 0;
      for (const p of points) {
        const dx = (p.x - cx) / bandwidthX;
        const dy = (p.y - cy) / bandwidthY;
        const d2 = dx * dx + dy * dy;
        if (d2 > 16) continue; // ~4 bandwidths out, negligible Gaussian weight
        const w = Math.exp(-d2 / 2);
        wSum += w;
        valSum += w * p.score;
      }
      const idx = gy * gridSize + gx;
      field[idx] = wSum > 1e-6 ? valSum / wSum : 0;
      weight[idx] = wSum;
    }
  }
  return { field, weight };
}
