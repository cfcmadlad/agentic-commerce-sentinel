/**
 * Isoline (contour) extraction over a scalar field.
 *
 * Deliberately triangle-based rather than classic 4-corner marching
 * squares: splitting each grid cell into two triangles means a contour
 * crossing is always unambiguous (a triangle has exactly 3 edges and a
 * threshold can only separate 1 or 2 of its corners from the rest, so
 * there is never a saddle case to resolve arbitrarily, unlike the
 * 4-corner case). This is the same idea real contouring implementations
 * (e.g. CONREC) use for the same reason -- correctness over the classic
 * algorithm's edge cases, not a shortcut.
 */

export type Segment = readonly [readonly [number, number], readonly [number, number]];

/**
 * Finds where a threshold crosses one triangle, if it does.
 *
 * @param v0 - First vertex's scalar value.
 * @param p0 - First vertex's grid-space position.
 * @param v1 - Second vertex's scalar value.
 * @param p1 - Second vertex's grid-space position.
 * @param v2 - Third vertex's scalar value.
 * @param p2 - Third vertex's grid-space position.
 * @param threshold - The isovalue to extract.
 * @returns The crossing segment, or null if the threshold doesn't split this triangle.
 */
function triangleCrossing(
  v0: number,
  p0: readonly [number, number],
  v1: number,
  p1: readonly [number, number],
  v2: number,
  p2: readonly [number, number],
  threshold: number,
): Segment | null {
  const edges: [number, readonly [number, number], number, readonly [number, number]][] = [
    [v0, p0, v1, p1],
    [v1, p1, v2, p2],
    [v2, p2, v0, p0],
  ];
  const crossings: [number, number][] = [];
  for (const [va, pa, vb, pb] of edges) {
    if (va > threshold !== vb > threshold) {
      const t = (threshold - va) / (vb - va);
      crossings.push([pa[0] + (pb[0] - pa[0]) * t, pa[1] + (pb[1] - pa[1]) * t]);
    }
  }
  return crossings.length === 2 ? [crossings[0], crossings[1]] : null;
}

/**
 * Extracts every contour segment at one threshold, in grid coordinates.
 *
 * @param field - Row-major gridSize*gridSize scalar field.
 * @param gridSize - Grid resolution per axis.
 * @param threshold - The isovalue to extract.
 * @returns Line segments in grid-cell coordinates (0..gridSize-1 per axis);
 *   the caller maps these to pixel space.
 */
export function contourSegments(field: Float32Array, gridSize: number, threshold: number): Segment[] {
  const segments: Segment[] = [];
  for (let y = 0; y < gridSize - 1; y++) {
    for (let x = 0; x < gridSize - 1; x++) {
      const tl = field[y * gridSize + x];
      const tr = field[y * gridSize + x + 1];
      const bl = field[(y + 1) * gridSize + x];
      const br = field[(y + 1) * gridSize + x + 1];
      const ptl: [number, number] = [x, y];
      const ptr: [number, number] = [x + 1, y];
      const pbl: [number, number] = [x, y + 1];
      const pbr: [number, number] = [x + 1, y + 1];

      const a = triangleCrossing(tl, ptl, tr, ptr, bl, pbl, threshold);
      if (a) segments.push(a);
      const b = triangleCrossing(tr, ptr, br, pbr, bl, pbl, threshold);
      if (b) segments.push(b);
    }
  }
  return segments;
}
