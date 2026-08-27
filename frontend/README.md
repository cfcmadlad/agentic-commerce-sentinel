# Sentinel frontend

Six views over the Agentic-Commerce Transaction Sentinel's detection pipeline. See the
[root README](../README.md) for the project this belongs to — this file only covers the frontend
itself.

## Landing (`/`)

The public entry point: why the project exists, the four-layer architecture, a live draggable-
threshold widget reading the real held-out-class data, a guide to the other five pages, and a
further-reading list of the real methods this project builds on.

## Live demo (`/demo`)

Walks five real scenarios through the same four-layer pipeline the evaluation harness scores
against: mandate verification, scope enforcement, the behavioral model with its SHAP attribution,
and the reasoning/audit narration. When `VITE_API_BASE_URL` is set, this view POSTs real, pre-signed
request bodies (`public/live_demo_requests.json`, exported by `../run_live_demo_export.py`) to a
running instance of `/service` and renders the genuine response. Without that env var — the case for
the hosted static build — it falls back to the fixtures in `src/mock/sessions.ts`, which mirror the
same real `BaselineDecision` / `EnsembleDecision` / attribution / narration response shapes.

## Sandbox (`/sandbox`)

A from-scratch client-side port of Layer 2's six scope rules (`src/sandbox/scopeEngine.ts`), faithful
to `../detect/scope.py`'s exact comparisons. Build a mandate, build a transaction, get a live verdict
on every drag — no backend involved, since the rules themselves are the thing being demonstrated.

## Collide (`/collide`) and the landing page's mini-chart

Renders every point in `public/collision.json` (real per-session scores from
`../run_collision_export.py`, never retrained) on a draggable-threshold, log-scale scatter. The
landing page embeds a compact version of the same chart (`src/components/MiniCollide.tsx`), sharing
its scoring math with the full page via `src/lib/collide.ts` so the two never drift apart.

## Terrain (`/terrain`)

The same real per-session data as Collide, rendered as a pannable, zoomable kernel-density risk map
with real contour lines (`src/terrain/field.ts`, `src/terrain/contour.ts`).

## Evaluation (`/metrics`)

Renders `public/metrics.json`, a static export produced by the evaluation harness — not a live API
call. Every number on this page traces back to the same run reported in the root README, and cannot
drift from it. Regenerate after any change to the detection pipeline or a re-run of the evaluation:

```bash
cd ..
python run_milestone_b.py --n-legitimate 20000 --seed 42 --json-out frontend/public/metrics.json
python run_collision_export.py --json-out frontend/public/collision.json
```

## Development

```bash
npm install
npm run dev       # dev server with HMR
npm run build     # type-checks (tsc -b) then produces dist/
npm run lint      # oxlint
```

To exercise the live demo view against a real running service instead of its fixture fallback, set
`VITE_API_BASE_URL=http://localhost:8000` in a gitignored `.env.local` before `npm run dev`, and run
`uvicorn service.main:app --reload` from the repo root (see the root README's §13).

Vite + React + TypeScript, `react-router-dom` across all six views, `recharts` for the dashboard's
charts. No other frontend framework or state-management dependency.
