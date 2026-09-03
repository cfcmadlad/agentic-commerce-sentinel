# Sentinel frontend

A single-page internal dashboard over the Agentic-Commerce Transaction Sentinel's detection
pipeline — sidebar nav, data-dense panels, status badges, everything on one continuously-scrolling
page rather than spread across separate routes. See the [root README](../README.md) for the
project this belongs to — this file only covers the frontend itself.

The sidebar's six links (plus a de-emphasized About) are same-page jump links to `<section>`s on
that one page (`src/pages/Dashboard.tsx`), not routes — there is no router in this app. Clicking
one animates the scroll position to that section and highlights it; scrolling manually keeps the
sidebar's highlight in sync via an `IntersectionObserver`-based scroll-spy
(`src/components/AppShell.tsx`).

## Overview

Opens directly on live data — stat tiles read from `public/metrics.json`, a compact
draggable-threshold score-distribution widget, and a "where to look next" list of jump links. No
narrative or marketing copy first.

## Organizations

A company → organization → agent → session → transaction drill-down
(`src/components/OrgDrilldown.tsx`), built entirely on real per-session data
(`public/collision.json`). The organization layer itself is an illustrative grouping this
dashboard invents for navigation and says so on the page — the backend has no multi-tenant concept
anywhere in its schema — but every agent ID, session, score, and rate shown within it is real,
grouped by the real `agent_id` each session already carries (`src/lib/orgs.ts` does the grouping;
`run_collision_export.py` exports the real field).

## Decisions

Walks five real scenarios through the same four-layer pipeline the evaluation harness scores
against: mandate verification, scope enforcement, the behavioral model with its SHAP attribution,
and the reasoning/audit narration. When `VITE_API_BASE_URL` is set, this section POSTs real,
pre-signed request bodies (`public/live_demo_requests.json`, exported by
`../run_live_demo_export.py`) to a running instance of `/service` and renders the genuine response.
Without that env var — the case for the hosted static build — it falls back to the fixtures in
`src/mock/sessions.ts`, which mirror the same real `BaselineDecision` / `EnsembleDecision` /
attribution / narration response shapes.

## Sandbox

A from-scratch client-side port of Layer 2's six scope rules (`src/sandbox/scopeEngine.ts`), faithful
to `../detect/scope.py`'s exact comparisons. Build a mandate, build a transaction, get a live verdict
on every drag — no backend involved, since the rules themselves are the thing being demonstrated.

## Explorer

Every point in `public/collision.json` (real per-session scores from `../run_collision_export.py`,
never retrained), as either a log-scale scatter or a pannable, zoomable kernel-density risk terrain
with real contour lines (`src/terrain/field.ts`, `src/terrain/contour.ts`), switched with a segmented
control. Both share one lifted threshold control (`src/lib/collide.ts`, `src/components/explorer/`)
so dragging in one view and switching tabs keeps the same operating point.

## Evaluation

Renders `public/metrics.json`, a static export produced by the evaluation harness — not a live API
call. Every number on this section traces back to the same run reported in the root README, and cannot
drift from it. Regenerate after any change to the detection pipeline or a re-run of the evaluation:

```bash
cd ..
python run_full_eval.py --n-legitimate 20000 --seed 42 --json-out frontend/public/metrics.json
python run_collision_export.py --json-out frontend/public/collision.json
```

## About

Reference documentation, de-emphasized in the sidebar: why the project exists, the four-layer
architecture, and a further-reading list of the real methods this project builds on. Secondary by
design — Overview is the front door.

## Development

```bash
npm install
npm run dev       # dev server with HMR
npm run build     # type-checks (tsc -b) then produces dist/
npm run lint      # oxlint
```

To exercise the Decisions section against a real running service instead of its fixture fallback,
set `VITE_API_BASE_URL=http://localhost:8000` in a gitignored `.env.local` before `npm run dev`,
and run `uvicorn service.main:app --reload` from the repo root (see the root README's Getting Started section).

Vite + React + TypeScript, `recharts` for the Evaluation section's charts. No router and no
state-management dependency — the whole app is one page with local component state.
