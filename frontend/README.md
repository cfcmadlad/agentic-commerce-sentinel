# Sentinel frontend

Two views over the Agentic-Commerce Transaction Sentinel's detection pipeline: a live demo of the
decision path, and a static export of the full evaluation results. See the [root README](../README.md)
for the project this belongs to.

## Metrics dashboard (`/metrics`)

Renders `public/metrics.json`, a static export produced by the evaluation harness — not a live API
call. Every number on this page traces back to the same run reported in the root README, and cannot
drift from it. Regenerate after any change to the detection pipeline or a re-run of the evaluation:

```bash
cd ..
python run_milestone_b.py --n-legitimate 20000 --seed 42 --json-out frontend/public/metrics.json
```

## Live demo (`/demo`)

Walks a handful of example sessions through the same four-layer pipeline the evaluation harness
scores against: mandate verification, scope enforcement, the behavioral model with its SHAP
attribution, and a reasoning/audit panel. The first three layers are real — their response shapes in
`src/types/contract.ts` mirror the actual `BaselineDecision` / `EnsembleDecision` / attribution
dataclasses in `/detect`. The fourth is an explicit placeholder: there is no API service and no
reasoning layer yet, so this view reads from fixtures in `src/mock/sessions.ts` rather than a live
backend, and says so on screen rather than faking a narration.

## Development

```bash
npm install
npm run dev       # dev server with HMR
npm run build     # type-checks (tsc -b) then produces dist/
npm run lint      # oxlint
```

Vite + React + TypeScript, `react-router-dom` for the two views, `recharts` for the dashboard's
charts. No other frontend framework or state-management dependency — the whole app is two pages and
some fetch/fixture data, and didn't need more than that.
