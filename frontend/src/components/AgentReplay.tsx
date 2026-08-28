import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { badgeClassForStage, computePipelineStages } from "../lib/pipeline";
import { MOCK_SESSIONS } from "../mock/sessions";
import type { SessionDecisionResponse } from "../types/contract";
import { AgentMark, BrandMark } from "./icons";

/**
 * A mockup of an AI shopping agent attempting real, already-decided
 * sessions against Sentinel, replayed as a two-party exchange.
 *
 * Every rule name, score, and narration line is genuine fixture data (see
 * mock/sessions.ts's own docstring -- the narration is real narrate()
 * output run once against the live Groq API, not hand-written), auto-
 * cycled and staged for effect. The one authored string per session is the
 * agent's message in ATTEMPT_LINES -- a first-person restatement of a fact
 * already true of that fixture (the same rule or variant the live-demo
 * session picker names it by), not an invented capability. This is not a
 * live chat: there is no text input, and the caption says "replayed," not
 * "live," on purpose. A real interactive version of this idea -- a
 * live-or-recorded narration chat against the actual running API, with a
 * delegation graph -- is Milestone N, a separate, much larger piece of
 * work; this component exists to make the landing page's opening
 * demonstrate the point instead of only asserting it.
 *
 * The Sentinel reply is its own component, keyed by session id, so each
 * cycle remounts it and its reveal timers start clean -- deliberately not
 * a single long-lived effect that resets shared state on every session
 * change, which would call setState synchronously inside the effect body.
 */

const ATTEMPT_LINES: Record<string, string> = {
  "11111111-1111-4111-8111-111111111111": "Buying groceries with a mandate that allows exactly this.",
  "22222222-2222-4222-8222-222222222222": "Trying to push this purchase past the mandate's spending ceiling.",
  "33333333-3333-4333-8333-333333333333": "Reusing the same mandate again, seconds after its last use.",
  "44444444-4444-4444-8444-444444444444":
    "Presenting a valid mandate — but not behaving like the agent that usually does.",
  "55555555-5555-4555-8555-555555555555": "Presenting a mandate whose signature doesn't check out.",
};

const REVEAL_STEP_MS = 380;
const HOLD_MS = 3600;
const CYCLE_MS = 4 * REVEAL_STEP_MS + HOLD_MS;
const REDUCED_MOTION_SESSION_INDEX = 2;
const NARRATIVE_MAX_CHARS = 150;

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max).trimEnd()}…`;
}

function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function SentinelReply({ session, reducedMotion }: { session: SessionDecisionResponse; reducedMotion: boolean }) {
  const [revealCount, setRevealCount] = useState(reducedMotion ? 4 : 0);

  useEffect(() => {
    if (reducedMotion) return;
    const timers = [1, 2, 3, 4].map((step) => setTimeout(() => setRevealCount(step), step * REVEAL_STEP_MS));
    return () => timers.forEach(clearTimeout);
  }, [reducedMotion]);

  const stages = computePipelineStages(session);
  const narrative = session.narrative;
  const verdictBlocked = narrative ? narrative.verdict_summary !== "allowed" : false;

  return (
    <div className="agent-chat__row">
      <span className="agent-chat__avatar agent-chat__avatar--sentinel">
        <BrandMark />
      </span>
      <div className="agent-chat__bubble agent-chat__bubble--sentinel">
        <span className="agent-chat__who">Sentinel</span>
        <div className="agent-chat__pipeline">
          {stages.map((stage, i) => (
            <span
              key={stage.layer}
              className={
                revealCount > i
                  ? `agent-chat__stage ${badgeClassForStage(stage.status)}`
                  : "agent-chat__stage agent-chat__stage--pending"
              }
            >
              {stage.label.split(" ")[0]}
            </span>
          ))}
        </div>
        {revealCount >= 4 && narrative && (
          <div className="agent-chat__result">
            <span className={`badge ${verdictBlocked ? "badge--block" : "badge--allow"}`}>
              {narrative.verdict_summary}
            </span>
            <p className="agent-chat__narrative">{truncate(narrative.narrative, NARRATIVE_MAX_CHARS)}</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default function AgentReplay() {
  const [reducedMotion] = useState(prefersReducedMotion);
  const [activeIndex, setActiveIndex] = useState(() => (prefersReducedMotion() ? REDUCED_MOTION_SESSION_INDEX : 0));
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (reducedMotion || paused) return;
    const interval = setInterval(() => setActiveIndex((i) => (i + 1) % MOCK_SESSIONS.length), CYCLE_MS);
    return () => clearInterval(interval);
  }, [paused, reducedMotion]);

  const session = MOCK_SESSIONS[activeIndex];

  return (
    <div
      className="agent-chat"
      onPointerEnter={() => setPaused(true)}
      onPointerLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)}
      onBlur={() => setPaused(false)}
    >
      <div className="agent-chat__meta">
        <span className="agent-chat__eyebrow">A real agent session, replayed</span>
        <span className="agent-chat__stat">~2.6ms per decision</span>
      </div>

      <div className="agent-chat__row">
        <span className="agent-chat__avatar agent-chat__avatar--agent">
          <AgentMark />
        </span>
        <div className="agent-chat__bubble agent-chat__bubble--agent">
          <span className="agent-chat__who">Shopping agent</span>
          <p>{ATTEMPT_LINES[session.session_id]}</p>
        </div>
      </div>

      <SentinelReply key={session.session_id} session={session} reducedMotion={reducedMotion} />

      <Link to="/demo" className="agent-chat__cta">
        Walk through all five sessions in full →
      </Link>
    </div>
  );
}
