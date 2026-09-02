import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  AboutIcon,
  BrandMark,
  DecisionsIcon,
  DelegationIcon,
  EvaluationIcon,
  ExplorerIcon,
  OperationsIcon,
  OrganizationsIcon,
  OverviewIcon,
  SandboxIcon,
} from "./icons";
import { scrollToSection } from "../lib/scroll";

/**
 * Persistent app chrome: a left sidebar (brand, section jump-links, a
 * de-emphasized About link, a footer disclaimer) plus the single-page
 * content it wraps. This is a one-page app now -- no routing -- so the
 * sidebar links are same-page anchors, and "active" highlighting is a
 * scroll-spy (`IntersectionObserver` watching which `<section>` is nearest
 * the top of the scrolling content area) rather than a matched route.
 *
 * Layout: `.app-shell` is pinned to exactly the viewport height; the
 * sidebar and `.app-content` each own their own independent scroll
 * (`overflow-y: auto`) rather than the whole page scrolling with a sticky
 * sidebar. Deliberate -- `position: sticky` inside this flex shell hit a
 * real Chromium paint bug (layout position correct per
 * `getBoundingClientRect`, but stale pixels after a fast scroll), so the
 * sidebar is a plain, always-full-height flex child instead; this
 * "fixed-height shell, independently scrolling panes" pattern is also just
 * the standard app-shell layout (Gmail, Slack, most SaaS dashboards) and
 * has no scroll-linked positioning to get wrong. Collapses to a horizontal,
 * naturally-flowing top strip below 768px (see index.css's media query).
 *
 * Nav clicks scroll explicitly via `scrollIntoView` rather than relying on
 * the browser's native `#anchor` jump -- confirmed by hand that native
 * fragment navigation does not reliably scroll a nested `overflow:auto`
 * container (it updates `location.hash` but the visual scroll position can
 * silently fail to follow), only the document itself. `scrollIntoView`
 * finds the real scrolling ancestor regardless, so it works with this
 * shell's independently-scrolling `.app-content`.
 */

const SECTIONS = [
  { id: "overview", label: "Overview", icon: OverviewIcon },
  { id: "organizations", label: "Organizations", icon: OrganizationsIcon },
  { id: "decisions", label: "Decisions", icon: DecisionsIcon },
  { id: "sandbox", label: "Sandbox", icon: SandboxIcon },
  { id: "delegation", label: "Delegation", icon: DelegationIcon },
  { id: "operations", label: "Operations", icon: OperationsIcon },
  { id: "explorer", label: "Explorer", icon: ExplorerIcon },
  { id: "evaluation", label: "Evaluation", icon: EvaluationIcon },
];

const ALL_SECTION_IDS = [...SECTIONS.map((s) => s.id), "about"];

function useScrollSpy(sectionIds: string[], root: HTMLElement | null): string {
  const [activeId, setActiveId] = useState(sectionIds[0]);

  useEffect(() => {
    if (!root) return;
    const elements = sectionIds
      .map((id) => document.getElementById(id))
      .filter((el): el is HTMLElement => el !== null);

    // Tracks every section's own current intersection state, rather than
    // trusting one callback batch's array order for "which is active".
    // IntersectionObserver does not guarantee entries arrive in document
    // order -- on the very first observe() call for several elements at
    // once (page load, or a fast scroll), more than one section can be
    // simultaneously intersecting, and taking entries[0] picked whichever
    // one the browser happened to report first, not necessarily the
    // topmost. Recomputing "the topmost currently-intersecting section, in
    // sectionIds order" on every callback is correct regardless of
    // delivery order.
    const isIntersecting = new Map<string, boolean>(sectionIds.map((id) => [id, false]));
    let observer: IntersectionObserver | null = null;

    // Below the mobile breakpoint, `.app-content` switches to
    // `overflow-y: visible` (the window scrolls instead -- see index.css's
    // 768px media query); it stops being a real scroll container. Using it
    // as the IntersectionObserver root regardless made rootMargin's
    // percentages relative to its full, unclipped scrollHeight (thousands
    // of pixels) instead of the real visible viewport, silently breaking
    // every boundary calculation -- reproduced concretely: Organizations
    // stayed highlighted while Overview's own content filled the screen.
    // Falling back to the true viewport (root: null) whenever `root` isn't
    // currently clipping its own overflow fixes this at whatever
    // breakpoint the CSS uses, not just today's 768px value. Reconnects on
    // resize since crossing that breakpoint changes the CSS but not this
    // effect's own dependencies.
    const connect = (): void => {
      observer?.disconnect();
      const clipsOverflow = getComputedStyle(root).overflowY !== "visible";
      observer = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            isIntersecting.set(entry.target.id, entry.isIntersecting);
          }
          const topmost = sectionIds.find((id) => isIntersecting.get(id));
          if (topmost !== undefined) {
            setActiveId(topmost);
          }
        },
        { root: clipsOverflow ? root : null, rootMargin: "-10% 0px -75% 0px", threshold: 0 },
      );
      elements.forEach((el) => observer!.observe(el));
    };

    connect();
    window.addEventListener("resize", connect);
    return () => {
      window.removeEventListener("resize", connect);
      observer?.disconnect();
    };
  }, [sectionIds, root]);

  return activeId;
}

export default function AppShell({ children }: { children: ReactNode }) {
  const contentRef = useRef<HTMLDivElement | null>(null);
  const [contentEl, setContentEl] = useState<HTMLDivElement | null>(null);
  const activeId = useScrollSpy(ALL_SECTION_IDS, contentEl);

  useEffect(() => {
    setContentEl(contentRef.current);
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a href="#overview" className="sidebar__brand" onClick={(e) => scrollToSection("overview", e)}>
          <BrandMark />
          Sentinel
        </a>
        <nav className="sidebar__nav">
          {SECTIONS.map((section) => (
            <a
              key={section.id}
              href={`#${section.id}`}
              onClick={(e) => scrollToSection(section.id, e)}
              className={`sidebar__link${activeId === section.id ? " active" : ""}`}
            >
              <section.icon />
              {section.label}
            </a>
          ))}
          <div className="sidebar__divider" />
          <a
            href="#about"
            onClick={(e) => scrollToSection("about", e)}
            className={`sidebar__link sidebar__link--secondary${activeId === "about" ? " active" : ""}`}
          >
            <AboutIcon />
            About
          </a>
        </nav>
        <div className="sidebar__footer">
          All data shown is synthetic. This is a detector and verifier, not an autonomous enforcement
          system — every automated finding is designed to escalate to a human reviewer.
        </div>
      </aside>
      <div className="app-main">
        <div className="app-topbar">
          <span className="app-topbar__badge">Synthetic data · demo</span>
          <a
            href="https://github.com/cfcmadlad/agentic-commerce-sentinel"
            target="_blank"
            rel="noreferrer"
            className="app-topbar__repo-link"
          >
            View source ↗
          </a>
        </div>
        <div className="app-content" ref={contentRef}>
          {children}
        </div>
      </div>
    </div>
  );
}
