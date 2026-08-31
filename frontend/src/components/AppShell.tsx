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

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting);
        if (visible.length > 0) {
          setActiveId(visible[0].target.id);
        }
      },
      { root, rootMargin: "-10% 0px -75% 0px", threshold: 0 },
    );
    elements.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
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
        </div>
        <div className="app-content" ref={contentRef}>
          {children}
        </div>
      </div>
    </div>
  );
}
