/**
 * Scrolls to a section by id, for same-page `#anchor` links.
 *
 * Not the browser's native fragment-navigation behavior, not
 * `Element.scrollIntoView()`, and not the native `behavior: "smooth"`
 * option on `scrollTo()` either -- all three were tried, and all three
 * were confirmed unreliable by hand in this app's actual runtime
 * environment (native fragment navigation silently fails to move a nested
 * scroll container at all; `scrollIntoView()` likewise no-ops here for
 * reasons that never reduced to one misconfigured CSS property;
 * `scrollTo({ behavior: "smooth" })` left the scroll position untouched
 * entirely rather than animating or jumping). A hand-rolled
 * `requestAnimationFrame` easing loop over a plain `scrollTop`/`scrollTo`
 * assignment has none of that platform-specific risk and was confirmed to
 * work correctly every time it was tested.
 *
 * Below the 768px breakpoint, `.app-content` switches to `overflow-y:
 * visible` and the *document* scrolls instead (see index.css's media
 * query) -- so this checks which one is actually scrollable
 * (`scrollHeight > clientHeight`) and animates that one.
 */
import type { MouseEvent } from "react";

const SCROLL_DURATION_MS = 420;

function easeInOutQuad(t: number): number {
  return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
}

function animateScroll(getPosition: () => number, setPosition: (value: number) => void, target: number): void {
  const start = getPosition();
  const distance = target - start;
  if (Math.abs(distance) < 1) return;
  const startTime = performance.now();

  function step(now: number): void {
    const elapsed = now - startTime;
    const t = Math.min(1, elapsed / SCROLL_DURATION_MS);
    setPosition(start + distance * easeInOutQuad(t));
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

export function scrollToSection(id: string, e: MouseEvent): void {
  e.preventDefault();
  const container = document.querySelector<HTMLElement>(".app-content");
  const target = document.getElementById(id);
  if (target) {
    const containerScrolls = !!container && container.scrollHeight > container.clientHeight;
    if (containerScrolls && container) {
      const top = target.offsetTop - container.offsetTop;
      animateScroll(
        () => container.scrollTop,
        (v) => {
          container.scrollTop = v;
        },
        top,
      );
    } else {
      const top = target.getBoundingClientRect().top + window.scrollY;
      animateScroll(
        () => window.scrollY,
        (v) => window.scrollTo(0, v),
        top,
      );
    }
  }
  history.replaceState(null, "", `#${id}`);
}
