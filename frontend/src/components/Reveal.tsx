import { useEffect, useRef, useState, type ReactNode } from "react";

/**
 * Fades and lifts its children into place the first time they scroll into
 * view, then leaves them alone -- a one-shot reveal, not a scroll-driven
 * animation. `.reveal`'s own reduced-motion override in index.css makes
 * this a no-op (always visible, no transition) for anyone who has asked
 * for less motion, so no JS branching is needed here for that case.
 */
export default function Reveal({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const node = ref.current;
    if (!node || typeof IntersectionObserver === "undefined") {
      setVisible(true);
      return;
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.15 },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  return (
    <div ref={ref} className={`reveal ${visible ? "is-visible" : ""}`}>
      {children}
    </div>
  );
}
