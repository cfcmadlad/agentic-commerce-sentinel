import { NavLink, Route, Routes, Navigate } from "react-router-dom";
import LiveDemo from "./pages/LiveDemo";
import MetricsDashboard from "./pages/MetricsDashboard";

export default function App() {
  return (
    <div className="app-shell">
      <nav className="app-nav">
        <span className="app-nav__title">Agentic-Commerce Transaction Sentinel</span>
        <div className="app-nav__links">
          <NavLink to="/demo" className={({ isActive }) => (isActive ? "active" : "")}>
            Live Demo
          </NavLink>
          <NavLink to="/metrics" className={({ isActive }) => (isActive ? "active" : "")}>
            Metrics Dashboard
          </NavLink>
        </div>
      </nav>
      <main className="app-main">
        <Routes>
          <Route path="/" element={<Navigate to="/demo" replace />} />
          <Route path="/demo" element={<LiveDemo />} />
          <Route path="/metrics" element={<MetricsDashboard />} />
        </Routes>
      </main>
    </div>
  );
}
