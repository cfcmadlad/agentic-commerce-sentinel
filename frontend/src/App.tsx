import { NavLink, Route, Routes, useLocation } from "react-router-dom";
import { BrandMark } from "./components/icons";
import Collide from "./pages/Collide";
import Landing from "./pages/Landing";
import LiveDemo from "./pages/LiveDemo";
import MetricsDashboard from "./pages/MetricsDashboard";
import Sandbox from "./pages/Sandbox";
import Terrain from "./pages/Terrain";

export default function App() {
  const location = useLocation();
  const isLanding = location.pathname === "/";

  return (
    <div className="app-shell">
      <nav className="app-nav">
        <div className="app-nav__inner">
          <NavLink to="/" className="nav-brand">
            <BrandMark className="nav-brand__mark" />
            Sentinel
          </NavLink>
          <div className="app-nav__links">
            <NavLink to="/demo" className={({ isActive }) => (isActive ? "active" : "")}>
              Live demo
            </NavLink>
            <NavLink to="/sandbox" className={({ isActive }) => (isActive ? "active" : "")}>
              Sandbox
            </NavLink>
            <NavLink to="/collide" className={({ isActive }) => (isActive ? "active" : "")}>
              Collide
            </NavLink>
            <NavLink to="/terrain" className={({ isActive }) => (isActive ? "active" : "")}>
              Terrain
            </NavLink>
            <NavLink to="/metrics" className={({ isActive }) => (isActive ? "active" : "")}>
              Evaluation
            </NavLink>
          </div>
          <div className="app-nav__cta">
            <NavLink to="/sandbox" className="btn btn--filled btn--sm">
              Try to break it
            </NavLink>
          </div>
        </div>
      </nav>
      <main className={isLanding ? "app-main" : "app-main app-main--app"}>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/demo" element={<LiveDemo />} />
          <Route path="/sandbox" element={<Sandbox />} />
          <Route path="/collide" element={<Collide />} />
          <Route path="/terrain" element={<Terrain />} />
          <Route path="/metrics" element={<MetricsDashboard />} />
        </Routes>
      </main>
    </div>
  );
}
