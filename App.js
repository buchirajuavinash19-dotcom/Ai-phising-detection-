import React, { useState, useCallback } from 'react';
import Dashboard from './pages/Dashboard';
import Scanner   from './pages/Scanner';
import History   from './pages/History';
import Tips      from './pages/Tips';
import About     from './pages/About';
import './App.css';

export default function App() {
  const [page, setPage]   = useState('scanner');
  const [navKey, setNavKey] = useState(0);

  // Force re-mount page every time we navigate — fixes History not updating
  const goTo = useCallback((p) => {
    setPage(p);
    setNavKey(k => k + 1);
  }, []);

  const nav = [
    { id:'dashboard', icon:'📊', label:'Dashboard' },
    { id:'scanner',   icon:'🔍', label:'Scanner'   },
    { id:'history',   icon:'📋', label:'History'   },
    { id:'tips',      icon:'💡', label:'Safety Tips'},
    { id:'about',     icon:'ℹ️',  label:'About'     },
  ];

  const Page = { dashboard:Dashboard, scanner:Scanner, history:History, tips:Tips, about:About }[page];

  return (
    <div className="app">
      {/* Sidebar */}
      <nav className="sidebar">
        <div className="sidebar-logo">
          <span style={{fontSize:26}}>🛡️</span>
          <span className="logo-text">PhishGuard AI</span>
        </div>
        <div className="nav-section-label">Menu</div>
        <ul className="nav-links">
          {nav.map(({id,icon,label}) => (
            <li key={id} className={`nav-item ${page===id?'active':''}`} onClick={() => goTo(id)}>
              <span className="nav-icon">{icon}</span>
              <span>{label}</span>
            </li>
          ))}
        </ul>
        <div className="sidebar-footer">
          <div style={{fontSize:12,color:'var(--text-muted)'}}>
            <span className="status-dot"/>AI Engine Active
          </div>
          <div style={{fontSize:11,color:'var(--text-muted)',marginTop:4}}>v2.0 • No backend needed</div>
        </div>
      </nav>

      {/* Main — key forces full remount on navigate, fixing stale history */}
      <main className="main-content">
        <Page key={`${page}-${navKey}`} />
      </main>
    </div>
  );
}
