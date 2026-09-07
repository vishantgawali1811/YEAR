import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar.jsx';
import TopNav from './components/TopNav.jsx';
import LiveTicker from './components/LiveTicker.jsx';
import MatrixRain from './components/MatrixRain.jsx';
import Dashboard from './pages/Dashboard.jsx';
import CVEDetail from './pages/CVEDetail.jsx';
import Terminal from './pages/Terminal.jsx';
import Analysis from './pages/Analysis.jsx';
import { getStats } from './api/cveApi.js';

export default function App() {
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });
  const [tickerItems, setTickerItems] = useState([]);

  useEffect(() => {
    getStats()
      .then(s => {
        setStats(s);
        setTickerItems([
          `DATASET LOADED :: ${s.total?.toLocaleString()} CVEs indexed`,
          `CRITICAL: ${s.critical} | HIGH: ${s.high} | MEDIUM: ${s.medium} | LOW: ${s.low}`,
          `TOP PRODUCT: ${s.top_product || 'pan-os'} :: ${s.top_product_count || ''} records`,
          'RAG PIPELINE :: ONLINE :: Flan-T5-Base ready',
          'NLP PARSER :: Regex+Keyword :: READY',
        ]);
      })
      .catch(() => {}); // backend may not be running yet
  }, []);

  const threatLevel = stats.critical > 20 ? 'CRITICAL' : stats.critical > 5 ? 'HIGH' : 'MEDIUM';

  return (
    <BrowserRouter>
      <MatrixRain />
      <div className="app-shell">
        <Sidebar />
        <div className="main-area">
          <TopNav threatLevel={threatLevel} totalCves={stats.total} />
          <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
            <div className="page-content" style={{ flex: 1, overflowY: 'auto' }}>
              <Routes>
                <Route path="/" element={<Dashboard stats={stats} />} />
                <Route path="/cve/:cveId" element={<CVEDetail />} />
                <Route path="/terminal" element={<Terminal />} />
                <Route path="/analysis" element={<Analysis stats={stats} />} />
              </Routes>
            </div>
            <LiveTicker items={tickerItems} />
          </div>
        </div>
      </div>
    </BrowserRouter>
  );
}
