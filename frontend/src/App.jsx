import { useState, useMemo, useEffect } from 'react'
import { Activity, ShieldAlert } from 'lucide-react'
import { ResponsiveContainer, BarChart, CartesianGrid, XAxis, YAxis, Tooltip, Bar } from 'recharts'

// Hooks
import { useAuth } from './hooks/useAuth'
import { useSecurityDashboard } from './hooks/useSecurityDashboard'

// Core UI Components
import Toast from './components/Toast'
import IncidentModal from './components/IncidentModal'
import Login from './components/Login'
import ChangePasswordModal from './components/ChangePasswordModal'
import ReportGenerator from './components/ReportGenerator'

// Layout Components (Extracted inline for atomic design but kept in file for simplicity as per refactor plan)
import DashboardHeader from './components/Layout/DashboardHeader'
import KPIGrid from './components/Layout/KPIGrid'
import ThreatTable from './components/Layout/ThreatTable'

// Visualizers
import GeoThreatMap from './components/Visualizers/GeoThreatMap'
import TopologyGraph from './components/Visualizers/TopologyGraph'

// Charts
import AttackTypeChart from './components/Charts/AttackTypeChart'
import FeatureImportanceChart from './components/Charts/FeatureImportanceChart'
import TrafficTrendChart from './components/Charts/TrafficTrendChart'

import './index.css'

/**
 * Main Application Controller
 * Orchestrates the Dashboard Layout and Global State
 */
function App() {
  // --- Infrastructure State ---
  const { isAuthenticated, userRole, username, login, logout, toggleRole } = useAuth()

  // --- UI State ---
  const [selectedDate, setSelectedDate] = useState(() => new Date().toISOString().split('T')[0])

  // --- Domain State (Telemetry) ---
  const {
    threats, totalThreats, riskStats, metrics, features, attackTypes,
    criticalAlerts, highRiskCount, alert, wsStatus, setAlert, actions, trendData
  } = useSecurityDashboard(isAuthenticated, selectedDate)

  // --- UI State ---
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark')
  const [selectedIncident, setSelectedIncident] = useState(null)
  const [isPasswordModalOpen, setPasswordModalOpen] = useState(false)

  // Drill-down Filters
  const [filterCategory, setFilterCategory] = useState('All')
  const [filterSeverity, setFilterSeverity] = useState('All')

  // Theme Management Side Effect
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  const toggleTheme = () => setTheme(curr => (curr === 'dark' ? 'light' : 'dark'))

  // --- Data Processing Layer ---
  const activeViewData = useMemo(() => {
    return threats.filter(t => {
      // Category Filter
      if (filterCategory !== 'All' && t.predicted_label !== filterCategory) return false

      // Severity Filter
      if (filterSeverity !== 'All') {
        const score = t.risk_score
        if (filterSeverity === 'Critical' && score < 80) return false
        if (filterSeverity === 'High' && (score < 60 || score >= 80)) return false
        if (filterSeverity === 'Medium' && (score < 30 || score >= 60)) return false
        if (filterSeverity === 'Low' && score >= 30) return false
      }
      return true
    })
  }, [threats, filterCategory, filterSeverity])

  // --- Routing Guard ---
  if (!isAuthenticated) {
    return <Login onLogin={login} />
  }

  return (
    <div className="app-container">
      {/* 1. Header Navigation */}
      <DashboardHeader
        theme={theme}
        userRole={userRole}
        criticalAlerts={criticalAlerts}
        wsStatus={wsStatus}
        actions={{
          toggleTheme,
          toggleRole,
          logout,
          openPasswordModal: () => setPasswordModalOpen(true),
          resolveThreat: actions.resolveThreat,
          dbStatus: actions.dbStatus
        }}
      >
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <input
            type="date"
            value={selectedDate}
            onChange={(e) => setSelectedDate(e.target.value)}
            style={{
              padding: '8px',
              borderRadius: '6px',
              border: '1px solid var(--border)',
              backgroundColor: 'var(--card-bg)',
              color: 'var(--text-primary)',
              fontFamily: 'inherit'
            }}
          />
          <ReportGenerator date={selectedDate} />
        </div>
      </DashboardHeader>

      {/* 2. Key Performance Indicators */}
      <KPIGrid
        stats={{
          total: totalThreats,
          highRisk: highRiskCount,
          health: 98.5,
          accuracy: metrics?.accuracy,
          responseTime: 1.2
        }}
        userRole={userRole}
      />

      <main className="dashboard-grid">
        {/* 3. Analytics Panel */}
        <section className="card chart-card">
          <h2><Activity size={20} /> Analysis Overview</h2>
          <div className="charts-container">
            <div className="chart-wrapper">
              <h4 className="chart-title">Risk Levels</h4>
              <ResponsiveContainer>
                <BarChart data={riskStats}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis dataKey="name" stroke="var(--text-secondary)" fontSize={12} tick={{ fill: 'var(--text-secondary)' }} />
                  <YAxis stroke="var(--text-secondary)" fontSize={12} tick={{ fill: 'var(--text-secondary)' }} />
                  <Tooltip
                    cursor={{ fill: 'transparent' }}
                    contentStyle={{ backgroundColor: 'var(--chart-tooltip-bg)', borderColor: 'var(--chart-tooltip-border)', color: 'var(--chart-tooltip-text)' }}
                    itemStyle={{ color: 'var(--chart-tooltip-text)' }}
                  />
                  <Bar dataKey="value" fill="var(--accent)" name="Count" radius={[4, 4, 0, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <AttackTypeChart data={attackTypes} />
            <TrafficTrendChart data={trendData} />

            <div className="chart-wrapper risk-factors-wrapper">
              <FeatureImportanceChart data={features} />
            </div>
          </div>
        </section>

        {/* 4. Visualization Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <GeoThreatMap theme={theme} threats={threats} />
          <TopologyGraph />
        </div>

        {/* 5. Data Feed Panel */}
        <ThreatTable
          data={activeViewData}
          filters={{ type: filterCategory, risk: filterSeverity }}
          setFilters={{ setType: setFilterCategory, setRisk: setFilterSeverity }}
          onRowAction={{
            view: setSelectedIncident,
            block: actions.blockIP
          }}
          userRole={userRole}
        />
      </main>

      {/* 6. Global Overlays */}
      {alert && (
        <Toast
          message={alert.message}
          type={alert.type}
          onClose={() => setAlert(null)}
        />
      )}

      {selectedIncident && (
        <IncidentModal
          threat={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onResolve={actions.resolveThreat}
        />
      )}

      {isPasswordModalOpen && (
        <ChangePasswordModal
          isOpen={isPasswordModalOpen}
          onClose={() => setPasswordModalOpen(false)}
          username={username}
        />
      )}
    </div>
  )
}

export default App
