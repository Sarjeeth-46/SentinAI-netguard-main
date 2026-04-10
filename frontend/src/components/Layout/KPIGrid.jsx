import { Server, AlertTriangle, CheckCircle, Zap, Target } from 'lucide-react'

const KPIGrid = ({ stats, userRole }) => {
    return (
        <div className="kpi-grid">
            <div className="kpi-card">
                <div className="kpi-icon"><Server size={24} color="var(--accent-primary)" /></div>
                <div className="kpi-info">
                    <h3>Total Threats</h3>
                    <p>{stats.total}</p>
                </div>
            </div>
            <div className="kpi-card">
                <div className="kpi-icon"><AlertTriangle size={24} color="var(--status-danger)" /></div>
                <div className="kpi-info">
                    <h3>Critical Threats</h3>
                    <p>{stats.highRisk}</p>
                </div>
            </div>
            <div className="kpi-card">
                <div className="kpi-icon"><CheckCircle size={24} color="var(--status-success)" /></div>
                <div className="kpi-info">
                    <h3>System Health</h3>
                    <p>{stats.health}%</p>
                </div>
            </div>
            {
                userRole === 'SOC Analyst' ? (
                    <div className="kpi-card">
                        <div className="kpi-icon"><Zap size={24} color="var(--status-warning)" /></div>
                        <div className="kpi-info">
                            <h3>Response Time</h3>
                            <p>{stats.responseTime}s</p>
                        </div>
                    </div>
                ) : (
                    <div className="kpi-card">
                        <div className="kpi-icon"><Target size={24} color="var(--status-success)" /></div>
                        <div className="kpi-info">
                            <h3>Model Accuracy</h3>
                            <p>{stats.accuracy ? (stats.accuracy * 100).toFixed(0) + '%' : 'N/A'}</p>
                        </div>
                    </div>
                )
            }
        </div>
    )
}

export default KPIGrid
