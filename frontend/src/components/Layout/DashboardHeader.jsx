import { ShieldAlert, User, UserCog, LogOut, Lock } from 'lucide-react'
import NotificationCenter from '../NotificationCenter'
import ThemeToggle from '../ThemeToggle'

const DashboardHeader = ({ theme, userRole, criticalAlerts, wsStatus, actions, children }) => {
    return (
        <header className="header">
            <div className="logo">
                <ShieldAlert size={32} color={"var(--status-info)"} />
                <h1>Sentin<span style={{ color: 'var(--accent-primary)' }}>AI</span> NetGuard</h1>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                {/* Custom Controls (Date Picker / PDF) */}
                {children}

                <NotificationCenter alerts={criticalAlerts} onResolve={actions.resolveThreat} />
                <ThemeToggle theme={theme} toggleTheme={actions.toggleTheme} />

                <div className="role-toggle" onClick={actions.toggleRole}>
                    {userRole === 'SOC Analyst' ? <User size={18} /> : <UserCog size={18} />}
                    <span>{userRole} View</span>
                </div>

                <div className="status-badge" style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '4px 10px', background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                    <div className={wsStatus === 'CONNECTED' ? 'pulse-icon' : ''} style={{ 
                        width: 10, height: 10, borderRadius: '50%', 
                        background: wsStatus === 'CONNECTED' ? 'var(--status-success)' : (wsStatus === 'CONNECTING' || wsStatus === 'RECONNECTING' ? 'orange' : 'var(--status-danger)'),
                        boxShadow: wsStatus === 'CONNECTED' ? '0 0 8px var(--status-success)' : ''
                    }}></div>
                    <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {wsStatus === 'CONNECTED' ? 'LIVE' : wsStatus}
                    </span>
                </div>

                <div className="db-status-badge" style={{
                    padding: '4px 8px',
                    borderRadius: '4px',
                    border: '1px solid var(--border-subtle)',
                    fontSize: '0.8rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: actions.dbStatus === 'connected' ? 'rgba(9, 105, 218, 0.1)' : 'rgba(255, 171, 0, 0.1)'
                }}>
                    <div style={{
                        width: 8, height: 8, borderRadius: '50%',
                        background: actions.dbStatus === 'connected' ? 'var(--primary)' : 'orange'
                    }}></div>
                    <span>{actions.dbStatus === 'connected' ? 'MongoDB Connected' : 'DB Disconnected'}</span>
                </div>

                <div style={{ width: '1px', height: '24px', background: 'var(--border-subtle)', margin: '0 5px' }}></div>

                <button onClick={actions.openPasswordModal} className="action-btn" title="Change Password" style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-subtle)' }}>
                    <Lock size={16} />
                </button>

                <button onClick={actions.logout} className="action-btn" title="Logout" style={{ color: 'var(--status-danger)', border: '1px solid var(--status-danger)' }}>
                    <LogOut size={16} />
                </button>
            </div>
        </header>
    )
}

export default DashboardHeader
