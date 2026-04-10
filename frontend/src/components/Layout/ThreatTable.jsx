import { useState, useEffect } from 'react'
import { ShieldAlert, Flame, Eye, ChevronLeft, ChevronRight } from 'lucide-react'

const ThreatTable = ({ data = [], filters = { type: 'All', risk: 'All' }, setFilters = {}, onRowAction = {}, userRole = 'Observer' }) => {
    // Pagination State
    const [currentPage, setCurrentPage] = useState(1);
    const itemsPerPage = 10;

    // Reset to page 1 whenever the data set changes (filter change, refresh, WS update)
    // Prevents "empty page" bug where page 2+ is selected but data shrank to fewer pages
    useEffect(() => {
        setCurrentPage(1);
    }, [data.length]);

    const totalPages = Math.ceil((data?.length || 0) / itemsPerPage);
    const startIndex = (currentPage - 1) * itemsPerPage;
    const currentData = (data || []).slice(startIndex, startIndex + itemsPerPage);

    const handlePageChange = (newPage) => {
        if (newPage >= 1 && newPage <= totalPages) {
            setCurrentPage(newPage);
        }
    };

    const getRiskColor = (score) => {
        if (score >= 80) return 'text-red-500'
        if (score >= 60) return 'text-orange-500'
        if (score >= 30) return 'text-yellow-500'
        return 'text-green-500'
    }

    const getRowClass = (score) => score >= 80 ? 'critical-row' : ''

    return (
        <section className="card feed-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                <h2><ShieldAlert size={20} /> Threat Drill-Down</h2>
                <div style={{ display: 'flex', gap: '10px' }}>
                    <select className="filter-select" value={filters.type} onChange={e => { setFilters.setType(e.target.value); setCurrentPage(1); }}>
                        <option value="All">All Types</option>
                        <option value="DDoS">DDoS</option>
                        <option value="Brute Force">Brute Force</option>
                        <option value="Port Scan">Port Scan</option>
                        <option value="Normal">Normal</option>
                    </select>
                    <select className="filter-select" value={filters.risk} onChange={e => { setFilters.setRisk(e.target.value); setCurrentPage(1); }}>
                        <option value="All">All Risks</option>
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                    </select>
                </div>
            </div>

            <div className="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Timestamp</th>
                            <th>Source IP</th>
                            <th>Target IP</th>
                            <th>Type</th>
                            <th>Confidence</th>
                            <th>Risk Score</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {currentData.map((t, i) => (
                            <tr key={i} className={getRowClass(t.risk_score)}>
                                <td>
                                    <span style={{
                                        padding: '2px 8px', borderRadius: '10px', fontSize: '0.75rem', fontWeight: 600,
                                        background: t.status === 'Resolved' ? 'var(--bg-elevated)' : 'var(--critical-bg-subtle)',
                                        color: t.status === 'Resolved' ? 'var(--status-success)' : 'var(--status-danger)'
                                    }}>
                                        {t.status || 'Active'}
                                    </span>
                                </td>
                                <td>{new Date(t.timestamp).toLocaleTimeString()}</td>
                                <td>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        {t.source_ip}
                                        {t.escalation_flag && (
                                            <span title="Repeat Offender: Risk Escalated">
                                                <Flame size={14} color="var(--status-danger)" fill="var(--status-danger)" />
                                            </span>
                                        )}
                                    </div>
                                </td>
                                <td>{t.destination_ip || t.dest_ip || '-'}</td>
                                <td style={{ fontWeight: 'bold', color: t.predicted_label === 'Normal' ? 'var(--status-success)' : 'var(--text-primary)' }}>{t.predicted_label}</td>
                                <td>{t.confidence ? (t.confidence * 100).toFixed(0) + '%' : 'N/A'}</td>
                                <td className={`risk-score ${getRiskColor(t.risk_score)}`}>
                                    {t.risk_score} <span style={{ fontSize: '0.7em', opacity: 0.7 }}>
                                        {t.risk_score >= 80 ? '(CRITICAL)' : t.risk_score >= 60 ? '(HIGH)' : t.risk_score >= 30 ? '(MED)' : '(LOW)'}
                                    </span>
                                </td>
                                <td>
                                    <div style={{ display: 'flex', gap: '8px' }}>
                                        <button onClick={() => onRowAction.view(t)} className="action-btn" style={{
                                            color: 'var(--status-info)', borderColor: 'var(--status-info)'
                                        }}>
                                            <Eye size={12} /> View
                                        </button>
                                        {userRole === 'SOC Analyst' && t.status !== 'Resolved' && (
                                            <button onClick={() => onRowAction.block(t.id, t.source_ip)} className="action-btn" style={{
                                                color: 'var(--status-danger)', borderColor: 'var(--status-danger)'
                                            }}>
                                                <ShieldAlert size={12} /> Block
                                            </button>
                                        )}
                                    </div>
                                </td>
                            </tr>
                        ))}
                        {data.length === 0 && (
                            <tr><td colSpan="8" style={{ textAlign: 'center', padding: '20px' }}>No threats match filters...</td></tr>
                        )}
                        {currentData.length === 0 && data.length > 0 && (
                            <tr><td colSpan="8" style={{ textAlign: 'center', padding: '20px' }}>Page is empty...</td></tr>
                        )}
                    </tbody>
                </table>
            </div>

            {/* Pagination Controls */}
            {data.length > itemsPerPage && (
                <div style={{
                    display: 'flex',
                    justifyContent: 'flex-end',
                    alignItems: 'center',
                    padding: '10px 0',
                    gap: '15px',
                    marginTop: '10px',
                    borderTop: '1px solid var(--border-subtle)'
                }}>
                    <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                        Page {currentPage} of {totalPages}
                    </span>
                    <div style={{ display: 'flex', gap: '5px' }}>
                        <button
                            onClick={() => handlePageChange(currentPage - 1)}
                            disabled={currentPage === 1}
                            className="action-btn"
                            style={{
                                padding: '5px 10px',
                                opacity: currentPage === 1 ? 0.5 : 1,
                                cursor: currentPage === 1 ? 'not-allowed' : 'pointer'
                            }}
                        >
                            <ChevronLeft size={16} /> Prev
                        </button>
                        <button
                            onClick={() => handlePageChange(currentPage + 1)}
                            disabled={currentPage === totalPages}
                            className="action-btn"
                            style={{
                                padding: '5px 10px',
                                opacity: currentPage === totalPages ? 0.5 : 1,
                                cursor: currentPage === totalPages ? 'not-allowed' : 'pointer'
                            }}
                        >
                            Next <ChevronRight size={16} />
                        </button>
                    </div>
                </div>
            )}
        </section>
    )
}

export default ThreatTable
