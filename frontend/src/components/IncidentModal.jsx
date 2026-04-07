import { useRef, useEffect } from 'react';
import { X, ShieldAlert, CheckCircle, AlertTriangle, Monitor, Activity } from 'lucide-react';

const IncidentModal = ({ threat, onClose, onResolve }) => {
    const modalRef = useRef(null);

    useEffect(() => {
        const handleClickOutside = (event) => {
            if (modalRef.current && !modalRef.current.contains(event.target)) {
                onClose();
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [onClose]);

    if (!threat) return null;

    const getRiskColor = (score) => {
        if (score >= 80) return '#fa1f02ff';
        if (score >= 60) return '#F97316';
        if (score >= 30) return '#EAB308';
        return '#22C55E';
    };

    const riskColor = getRiskColor(threat.risk_score);

    return (
        <div style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 1000,
            backdropFilter: 'blur(4px)'
        }}>
            <div ref={modalRef} style={{
                background: 'var(--card-bg)',
                border: `1px solid ${riskColor}`,
                borderRadius: '12px',
                width: '600px',
                maxWidth: '90%',
                boxShadow: '0 20px 50px rgba(0,0,0,0.5)',
                overflow: 'hidden'
            }}>
                {/* Header */}
                <div style={{
                    padding: '20px 24px',
                    borderBottom: '1px solid var(--border)',
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    background: `linear-gradient(to right, ${riskColor}15, transparent)`
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <ShieldAlert color={riskColor} size={24} />
                        <h2 style={{ margin: 0, color: 'var(--text-primary)', fontSize: '1.25rem' }}>Incident Details</h2>
                    </div>
                    <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }}>
                        <X size={20} />
                    </button>
                </div>

                {/* Body */}
                <div style={{ padding: '24px' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '24px' }}>
                        <div>
                            <label style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Source IP</label>
                            <div style={{ color: 'var(--text-primary)', fontFamily: 'monospace', fontSize: '1.1rem' }}>{threat.source_ip}</div>
                        </div>
                        <div>
                            <label style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Target IP</label>
                            <div style={{ color: 'var(--text-primary)', fontFamily: 'monospace', fontSize: '1.1rem' }}>{threat.dest_ip}</div>
                        </div>
                        <div>
                            <label style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Attack Type</label>
                            <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{threat.predicted_label}</div>
                        </div>
                        <div>
                            <label style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Timestamp</label>
                            <div style={{ color: 'var(--text-primary)' }}>{new Date(threat.timestamp).toLocaleString()}</div>
                        </div>
                    </div>

                    <div style={{ background: 'rgba(0,0,0,0.1)', padding: '16px', borderRadius: '8px', marginBottom: '24px', border: '1px solid var(--border)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                            <span style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>AI Confidence</span>
                            <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{(threat.attack_probability * 100).toFixed(1)}%</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <span style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>Risk Score</span>
                            <span style={{ color: riskColor, fontWeight: 700 }}>{threat.risk_score} / 100</span>
                        </div>
                    </div>

                    {/* Recommended Action */}
                    <div style={{ marginBottom: '24px' }}>
                        <h4 style={{ color: 'var(--text-primary)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <Activity size={16} color="var(--accent)" /> Recommended Action
                        </h4>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', lineHeight: '1.5' }}>
                            {threat.predicted_label === 'DDoS' ? 'Initiate traffic throttling on source IP and verify upstream filters.' :
                                threat.predicted_label === 'Brute Force' ? 'Block source IP temporarily and force password reset for targeted account.' :
                                    threat.predicted_label === 'Port Scan' ? 'Monitor for subsequent connection attempts. No immediate block required unless frequency increases.' :
                                        'Investigate payload and monitor session activity.'}
                        </p>
                    </div>

                    {/* Status Badge */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
                        <span style={{ color: '#8B949E' }}>Status:</span>
                        <span style={{
                            padding: '4px 12px',
                            borderRadius: '12px',
                            fontSize: '0.85rem',
                            fontWeight: 600,
                            background: threat.status === 'Resolved' ? 'rgba(46, 160, 67, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                            color: threat.status === 'Resolved' ? '#2EA043' : '#F43F5E',
                            border: `1px solid ${threat.status === 'Resolved' ? '#2EA043' : '#F43F5E'}`
                        }}>
                            {threat.status || 'Active'}
                        </span>
                    </div>
                </div>

                {/* Footer */}
                <div style={{
                    padding: '20px 24px',
                    borderTop: '1px solid var(--border)',
                    display: 'flex', justifyContent: 'flex-end', gap: '12px',
                    background: 'var(--card-bg)'
                }}>
                    <button onClick={onClose} style={{
                        padding: '8px 16px', borderRadius: '6px', border: '1px solid var(--border)',
                        background: 'none', color: 'var(--text-primary)', cursor: 'pointer'
                    }}>
                        Close
                    </button>

                    {threat.status !== 'Resolved' && (
                        <button onClick={() => onResolve(threat.id)} style={{
                            padding: '8px 16px', borderRadius: '6px', border: 'none',
                            background: 'var(--success)', color: '#FFFFFF', fontWeight: 600,
                            cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px'
                        }}>
                            <CheckCircle size={16} /> Mark as Resolved
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
};

export default IncidentModal;
