import { useState, useEffect } from 'react';
import { AlertTriangle, X } from 'lucide-react';

const Toast = ({ message, type = 'info', onClose }) => {
    const [visible, setVisible] = useState(false);

    useEffect(() => {
        // Trigger entrance animation
        requestAnimationFrame(() => setVisible(true));

        // Auto dismiss
        const timer = setTimeout(() => {
            setVisible(false);
            setTimeout(onClose, 300); // Wait for exit animation
        }, 5000);

        return () => clearTimeout(timer);
    }, [onClose]);

    const isCritical = type === 'critical';

    return (
        <div
            style={{
                position: 'fixed',
                bottom: '30px',
                right: '30px',
                background: 'var(--bg-surface)',
                color: 'var(--text-primary)',
                padding: '16px 24px',
                borderRadius: '8px',
                border: `1px solid ${isCritical ? 'var(--status-danger)' : 'var(--accent-primary)'}`,
                boxShadow: isCritical ? '0 4px 12px rgba(244, 63, 94, 0.3)' : '0 4px 12px rgba(56, 189, 248, 0.2)',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                zIndex: 1000,
                transform: visible ? 'translateY(0) scale(1)' : 'translateY(20px) scale(0.95)',
                opacity: visible ? 1 : 0,
                transition: 'all 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
                minWidth: '300px',
            }}
        >
            <div
                style={{
                    background: isCritical ? 'var(--critical-bg-subtle)' : 'var(--bg-elevated)',
                    padding: '8px',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                }}
            >
                <AlertTriangle size={20} color={isCritical ? 'var(--status-danger)' : 'var(--accent-primary)'} />
            </div>

            <div style={{ flex: 1 }}>
                <h4 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600, color: isCritical ? 'var(--status-danger)' : 'var(--accent-primary)' }}>
                    {isCritical ? 'CRITICAL THREAT DETECTED' : 'System Alert'}
                </h4>
                <p style={{ margin: '4px 0 0', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    {message}
                </p>
            </div>

            <button
                onClick={() => { setVisible(false); setTimeout(onClose, 300); }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', padding: 4 }}
            >
                <X size={16} />
            </button>
        </div>
    );
};

export default Toast;
