import React from 'react';
import { ShieldAlert, XCircle } from 'lucide-react';

const AlertBanner = ({ alerts, onResolve }) => {
    if (!alerts || alerts.length === 0) return null;

    return (
        <div className="alert-banner">
            <div className="alert-header">
                <ShieldAlert size={20} className="pulse-icon" />
                <span>CRITICAL ALERTS ({alerts.length})</span>
            </div>
            <div className="alert-ticker">
                {alerts.map((alert) => (
                    <div key={alert.id} className="alert-item">
                        <span className="alert-time">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                        <span className="alert-msg">
                            <strong>{alert.predicted_label}</strong> from {alert.source_ip}
                        </span>
                        <button
                            className="resolve-btn-mini"
                            onClick={() => onResolve(alert.id)}
                        >
                            Resolve
                        </button>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default AlertBanner;
