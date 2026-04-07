import React, { useState, useRef, useEffect } from 'react';
import { Bell, ShieldAlert, X, CheckCircle } from 'lucide-react';

const NotificationCenter = ({ alerts, onResolve }) => {
    const [isOpen, setIsOpen] = useState(false);
    const dropdownRef = useRef(null);

    const toggleDropdown = () => setIsOpen(!isOpen);

    // Close dropdown when clicking outside
    useEffect(() => {
        const handleClickOutside = (event) => {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const unsortedAlerts = [...alerts].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    return (
        <div className="notification-container" ref={dropdownRef}>
            <button
                className={`notification-bell ${isOpen ? 'active' : ''}`}
                onClick={toggleDropdown}
                aria-label="Notifications"
            >
                <Bell size={20} />
                {alerts.length > 0 && (
                    <span className="notification-badge">{alerts.length}</span>
                )}
            </button>

            {isOpen && (
                <div className="notification-dropdown">
                    <div className="notification-header">
                        <h3>Notifications</h3>
                        <span className="notification-count">{alerts.length} New</span>
                    </div>

                    <div className="notification-list">
                        {alerts.length === 0 ? (
                            <div className="empty-state">
                                <CheckCircle size={32} color="var(--text-secondary)" style={{ opacity: 0.5 }} />
                                <p>All clear! No active threats.</p>
                            </div>
                        ) : (
                            unsortedAlerts.map((alert) => (
                                <div key={alert.id} className="notification-item critical">
                                    <div className="notif-icon">
                                        <ShieldAlert size={16} color="#F43F5E" />
                                    </div>
                                    <div className="notif-content">
                                        <div className="notif-top">
                                            <span className="notif-title">{alert.predicted_label}</span>
                                            <span className="notif-time">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                                        </div>
                                        <p className="notif-msg">Detected from {alert.source_ip}</p>
                                        <button
                                            className="resolve-btn-text"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                onResolve(alert.id);
                                            }}
                                        >
                                            Mark Resolved
                                        </button>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

export default NotificationCenter;
