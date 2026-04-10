import React from 'react'
import { Sun, Moon, Monitor } from 'lucide-react'

const ThemeToggle = ({ theme, toggleTheme }) => {
    // theme can be 'dark', 'light', 'system'
    
    let Icon = Moon;
    let iconColor = 'var(--accent-primary)';
    
    if (theme === 'dark') {
        Icon = Moon;
        iconColor = 'var(--accent-primary)';
    } else if (theme === 'light') {
        Icon = Sun;
        iconColor = 'var(--status-warning)';
    } else {
        Icon = Monitor;
        iconColor = 'var(--status-info)';
    }

    return (
        <button
            onClick={toggleTheme}
            style={{
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '6px 12px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                cursor: 'pointer',
                color: 'var(--text-primary)',
                transition: 'all 0.2s ease',
                fontSize: '0.85rem'
            }}
            title={`Toggle Theme (Current: ${theme})`}
            onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--accent-primary)';
                e.currentTarget.style.boxShadow = '0 0 8px rgba(99,102,241,0.2)';
            }}
            onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border-subtle)';
                e.currentTarget.style.boxShadow = 'none';
            }}
        >
            <Icon size={16} color={iconColor} />
            <span style={{ textTransform: 'capitalize', fontWeight: 500, minWidth: '48px', textAlign: 'left' }}>
                {theme}
            </span>
        </button>
    )
}

export default ThemeToggle
