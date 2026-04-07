import React from 'react'
import { Sun, Moon } from 'lucide-react'

const ThemeToggle = ({ theme, toggleTheme }) => {
    return (
        <div
            onClick={toggleTheme}
            style={{
                width: '56px',
                height: '28px',
                background: theme === 'dark' ? '#1f2937' : '#e5e7eb',
                borderRadius: '20px',
                border: `1px solid ${theme === 'dark' ? '#374151' : '#d1d5db'}`,
                display: 'flex',
                alignItems: 'center',
                padding: '2px',
                cursor: 'pointer',
                position: 'relative',
                transition: 'all 0.3s ease'
            }}
            title="Toggle Theme"
        >
            <div style={{
                width: '24px',
                height: '24px',
                borderRadius: '50%',
                background: theme === 'dark' ? '#0B1015' : '#FFFFFF',
                boxShadow: '0 2px 4px rgba(0,0,0,0.2)',
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                transform: theme === 'dark' ? 'translateX(28px)' : 'translateX(0)',
                transition: 'transform 0.3s cubic-bezier(0.4, 0.0, 0.2, 1)',
                color: theme === 'dark' ? '#38BDF8' : '#F59E0B'
            }}>
                {theme === 'dark' ? <Moon size={14} /> : <Sun size={14} />}
            </div>
        </div>
    )
}

export default ThemeToggle
