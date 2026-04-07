import React, { useState } from 'react'
import { ShieldCheck, Lock } from 'lucide-react'

const Login = ({ onLogin }) => {
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState('')

    const handleSubmit = async (e) => {
        e.preventDefault()
        setError('')
        setIsLoading(true)

        const success = await onLogin(username, password)
        if (!success) {
            setError('Invalid credentials. Please try again.')
            setIsLoading(false)
        }
    }

    return (
        <div style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            height: '100vh',
            background: 'var(--bg-color)',
            color: 'var(--text-primary)'
        }}>
            <div className="card" style={{ width: '350px', textAlign: 'center' }}>
                <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '20px' }}>
                    <ShieldCheck size={48} color="var(--accent)" />
                </div>
                <h2 style={{ justifyContent: 'center', border: 'none' }}>System Login</h2>
                <p style={{ color: 'var(--text-secondary)', marginBottom: '20px' }}>NetGuard Secure Access</p>

                <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                    <input
                        type="text"
                        placeholder="Username"
                        value={username}
                        onChange={e => setUsername(e.target.value)}
                        style={{
                            background: 'var(--card-bg)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                            padding: '12px',
                            borderRadius: '6px',
                            outline: 'none'
                        }}
                    />
                    <input
                        type="password"
                        placeholder="Password"
                        value={password}
                        onChange={e => setPassword(e.target.value)}
                        style={{
                            background: 'var(--card-bg)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                            padding: '12px',
                            borderRadius: '6px',
                            outline: 'none'
                        }}
                    />

                    {error && <p style={{ color: 'var(--critical)', fontSize: '0.85rem' }}>{error}</p>}

                    <button type="submit" disabled={isLoading} style={{
                        background: isLoading ? 'var(--text-secondary)' : 'var(--accent)',
                        color: '#fff',
                        border: 'none',
                        padding: '12px',
                        borderRadius: '6px',
                        fontWeight: '600',
                        cursor: isLoading ? 'not-allowed' : 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '8px',
                        opacity: isLoading ? 0.7 : 1
                    }}>
                        {isLoading ? 'Authenticating...' : <><Lock size={16} /> Login</>}
                    </button>
                </form>
            </div>
        </div>
    )
}

export default Login
