import React from 'react';
import { ShieldAlert } from 'lucide-react';

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null, errorInfo: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true };
    }

    componentDidCatch(error, errorInfo) {
        this.setState({
            error: error,
            errorInfo: errorInfo
        });
        console.error("ErrorBoundary caught an error:", error, errorInfo);
    }

    render() {
        if (this.state.hasError) {
            return (
                <div style={{
                    display: 'flex', flexDirection: 'column', alignItems: 'center',
                    justifyContent: 'center', height: '100vh',
                    backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)'
                }}>
                    <ShieldAlert size={64} color="var(--status-danger)" style={{ marginBottom: '1rem' }} />
                    <h1 style={{ fontSize: '2rem', marginBottom: '1rem' }}>Something went wrong.</h1>
                    <p style={{ color: 'var(--text-secondary)', marginBottom: '2rem' }}>
                        The application encountered an unexpected error.
                    </p>
                    <button
                        onClick={() => window.location.reload()}
                        style={{
                            padding: '10px 20px', backgroundColor: 'var(--accent-primary)',
                            color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer',
                            fontWeight: '600', transition: 'background 0.2s'
                        }}
                    >
                        Reload Application
                    </button>
                    {process.env.NODE_ENV === 'development' && (
                        <details style={{ whiteSpace: 'pre-wrap', marginTop: '2rem', textAlign: 'left', padding: '1rem', background: 'var(--bg-primary)', borderRadius: '8px', maxWidth: '80%' }}>
                            <summary>Error Details</summary>
                            <br />
                            {this.state.error && this.state.error.toString()}
                            <br />
                            {this.state.errorInfo && this.state.errorInfo.componentStack}
                        </details>
                    )}
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;
