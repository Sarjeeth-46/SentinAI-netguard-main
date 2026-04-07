import { useState, useEffect } from 'react';
import api from '../api/axiosConfig';

export const useAuth = () => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [userRole, setUserRole] = useState('SOC Analyst');
    const [username, setUsername] = useState('');

    // Init auth state from backend HttpOnly session
    useEffect(() => {
        const verifyAuth = async () => {
            try {
                const res = await api.get('/auth/me');
                setIsAuthenticated(true);
                setUserRole(res.data.role || 'SOC Analyst');
                setUsername(res.data.username || '');
            } catch (error) {
                setIsAuthenticated(false);
            }
        };
        verifyAuth();
    }, []);

    const login = async (username, password) => {
        try {
            // Login will set the HttpOnly cookie
            await api.post('/auth/login', { username, password });

            // Re-verify to fetch role and username
            const meRes = await api.get('/auth/me');

            setIsAuthenticated(true);
            setUserRole(meRes.data.role || 'SOC Analyst');
            setUsername(meRes.data.username || '');
            return true;
        } catch (error) {
            console.error("Auth Error:", error);
            return false;
        }
    };

    const logout = async () => {
        try {
            await api.post('/auth/logout');
        } catch (e) { }
        setIsAuthenticated(false);
        setUserRole('SOC Analyst');
    };

    const toggleRole = () => {
        // In real auth, role is tied to user. 
        // We keep this for now but it won't persist across reloads unless we update the token (complex).
        // Let's just switch the local view state.
        setUserRole(prev => prev === 'SOC Analyst' ? 'CISO' : 'SOC Analyst');
    };

    return {
        isAuthenticated,
        userRole,
        username,
        login,
        logout,
        toggleRole
    };
};
