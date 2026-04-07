import React, { useState } from 'react';
import api from '../api/axiosConfig';
import { Lock, X, Check } from 'lucide-react';

const ChangePasswordModal = ({ isOpen, onClose, username }) => {
    const [oldPassword, setOldPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [loading, setLoading] = useState(false);

    if (!isOpen) return null;

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        if (newPassword !== confirmPassword) {
            setError("New passwords do not match.");
            return;
        }

        if (newPassword.length < 6) {
            setError("Password must be at least 6 characters.");
            return;
        }

        setLoading(true);
        try {
            await api.post('/auth/change-password', {
                username,
                old_password: oldPassword,
                new_password: newPassword
            });
            setSuccess("Password changed successfully!");
            setTimeout(() => {
                onClose();
                setOldPassword('');
                setNewPassword('');
                setConfirmPassword('');
                setSuccess('');
            }, 1500);
        } catch (err) {
            setError(err.response?.data?.detail || "Failed to update password.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center',
            justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(5px)'
        }}>
            <div className="card" style={{ width: '400px', position: 'relative' }}>
                <button onClick={onClose} style={{
                    position: 'absolute', top: '15px', right: '15px',
                    background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer'
                }}>
                    <X size={20} />
                </button>

                <h2 style={{ marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <Lock size={20} color="var(--accent)" /> Change Password
                </h2>

                <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                    <div>
                        <label style={{ display: 'block', marginBottom: '5px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Current Password</label>
                        <input
                            type="password"
                            value={oldPassword}
                            onChange={(e) => setOldPassword(e.target.value)}
                            required
                            style={{
                                width: '100%', padding: '10px', borderRadius: '6px',
                                background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)',
                                color: 'var(--text-primary)', outline: 'none'
                            }}
                        />
                    </div>
                    <div>
                        <label style={{ display: 'block', marginBottom: '5px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>New Password</label>
                        <input
                            type="password"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            required
                            style={{
                                width: '100%', padding: '10px', borderRadius: '6px',
                                background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)',
                                color: 'var(--text-primary)', outline: 'none'
                            }}
                        />
                    </div>
                    <div>
                        <label style={{ display: 'block', marginBottom: '5px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Confirm Password</label>
                        <input
                            type="password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                            style={{
                                width: '100%', padding: '10px', borderRadius: '6px',
                                background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)',
                                color: 'var(--text-primary)', outline: 'none'
                            }}
                        />
                    </div>

                    {error && <div style={{ color: 'var(--critical)', fontSize: '0.85rem' }}>{error}</div>}
                    {success && <div style={{ color: 'var(--success)', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '5px' }}><Check size={16} /> {success}</div>}

                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
                        <button type="button" onClick={onClose} style={{
                            padding: '8px 16px', borderRadius: '6px', border: '1px solid var(--border)',
                            background: 'transparent', color: 'var(--text-secondary)', cursor: 'pointer'
                        }}>Cancel</button>
                        <button type="submit" disabled={loading} style={{
                            padding: '8px 16px', borderRadius: '6px', border: 'none',
                            background: 'var(--accent)', color: 'white', fontWeight: 600, cursor: 'pointer',
                            opacity: loading ? 0.7 : 1
                        }}>
                            {loading ? 'Updating...' : 'Update Password'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default ChangePasswordModal;
