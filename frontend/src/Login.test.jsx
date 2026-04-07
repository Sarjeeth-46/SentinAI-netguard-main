import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import Login from './components/Login.jsx';

// Mock the useAuth hook since it handles the API logic
vi.mock('./hooks/useAuth.js', () => ({
    useAuth: () => ({
        login: vi.fn(),
        error: null,
        isLoading: false,
    }),
}));

describe('Login Component', () => {
    it('renders login form correctly', () => {
        render(<Login onLogin={vi.fn()} />);

        expect(screen.getByPlaceholderText('Username')).toBeInTheDocument();
        expect(screen.getByPlaceholderText('Password')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /login/i })).toBeInTheDocument();
    });

    it('allows typing in input fields', () => {
        render(<Login onLogin={vi.fn()} />);

        const usernameInput = screen.getByPlaceholderText('Username');
        const passwordInput = screen.getByPlaceholderText('Password');

        fireEvent.change(usernameInput, { target: { value: 'admin' } });
        fireEvent.change(passwordInput, { target: { value: 'password123' } });

        expect(usernameInput.value).toBe('admin');
        expect(passwordInput.value).toBe('password123');
    });
});
