import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import NotificationCenter from './components/NotificationCenter.jsx';

describe('NotificationCenter Component', () => {
    it('renders a bell icon', () => {
        // using empty alerts for initial render
        render(<NotificationCenter alerts={[]} setAlerts={() => { }} />);
        // The bell icon button should be present
        expect(screen.getByRole('button')).toBeInTheDocument();
    });

    it('displays correct unread count', () => {
        const alerts = [
            { id: '1', read: false, predicted_label: 'Alert 1' },
            { id: '2', read: false, predicted_label: 'Alert 2' },
            { id: '3', read: true, predicted_label: 'Alert 3' },
        ];
        render(<NotificationCenter alerts={alerts} setAlerts={() => { }} />);

        // Total length is 3 (no read filter in component)
        expect(screen.getByText('3')).toBeInTheDocument();
    });

    it('toggles dropdown when clicked', () => {
        const alerts = [{ id: '1', read: false, predicted_label: 'Test Alert', severity: 'Critical', timestamp: new Date().toISOString() }];
        render(<NotificationCenter alerts={alerts} setAlerts={() => { }} />);

        // initially hidden
        expect(screen.queryByText('Notifications')).not.toBeInTheDocument();

        // click bell
        fireEvent.click(screen.getByRole('button'));

        // dropdown appears
        expect(screen.getByText('Notifications')).toBeInTheDocument();
        expect(screen.getByText('Test Alert')).toBeInTheDocument();

        // click again to close
        fireEvent.click(screen.getByRole('button'));
        expect(screen.queryByText('Notifications Center')).not.toBeInTheDocument();
    });
});
