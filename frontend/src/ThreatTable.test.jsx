import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ThreatTable from './components/Layout/ThreatTable.jsx';

const mockThreats = [
    { id: '1', timestamp: '2024-01-01T00:00:00Z', source_ip: '10.0.0.1', dest_ip: '10.0.0.2', predicted_label: 'Brute Force', severity: 'Critical', confidence: 0.99 },
    { id: '2', timestamp: '2024-01-01T00:01:00Z', source_ip: '10.0.0.3', dest_ip: '10.0.0.4', predicted_label: 'Normal', severity: 'Low', confidence: 0.85 },
    // add a few more if needed to test pagination
];

describe('ThreatTable Component', () => {
    it('renders table headers and rows correctly', () => {
        // We pass an empty function for row actions to mock it
        render(<ThreatTable data={mockThreats} onRowAction={{ view: vi.fn(), block: vi.fn() }} />);

        expect(screen.getByText('Timestamp')).toBeInTheDocument();
        expect(screen.getByText('Source IP')).toBeInTheDocument();

        // Check if the mock data rendered by fetching all matching elements
        expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
        const bruteForceLabels = screen.getAllByText('Brute Force');
        expect(bruteForceLabels.length).toBeGreaterThan(0);
    });
});
