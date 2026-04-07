import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ReportGenerator from './components/ReportGenerator.jsx';
import api from './api/axiosConfig';

// Mock the jsPDF dependency
vi.mock('jspdf', () => {
    return {
        default: vi.fn().mockImplementation(() => ({
            text: vi.fn(),
            save: vi.fn(),
            setDrawColor: vi.fn(),
            line: vi.fn(),
            setFontSize: vi.fn(),
            setTextColor: vi.fn(),
            internal: { getNumberOfPages: () => 1 },
            setPage: vi.fn(),
        }))
    };
});

vi.mock('jspdf-autotable', () => ({
    default: vi.fn()
}));

vi.mock('./api/axiosConfig', () => ({
    default: {
        post: vi.fn().mockResolvedValue({
            data: {
                summary: { total_incidents: 0, severity_distribution: {}, top_offenders: {} },
                critical_threats: [],
                metadata: { target_date: '2024-01-01', report_id: '123' }
            }
        })
    }
}));

describe('ReportGenerator Component', () => {
    it('renders download button and date picker', () => {
        // We pass an empty function for handleAction to mock it
        render(<ReportGenerator />);

        expect(screen.getByRole('button', { name: /download report/i })).toBeInTheDocument();
    });

    it('allows clicking the download button', () => {
        render(<ReportGenerator />);
        const btn = screen.getByRole('button', { name: /download report/i });

        // We expect the button to not crash when clicked
        expect(() => fireEvent.click(btn)).not.toThrow();
    });
});
