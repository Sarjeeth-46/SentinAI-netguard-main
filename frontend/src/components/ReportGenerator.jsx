import React, { useState } from 'react';
import api from '../api/axiosConfig';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { Download, FileText, Loader } from 'lucide-react';

const ReportGenerator = ({ date }) => {
    const [loading, setLoading] = useState(false);

    const generatePDF = async () => {
        setLoading(true);
        try {
            // 1. Fetch Report Data
            // 1. Fetch Report Data (Trigger Generation)
            const targetDate = date || new Date().toISOString().split('T')[0];
            // Use POST to ensure report is generated if missing
            const res = await api.post(`/reports/generate`, { date: targetDate });

            if (res.data.error) {
                alert("No report data available for this date.");
                setLoading(false);
                return;
            }

            const data = res.data;
            const doc = new jsPDF();

            // 2. Build PDF Content
            // Header
            doc.setFontSize(22);
            doc.setTextColor(30, 41, 59); // Slate-800
            doc.text("SentinAI NetGuard - Daily Security Report", 14, 20);

            doc.setFontSize(12);
            doc.setTextColor(100);
            doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 30);
            const safeTargetDate = (data && data.metadata && data.metadata.target_date) ? data.metadata.target_date : targetDate;
            const safeReportId = (data && data.metadata && data.metadata.report_id) ? data.metadata.report_id : 'N/A';
            doc.text(`Target Date: ${safeTargetDate}`, 14, 36);
            doc.text(`Report ID: ${safeReportId}`, 14, 42);

            if (data?.status === 'No Data') {
                doc.setFontSize(14);
                doc.setTextColor(200, 0, 0);
                doc.text("No threats recorded for this date.", 14, 60);
                doc.save(`SentinAI_Report_${targetDate}.pdf`);
                setLoading(false);
                return;
            }

            // Summary Section
            doc.setDrawColor(200);
            doc.line(14, 48, 196, 48);

            doc.setFontSize(16);
            doc.setTextColor(0);
            doc.text("Executive Summary", 14, 60);

            const summary = data?.summary || {};
            const startY = 70;

            doc.setFontSize(12);
            doc.text(`Total Incidents Detected: ${summary.total_incidents}`, 14, startY);

            // Risk Stats
            doc.text("Severity Distribution:", 14, startY + 10);
            let offset = 0;
            Object.entries(summary?.severity_distribution || {}).forEach(([level, count]) => {
                doc.text(`- ${level}: ${count}`, 20, startY + 18 + offset);
                offset += 6;
            });

            // Top Attackers
            doc.text("Top 5 Source IPs:", 100, startY + 10);
            offset = 0;
            Object.entries(summary?.top_offenders || {}).forEach(([ip, count]) => {
                doc.text(`- ${ip}: ${count}`, 106, startY + 18 + offset);
                offset += 6;
            });

            // Critical Threats Table
            doc.text("High Priority Threats", 14, startY + 60);

            const tableRows = (data?.critical_threats || []).map(threat => [
                threat?.timestamp?.split(' ')[1] || 'N/A', // Time only
                threat?.source || threat?.src_ip || 'Unknown',
                threat?.type || 'Unknown',
                threat?.risk_score?.toString() || '0'
            ]);

            autoTable(doc, {
                startY: startY + 65,
                head: [['Time', 'Source IP', 'Attack Vector', 'Risk Score']],
                body: tableRows,
                theme: 'grid',
                headStyles: { fillColor: [220, 38, 38] }, // Red header
                styles: { fontSize: 10 }
            });

            // Footer
            const pageCount = doc.internal.getNumberOfPages();
            for (let i = 1; i <= pageCount; i++) {
                doc.setPage(i);
                doc.setFontSize(10);
                doc.setTextColor(150);
                doc.text(`Confidential - SentinAI Internal Use Only - Page ${i} of ${pageCount}`, 14, 290);
            }

            // Save
            doc.save(`SentinAI_Report_${targetDate}.pdf`);

        } catch (err) {
            console.error("Report Generation Error:", err);
            const msg = err.response?.data?.detail || err.message;
            alert(`Failed to generate report: ${msg}`);
        } finally {
            setLoading(false);
        }
    };

    return (
        <button
            onClick={generatePDF}
            disabled={loading}
            style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                padding: '8px 16px',
                backgroundColor: 'var(--accent)',
                color: 'white',
                border: 'none', borderRadius: '6px',
                cursor: 'pointer',
                opacity: loading ? 0.7 : 1
            }}
        >
            {loading ? <Loader size={16} className="spin" /> : <FileText size={16} />}
            {loading ? 'Generating...' : 'Download Report'}
        </button>
    );
};

export default ReportGenerator;
