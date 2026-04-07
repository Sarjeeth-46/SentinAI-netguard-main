import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const TrafficTrendChart = ({ data }) => {
    // Transform data if needed, or assume data is passed in correct format
    // Expecting data to be an array of objects with timestamp/time and risk_score/value

    // If data is empty, show a placeholder or empty state
    if (!data || data.length === 0) {
        return (
            <div className="chart-wrapper" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <p style={{ color: 'var(--text-secondary)' }}>No Trend Data Available</p>
            </div>
        );
    }

    return (
        <div className="chart-wrapper">
            <h4 className="chart-title">Traffic Severity Trend</h4>
            <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                    data={data}
                    margin={{
                        top: 10,
                        right: 30,
                        left: 0,
                        bottom: 0,
                    }}
                >
                    <defs>
                        <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="var(--accent)" stopOpacity={0.8} />
                            <stop offset="95%" stopColor="var(--accent)" stopOpacity={0} />
                        </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" vertical={false} />
                    <XAxis
                        dataKey="timestamp"
                        stroke="var(--text-secondary)"
                        fontSize={10}
                        tickFormatter={(tick) => new Date(tick).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    />
                    <YAxis stroke="var(--text-secondary)" fontSize={10} />
                    <Tooltip
                        contentStyle={{ backgroundColor: 'var(--chart-tooltip-bg)', borderColor: 'var(--chart-tooltip-border)', color: 'var(--chart-tooltip-text)' }}
                        itemStyle={{ color: 'var(--chart-tooltip-text)' }}
                        labelFormatter={(label) => new Date(label).toLocaleTimeString()}
                    />
                    <Area
                        type="monotone"
                        dataKey="risk_score"
                        stroke="var(--accent)"
                        fillOpacity={1}
                        fill="url(#colorRisk)"
                        isAnimationActive={false}
                    />
                </AreaChart>
            </ResponsiveContainer>
        </div>
    );
};

export default TrafficTrendChart;
