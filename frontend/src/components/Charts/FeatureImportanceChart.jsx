import React from 'react'
import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    Cell
} from 'recharts'

const FeatureImportanceChart = ({ data }) => {
    // Deep Navy/Neon Theme Colors
    const colors = ['var(--status-info)', 'var(--accent-primary)', 'var(--status-warning)']

    return (
        <div className="chart-wrapper">
            <h3 className="chart-title">ML Model Explainability (Feature Importance)</h3>
            <div style={{ width: '100%', height: '200px' }}>
                <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                        data={data}
                        layout="vertical"
                        margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
                    >
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" horizontal={false} />
                        <XAxis type="number" stroke="var(--text-secondary)" fontSize={10} />
                        <YAxis
                            dataKey="feature"
                            type="category"
                            stroke="var(--text-secondary)"
                            fontSize={11}
                            width={80}
                            tick={{ fill: 'var(--text-primary)' }}
                        />
                        <Tooltip
                            contentStyle={{ background: 'var(--chart-tooltip-bg)', border: '1px solid var(--chart-tooltip-border)' }}
                            itemStyle={{ color: 'var(--chart-tooltip-text)' }}
                            cursor={{ fill: 'var(--hover-bg)' }}
                        />
                        <Bar dataKey="importance" radius={[0, 4, 4, 0]}>
                            {data.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
                            ))}
                        </Bar>
                    </BarChart>
                </ResponsiveContainer>
            </div>
        </div>
    )
}

export default FeatureImportanceChart
