import React from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const COLORS = ['#38BDF8', '#F43F5E', '#D29922', '#2EA043', '#8B949E'];

const AttackTypeChart = ({ data }) => {
    return (
        <div className="chart-wrapper">
            <h4 className="chart-title">Attack Type Distribution</h4>
            <ResponsiveContainer>
                <PieChart>
                    <Pie
                        data={data}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        fill="#8884d8"
                        paddingAngle={5}
                        dataKey="value"
                    >
                        {data.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                    </Pie>
                    <Tooltip
                        contentStyle={{ backgroundColor: '#151B23', borderColor: '#30363D', color: '#F0F6FC' }}
                        itemStyle={{ color: '#F0F6FC' }}
                    />
                    <Legend />
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
};

export default AttackTypeChart;
