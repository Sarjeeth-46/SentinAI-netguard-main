import React, { useEffect, useState } from 'react';
import api from '../../api/axiosConfig';
import { Server, Shield, Router, Database, Monitor, Smartphone, AlertTriangle, Maximize2, Minimize2 } from 'lucide-react';

const NetworkTopology = () => {
    const [topology, setTopology] = useState({ nodes: [], links: [] });
    const [selectedNode, setSelectedNode] = useState(null);
    const [loading, setLoading] = useState(true);
    const [isExpanded, setIsExpanded] = useState(false);

    useEffect(() => {
        const fetchTopology = async () => {
            try {
                const res = await api.get('/network/topology');
                setTopology(res.data);
                setLoading(false);
            } catch (err) {
                console.error("Failed to load topology", err);
                setLoading(false);
            }
        };
        fetchTopology();
    }, []);

    // Sync selectedNode with latest topology data to keep details panel live
    useEffect(() => {
        if (selectedNode) {
            const updatedNode = topology.nodes.find(n => n.id === selectedNode.id);
            if (updatedNode) {
                setSelectedNode(updatedNode);
            }
        }
    }, [topology]);

    const getNodeIcon = (type) => {
        switch (type) {
            case 'Firewall': return <Shield size={24} color="var(--accent)" />;
            case 'Router': return <Router size={24} color="var(--warning)" />;
            case 'Switch': return <Server size={24} color="var(--text-secondary)" />;
            case 'Database': return <Database size={24} color="var(--critical)" />;
            case 'Server': return <Server size={24} color="var(--success)" />;
            case 'Client': return <Monitor size={24} color="var(--text-primary)" />;
            default: return <Smartphone size={24} color="var(--text-primary)" />;
        }
    };

    const getStatusColor = (status) => {
        if (status === 'Compromised') return 'var(--critical)';
        if (status === 'Warning') return 'var(--warning)';
        return 'var(--success)'; // Healthy
    };

    if (loading) return <div className="card">Loading Topology...</div>;

    const containerStyle = isExpanded ? {
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        width: '100vw',
        height: '100vh',
        zIndex: 9999,
        background: 'var(--bg-color)', // Corrected from --bg-primary
        padding: '20px',
        display: 'flex',
        gap: '20px',
        boxSizing: 'border-box'
    } : {
        height: '450px',
        display: 'flex',
        gap: '20px',
        position: 'relative' // relative context
    };

    return (
        <div className="card topology-card" style={containerStyle}>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <h2><Router size={20} /> Network Topology</h2>
                    <button
                        onClick={() => setIsExpanded(!isExpanded)}
                        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }}
                        title={isExpanded ? "Exit Fullscreen" : "Fullscreen"}
                    >
                        {isExpanded ? <Minimize2 size={24} /> : <Maximize2 size={20} />}
                    </button>
                </div>
                <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
                    <svg width="100%" height="100%" viewBox="0 0 800 800" preserveAspectRatio="xMidYMid meet">
                        <defs>
                            <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="32" refY="3.5" orient="auto">
                                <polygon points="0 0, 10 3.5, 0 7" fill="var(--border)" />
                            </marker>
                        </defs>
                        {/* Links */}
                        {topology.links.map((link, i) => {
                            const source = topology.nodes.find(n => n.id === link.source);
                            const target = topology.nodes.find(n => n.id === link.target);
                            if (!source || !target) return null;

                            // Ensure numeric coordinates
                            const x1 = Number(source.x) || 400;
                            const y1 = Number(source.y) || 400;
                            const x2 = Number(target.x) || 400;
                            const y2 = Number(target.y) || 400;

                            return (
                                <line
                                    key={i}
                                    x1={x1} y1={y1}
                                    x2={x2} y2={y2}
                                    stroke="var(--border)"
                                    strokeWidth="2"
                                    markerEnd="url(#arrowhead)"
                                />
                            );
                        })}

                        {/* Nodes */}
                        {topology.nodes.map((node) => {
                            const nx = Number(node.x) || 400;
                            const ny = Number(node.y) || 400;
                            const isSelected = selectedNode?.id === node.id;
                            const isCompromised = node.status === 'Compromised';

                            return (
                                <g
                                    key={node.id}
                                    transform={`translate(${nx}, ${ny})`}
                                    onClick={() => setSelectedNode(node)}
                                    style={{ cursor: 'pointer' }}
                                >
                                    {/* Pulse Effect for Compromised Nodes */}
                                    {isCompromised && (
                                        <circle r="30" fill="var(--critical)" opacity="0.3">
                                            <animate attributeName="r" from="25" to="40" dur="1.5s" repeatCount="indefinite" />
                                            <animate attributeName="opacity" from="0.3" to="0" dur="1.5s" repeatCount="indefinite" />
                                        </circle>
                                    )}

                                    {/* Main Node Body */}
                                    <circle
                                        r="25"
                                        fill="var(--card-bg)"
                                        stroke={getStatusColor(node.status)}
                                        strokeWidth={isCompromised ? 3 : 2}
                                    />

                                    {/* Simple Label Icon (Initial Letter) */}
                                    <text dy="5" textAnchor="middle" fill="var(--text-primary)" fontSize="14" fontWeight="bold">
                                        {node.type.charAt(0)}
                                    </text>

                                    {/* Threat Badge */}
                                    {node.threats > 0 && (
                                        <g transform="translate(18, -18)">
                                            <circle r="8" fill="var(--critical)" stroke="var(--card-bg)" strokeWidth="1" />
                                            <text y="3" textAnchor="middle" fontSize="10" fill="white" fontWeight="bold">
                                                {node.threats}
                                            </text>
                                        </g>
                                    )}

                                    {/* Label - Shortened */}
                                    <text
                                        y="40"
                                        textAnchor="middle"
                                        fill="var(--text-secondary)"
                                        fontSize="12"
                                        style={{ userSelect: 'none', pointerEvents: 'none' }}
                                    >
                                        {node.name.split('-').pop()}
                                    </text>

                                    {/* Tooltip for Full Name */}
                                    <title>{node.name} ({node.ip})</title>
                                </g>
                            );
                        })}
                    </svg>
                </div>
                {/* Legend */}
                <div style={{ display: 'flex', gap: '15px', justifyContent: 'center', marginTop: '10px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--success)' }}></div> Healthy</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--warning)' }}></div> Warning</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--critical)' }}></div> Compromised</span>
                </div>
            </div>

            {/* Details Panel */}
            {selectedNode && (
                <div style={{
                    width: '200px',
                    borderLeft: '1px solid var(--border)',
                    paddingLeft: '20px',
                    display: 'flex',
                    flexDirection: 'column',
                    animation: 'slideIn 0.3s ease'
                }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                        <h3 style={{ margin: 0, fontSize: '1rem', color: 'var(--text-primary)' }}>Node Details</h3>
                        <button
                            onClick={() => setSelectedNode(null)}
                            style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
                        >
                            ✕
                        </button>
                    </div>

                    <div style={{ marginBottom: '20px' }}>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>ID</div>
                        <div style={{ fontWeight: 600 }}>{selectedNode.id}</div>
                    </div>

                    <div style={{ marginBottom: '20px' }}>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>IP Address</div>
                        <div style={{ fontFamily: 'monospace', background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: '4px', display: 'inline-block' }}>
                            {selectedNode.ip}
                        </div>
                    </div>

                    <div style={{ marginBottom: '20px' }}>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Status</div>
                        <div style={{
                            color: getStatusColor(selectedNode.status),
                            fontWeight: 600,
                            display: 'flex', alignItems: 'center', gap: '6px'
                        }}>
                            {selectedNode.status === 'Compromised' && <AlertTriangle size={14} />}
                            {selectedNode.status}
                        </div>
                    </div>

                    {selectedNode.threats > 0 && (
                        <div style={{
                            padding: '10px',
                            background: 'rgba(244, 63, 94, 0.1)',
                            border: '1px solid var(--critical)',
                            borderRadius: '8px'
                        }}>
                            <div style={{ fontSize: '0.75rem', color: 'var(--critical)', fontWeight: 600, marginBottom: '4px' }}>
                                Active Threat
                            </div>
                            <div style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                                {selectedNode.latest_threat}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default NetworkTopology;
