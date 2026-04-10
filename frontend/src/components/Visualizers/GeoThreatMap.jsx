import React, { useMemo } from 'react';
import { ComposableMap, Geographies, Geography } from 'react-simple-maps';
import { scaleLinear } from 'd3-scale';
import { Globe } from 'lucide-react';

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

const ThreatMap = ({ theme, threats = [] }) => {
    // Aggregation: Count threats by country
    // Aggregation: Count threats by country
    const data = React.useMemo(() => {
        const counts = {};
        threats.forEach(t => {
            const country = t.source_country || (t.metadata && t.metadata.source_country) || 'UNK';
            counts[country] = (counts[country] || 0) + 1;
        });
        return Object.keys(counts).map(k => ({ id: k, value: counts[k] }));
    }, [threats]);
    // ISO Alpha-3 and Alpha-2 to Numeric Mapping for world-atlas
    const isoMap = {
        "USA": "840", "US": "840", "CHN": "156", "CN": "156",
        "RUS": "643", "RU": "643", "BRA": "076", "BR": "076",
        "IND": "356", "IN": "356", "DEU": "276", "DE": "276",
        "GBR": "826", "GB": "826", "FRA": "250", "FR": "250",
        "JPN": "392", "JP": "392", "KOR": "410", "KR": "410",
        "CAN": "124", "CA": "124", "AUS": "036", "AU": "036"
    };

    const maxValue = Math.max(...data.map(d => d.value), 1); // Ensure min is 1 to avoid NaN domain if empty

    // Theme Colors
    const isDark = theme === 'dark';
    const baseColor = "var(--bg-elevated)";
    const hoverColor = "var(--accent-primary)";
    const strokeColor = "var(--border-subtle)";
    const emptyColor = "var(--bg-surface)";

    // Debugging: Log data to see if we have matches
    // console.log("Geo Data:", data);

    const colorScale = scaleLinear()
        .domain([0, maxValue])
        .range([emptyColor, "var(--status-danger)"]);

    return (
        <div className="card" style={{ minHeight: '400px', display: 'flex', flexDirection: 'column' }}>
            <h2><Globe size={20} color="var(--accent-primary)" style={{ marginRight: '8px' }} /> Global Threat Origins</h2>
            <div style={{ flex: 1, position: 'relative' }}>
                <ComposableMap
                    projection="geoMercator"
                    projectionConfig={{ scale: 120, center: [0, 30] }}
                    style={{ width: "100%", height: "100%" }}
                >
                    <Geographies geography={geoUrl}>
                        {({ geographies }) =>
                            geographies.map((geo) => {
                                // Match by Numeric Code (geo.id) or try mapped Alpha-3
                                const d = data.find((s) => {
                                    const mappedId = isoMap[s.id] || s.id;
                                    return mappedId === geo.id;
                                });
                                return (
                                    <Geography
                                        key={geo.rsmKey}
                                        geography={geo}
                                        fill={d ? colorScale(d.value) : baseColor}
                                        stroke={strokeColor}
                                        strokeWidth={0.5}
                                        style={{
                                            default: { outline: "none", transition: "all 0.3s" },
                                            hover: { fill: hoverColor, outline: "none", cursor: 'pointer' },
                                            pressed: { outline: "none" },
                                        }}
                                        title={d ? `${geo.properties.name}: ${d.value} Threats` : geo.properties.name}
                                    />
                                );
                            })
                        }
                    </Geographies>
                </ComposableMap>

                {/* Legend */}
                <div style={{
                    position: 'absolute',
                    bottom: 20,
                    left: 20,
                    background: 'var(--bg-surface)',
                    padding: '10px',
                    borderRadius: '8px',
                    border: '1px solid var(--border-subtle)',
                    boxShadow: '0 4px 6px rgba(0,0,0,0.1)'
                }}>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '5px' }}>Threat Intensity</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                        <div style={{ width: '10px', height: '10px', background: baseColor }}></div>
                        <span style={{ fontSize: '10px', color: 'var(--text-primary)' }}>Low</span>
                        <div style={{ width: '40px', height: '4px', background: `linear-gradient(to right, ${baseColor}, var(--status-danger))` }}></div>
                        <span style={{ fontSize: '10px', color: 'var(--text-primary)' }}>High</span>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ThreatMap;
