/**
 * Project: SentinAI NetGuard
 * Module: Security Dashboard Hook
 * Description: A custom React Hook that acts as the Presentation Layer Controller.
 *              Manages polling synchronization, state aggregation, and interaction logic
 *              for the Security Operation Center (SOC) Dashboard.
 *
 *  ⚠️  Single-source-of-truth rule:
 *      ALL dashboard metrics (KPI cards, risk bar chart, attack chart, trend)
 *      are derived from ONE fetch to /api/dashboard/overview.
 *      No secondary fetches for dashboard data are permitted.
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import api from '../api/axiosConfig';

// ----------------------------------------------------------
// Helper: convert risk_levels object → [{name, value}] array
// Keys are lower-case in the API; display as Title-case.
// ----------------------------------------------------------
const LABEL_MAP = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

function riskLevelsToStats(risk_levels = {}) {
    return Object.entries(LABEL_MAP).map(([key, label]) => ({
        name:  label,
        value: risk_levels[key] ?? 0,
    }));
}

function attackDistToArray(attack_type_distribution = {}) {
    return Object.entries(attack_type_distribution).map(([name, value]) => ({ name, value }));
}

export const useSecurityDashboard = (isAuthenticated, dateFilter = null) => {
    // ── Core dashboard state ─────────────────────────────────────────────────
    const [totalThreats,  setTotalThreats]  = useState(0);      // KPI: Total Threats
    const [highRiskCount, setHighRiskCount] = useState(0);      // KPI: High Risk
    const [riskStats,     setRiskStats]     = useState([]);     // Bar chart data
    const [attackTypes,   setAttackTypes]   = useState([]);     // Attack donut data
    const [trendData,     setTrendData]     = useState([]);     // Severity trend line

    // ── Secondary state (not part of unified overview) ───────────────────────
    const [threats,        setThreats]       = useState([]);    // Full threat table
    const [metrics,        setMetrics]       = useState(null);
    const [features,       setFeatures]      = useState([]);
    const [criticalAlerts, setCriticalAlerts]= useState([]);

    // ── UI state ─────────────────────────────────────────────────────────────
    const [loading, setLoading] = useState(true);
    const [alert,   setAlert]   = useState(null);
    const [wsStatus, setWsStatus] = useState('CONNECTING'); // WS Health metric

    const isMounted = useRef(true);
    // Keep a ref so the WebSocket closure always reads the *current* dateFilter
    // without needing to be recreated every time the filter changes.
    const dateFilterRef = useRef(dateFilter);
    useEffect(() => { dateFilterRef.current = dateFilter; }, [dateFilter]);

    // ────────────────────────────────────────────────────────────────────────
    // Core sync function — ONE endpoint, all widgets
    // ────────────────────────────────────────────────────────────────────────
    const synchronizeTelemetry = useCallback(async (abortSignal) => {
        try {
            // ── Step 1: Fetch unified overview (single source of truth for KPIs) ──
            const overviewRes = await api.get('/dashboard/overview', { signal: abortSignal });
            const overview = overviewRes.data || {};

            const {
                total_threats            = 0,
                risk_levels              = {},
                attack_type_distribution = {},
                traffic_severity_trend   = [],
            } = overview;

            if (!isMounted.current) return;

            // FIX: Use local date (not UTC) for the isToday comparison.
            // new Date().toISOString() gives UTC date, which can be a day behind in IST (+05:30).
            // new Date().toLocaleDateString('en-CA') gives the local YYYY-MM-DD string.
            const todayLocal = new Date().toLocaleDateString('en-CA'); // 'en-CA' = YYYY-MM-DD format
            const isToday    = !dateFilter || dateFilter === todayLocal;

            if (isToday) {
                // KPI cards and chart data — always from the live overview
                setTotalThreats(total_threats);
                setHighRiskCount(risk_levels.critical ?? 0);
                setRiskStats(riskLevelsToStats(risk_levels));
                setAttackTypes(attackDistToArray(attack_type_distribution));
                setTrendData(traffic_severity_trend);
            }

            // ── Step 2: Fetch the threat table ────────────────────────────────────
            // This ALWAYS runs on mount/refresh regardless of date filter so the
            // table is never empty after a page refresh.
            if (isToday) {
                // Today: fetch all recent threats (no date filter) — gets live data
                try {
                    const threatsRes = await api.get('/threats', { signal: abortSignal });
                    const threatList = threatsRes.data || [];
                    if (!isMounted.current) return;
                    setThreats(threatList);
                    setCriticalAlerts(threatList.filter(t => t.risk_score >= 80).slice(0, 5));
                } catch (err) {
                    if (err.name === 'CanceledError' || err.name === 'AbortError') return;
                    console.warn('[Dashboard] Threat table fetch failed', err.message);
                }
            } else {
                // ── Step 3: Historical date filter ───────────────────────────────
                // The dateFilter is a local calendar date (YYYY-MM-DD).
                // Build UTC boundaries that cover the full local day:
                //   local 00:00 IST (+05:30) = previous-day 18:30 UTC
                //   local 23:59 IST (+05:30) = same-day     18:29 UTC
                // Using Date constructor with a bare "YYYY-MM-DD" string gives
                // midnight LOCAL time, which we then convert to UTC for the query.
                if (!/^\d{4}-\d{2}-\d{2}$/.test(dateFilter)) {
                    console.log(`[Dashboard] Ignoring incomplete date filter: ${dateFilter}`);
                    return;
                }
                console.log(`[Dashboard] Applying date filter for: ${dateFilter}`);

                // Midnight local time on the selected day
                const startLocal = new Date(`${dateFilter}T00:00:00`);
                const endLocal   = new Date(`${dateFilter}T23:59:59`);
                const start = startLocal.toISOString().replace('T', ' ').replace('Z', '+00:00');
                const end   = endLocal.toISOString().replace('T', ' ').replace('Z', '+00:00');

                try {
                    const filteredRes = await api.get('/threats', {
                        params: { start_time: start, end_time: end },
                        signal: abortSignal,
                    });
                    const filteredThreats = filteredRes.data || [];
                    if (!isMounted.current) return;
                    setThreats(filteredThreats);
                    setCriticalAlerts(filteredThreats.filter(t => t.risk_score >= 80));

                    // Re-compute KPIs from filtered data for historical view
                    const riskCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
                    const typeCounts = {};

                    filteredThreats.forEach(t => {
                        const score = t.risk_score ?? 0;
                        if      (score >= 80) riskCounts.Critical++;
                        else if (score >= 60) riskCounts.High++;
                        else if (score >= 30) riskCounts.Medium++;
                        else                  riskCounts.Low++;

                        const label = t.predicted_label || t.label || 'Unknown';
                        typeCounts[label] = (typeCounts[label] || 0) + 1;
                    });

                    setTotalThreats(filteredThreats.length);
                    setHighRiskCount(riskCounts.Critical);
                    setRiskStats(Object.entries(riskCounts).map(([name, value]) => ({ name, value })));
                    setAttackTypes(Object.entries(typeCounts).map(([name, value]) => ({ name, value })));

                    const sorted = [...filteredThreats].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
                    setTrendData(sorted.slice(-60).map(t => ({
                        timestamp: t.timestamp,
                        risk_score: t.risk_score || 0,
                    })));
                } catch (e) {
                    if (e.name === 'CanceledError' || e.name === 'AbortError') return;
                    console.error('[Dashboard] Filtered fetch failed', e);
                    setAlert({ type: 'error', message: `Filter failed: ${e.response?.data?.detail || e.message}` });
                }
            }

            // ── Step 4: ML artifacts ──────────────────────────────────────────────
            try {
                const [metricsRes, featuresRes] = await Promise.all([
                    api.get('/model/metrics', { signal: abortSignal }),
                    api.get('/model/features', { signal: abortSignal }),
                ]);
                if (!isMounted.current) return;
                setMetrics(metricsRes.data);
                setFeatures(featuresRes.data);
            } catch (e) {
                if (e.name !== 'CanceledError' && e.name !== 'AbortError') {
                    console.warn('[Dashboard] ML artifacts fetch failed', e.message);
                }
            }

            setLoading(false);
        } catch (error) {
            if (error.name === 'CanceledError' || error.name === 'AbortError') return;
            console.error('[Dashboard] Telemetry Sync Failure:', error);
            setAlert({ type: 'error', message: 'Connection lost. Retrying...' });
        } finally {
            setLoading(false);
        }
    }, [dateFilter]);

    // ── Action handlers ───────────────────────────────────────────────────────
    const resolveThreat = useCallback(async (id) => {
        try {
            await api.post(`/threats/${id}/resolve`);
            setThreats(prev => prev.map(t => t.id === id ? { ...t, status: 'Resolved' } : t));
            setCriticalAlerts(prev => prev.filter(t => t.id !== id));
            setAlert({ type: 'success', message: 'Incident marked as resolved.' });
        } catch (err) {
            console.error('Resolution Failed:', err);
            setAlert({ type: 'error', message: 'Failed to resolve threat.' });
        }
    }, []);

    const blockIP = useCallback(async (id, ip) => {
        try {
            await api.post(`/threats/${id}/block`);
            setAlert({ type: 'success', message: `IP ${ip} blocked successfully.` });
        } catch (err) {
            setAlert({ type: 'error', message: 'Block action failed.' });
        }
    }, []);

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    useEffect(() => {
        if (!isAuthenticated) return;

        isMounted.current = true;
        const controller = new AbortController();
        synchronizeTelemetry(controller.signal);

        // ── WebSocket: real-time optimistic updates ────────────────────────
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl    = `${protocol}//${window.location.host}/ws/dashboard`;
        const socket   = new WebSocket(wsUrl);

        socket.onopen = () => {
            console.log('[Dashboard] WebSocket Connected');
            setWsStatus('CONNECTED');
        };

        socket.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                // Handle both independent alerts AND correlated alerts from correlation engine
                if (message.type === 'THREAT_DETECTED' || message.type === 'CRITICAL_ALERT') {
                    const threat = message.data;
                    const activeFilter = dateFilterRef.current;
                    const threatLabel  = threat.predicted_label || threat.label || 'Unknown';

                    // Skip benign / Normal traffic — not a real threat alert
                    if (threatLabel === 'Normal') return;

                    // When a date filter is active, check if this event belongs to that date.
                    // If it does not match the filter date, skip all table/KPI updates.
                    if (activeFilter) {
                        let eventDateUtc = null;
                        try {
                            if (threat.timestamp) {
                                eventDateUtc = new Date(threat.timestamp).toISOString().slice(0, 10);
                            }
                        } catch (e) {
                            console.warn("Invalid timestamp received via WS:", threat.timestamp);
                        }
                        if (eventDateUtc && eventDateUtc !== activeFilter) {
                            return;
                        }
                    }

                    // Optimistically update threat table & list only (KPIs handled by SYSTEM_STATUS stream now)
                    setThreats(prev => {
                        if (prev.some(t => t.id === threat.id)) return prev;
                        return [threat, ...prev].slice(0, 500);
                    }); // Cap at 100 for memory safety

                    if (threat.risk_score >= 80) {
                        setCriticalAlerts(prev => {
                            if (prev.some(t => t.id === threat.id)) return prev;
                            return [threat, ...prev].slice(0, 5);
                        });
                    }

                    // Show alert toast for confirmed real attack events
                    setAlert({
                        type:    threat.risk_score >= 80 ? 'critical' : 'warning',
                        message: `Active Threat Detected: ${threatLabel} from ${threat.source_ip}`,
                    });
                } else if (message.type === 'SYSTEM_STATUS') {
                    // Live KPI stream — only apply when viewing today, not a historical date.
                    // FIX: use local date (same as synchronizeTelemetry) not UTC date.
                    const todayLocal = new Date().toLocaleDateString('en-CA');
                    if (dateFilterRef.current && dateFilterRef.current !== todayLocal) return;

                    const overview = message.payload || {};
                    const { total_threats = 0, risk_levels = {}, attack_type_distribution = {}, traffic_severity_trend = [] } = overview;

                    setTotalThreats(total_threats);
                    setHighRiskCount(risk_levels.critical ?? 0);
                    setRiskStats(riskLevelsToStats(risk_levels));
                    setAttackTypes(attackDistToArray(attack_type_distribution));
                    setTrendData(traffic_severity_trend);
                }
            } catch (err) {
                console.error('WS Message Error', err);
            }
        };

        socket.onclose = () => {
            console.log('[Dashboard] WebSocket Disconnected.');
            setWsStatus('DISCONNECTED');
        };

        socket.onerror = () => {
             setWsStatus('ERROR');
        };

        // We can safely remove the 30s poll timer since WS `SYSTEM_STATUS` pushes every 2 seconds.
        // If a drop occurs, users can manually refresh, or we can implement auto-reconnect logic (out of scope for quick fix).
        return () => {
            isMounted.current = false;
            controller.abort();
            socket.close();
        };
    }, [isAuthenticated, dateFilter, synchronizeTelemetry]);

    // ── Database Status ──────────────────────────────────────────────────────────
    const [dbStatus, setDbStatus] = useState('connecting...');

    useEffect(() => {
        const fetchDbStatus = () => {
            api.get('/system/db-status')
               .then(r => setDbStatus(r.data.status))
               .catch(() => setDbStatus('disconnected'));
        };
        fetchDbStatus();
        const interval = setInterval(fetchDbStatus, 5000);
        return () => clearInterval(interval);
    }, []);

    return {
        threats,
        totalThreats,   // KPI: Total Threats  ← derived from API, not threats.length
        riskStats,
        metrics,
        features,
        attackTypes,
        trendData,
        criticalAlerts,
        loading,
        highRiskCount,
        alert,
        wsStatus,
        setAlert,
        actions: {
            resolveThreat,
            blockIP,
            dbStatus,
        },
    };
};
