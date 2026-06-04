import React, { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  ShieldAlert, 
  Play, 
  Pause, 
  Plus, 
  Trash2, 
  ArrowUp, 
  ArrowDown, 
  Terminal, 
  Activity, 
  AlertTriangle, 
  Globe, 
  Search,
  RefreshCw,
  HelpCircle
} from "lucide-react";
import { 
  DEFAULT_RULES, 
  generateRandomPacket, 
  evaluatePacket, 
  createSiemLog 
} from "./simulationEngine";
import "./App.css";

function App() {
  // --- STATE ---
  const [rules, setRules] = useState(DEFAULT_RULES);
  const [isRunning, setIsRunning] = useState(true);
  const [spawnSpeed, setSpawnSpeed] = useState(1200); // ms between spawns
  const [flyingPackets, setFlyingPackets] = useState([]);
  const [effects, setEffects] = useState([]); // burst and ripple coordinates
  const [logs, setLogs] = useState([]);
  const [logFilter, setLogFilter] = useState("");
  const [isLogPaused, setIsLogPaused] = useState(false);
  const [hoveredPacket, setHoveredPacket] = useState(null);
  
  // Dashboard Metrics
  const [metrics, setMetrics] = useState({
    total: 0,
    allowed: 0,
    blocked: 0,
    threatsBlocked: 0,
    threatsBypassed: 0
  });
  const [protocolCounts, setProtocolCounts] = useState({ TCP: 0, UDP: 0, ICMP: 0 });
  const [severityCounts, setSeverityCounts] = useState({ low: 0, medium: 0, high: 0, critical: 0 });
  const [attackerStats, setAttackerStats] = useState({}); // { ip: blockCount }

  // UI state
  const [showAddRuleModal, setShowAddRuleModal] = useState(false);
  const [shieldActive, setShieldActive] = useState(false);
  const [shakePanel, setShakePanel] = useState(false);
  
  // New Rule Form
  const [newRule, setNewRule] = useState({
    name: "",
    protocol: "TCP",
    srcIp: "*",
    dstIp: "*",
    dstPort: "*",
    action: "ALLOW",
    active: true
  });

  // Refs for background loops
  const requestRef = useRef();
  const previousTimeRef = useRef();
  const spawnTimerRef = useRef();

  // --- LOGGING & STATS PROCESSOR ---
  const handleEvaluatedPacket = (packet, evaluation) => {
    const siemLog = createSiemLog(packet, evaluation);
    
    // 1. Add log (if logs not paused)
    if (!isLogPaused) {
      setLogs((prevLogs) => [siemLog, ...prevLogs].slice(0, 100));
    }

    // 2. Update basic stats
    setMetrics((prev) => {
      const isBlock = evaluation.action === "DENY";
      const isThreat = packet.isThreat;
      
      let threatsBlocked = prev.threatsBlocked;
      let threatsBypassed = prev.threatsBypassed;
      
      if (isThreat) {
        if (isBlock) threatsBlocked += 1;
        else threatsBypassed += 1;
      }

      return {
        total: prev.total + 1,
        allowed: prev.allowed + (isBlock ? 0 : 1),
        blocked: prev.blocked + (isBlock ? 1 : 0),
        threatsBlocked,
        threatsBypassed
      };
    });

    // 3. Update protocol counts
    setProtocolCounts((prev) => ({
      ...prev,
      [packet.protocol]: (prev[packet.protocol] || 0) + 1
    }));

    // 4. Update severity counts
    setSeverityCounts((prev) => ({
      ...prev,
      [siemLog.severity]: (prev[siemLog.severity] || 0) + 1
    }));

    // 5. Update top attackers list if blocked
    if (evaluation.action === "DENY") {
      setAttackerStats((prev) => ({
        ...prev,
        [packet.srcIp]: (prev[packet.srcIp] || 0) + 1
      }));
    }
  };

  // --- ANIMATION STEP LOOP ---
  const animatePackets = (time) => {
    if (previousTimeRef.current !== undefined) {
      // Calculate delta time
      const deltaTime = time - previousTimeRef.current;
      
      setFlyingPackets((prevPackets) => {
        const nextPackets = [];
        
        for (const p of prevPackets) {
          // speed factor scaled by screen width (1.5% of visualizer width per tick approx)
          const nextX = p.x + 0.55; 
          
          if (!p.evaluated && nextX >= 50) {
            // Evaluated when it crosses the 50% threshold (Firewall barrier)
            const evaluation = evaluatePacket(p, rules);
            handleEvaluatedPacket(p, evaluation);
            
            if (evaluation.action === "DENY") {
              // Trigger shield block visual effect
              setShieldActive(true);
              setTimeout(() => setShieldActive(false), 120);
              
              if (p.isThreat) {
                // Shake screen on threat block for premium feedback
                setShakePanel(true);
                setTimeout(() => setShakePanel(false), 200);
              }
              
              // Add burst effect
              addVisualEffect("burst", 50, p.y, p.isThreat);
              
              // Packet does not continue
              continue; 
            } else {
              // Add allow ripple effect
              addVisualEffect("ripple", 50, p.y, false);
            }
            
            nextPackets.push({ ...p, x: nextX, evaluated: true, action: "ALLOW" });
          } else if (nextX >= 100) {
            // Reached destination, vanishes safely
            continue;
          } else {
            nextPackets.push({ ...p, x: nextX });
          }
        }
        return nextPackets;
      });
    }
    
    previousTimeRef.current = time;
    if (isRunning) {
      requestRef.current = requestAnimationFrame(animatePackets);
    }
  };

  // Trigger animation loop
  useEffect(() => {
    if (isRunning) {
      previousTimeRef.current = undefined;
      requestRef.current = requestAnimationFrame(animatePackets);
    }
    return () => cancelAnimationFrame(requestRef.current);
  }, [isRunning, rules, isLogPaused]); // Depend on rules and pause state

  // --- PACKET SPAWNING TIMER ---
  useEffect(() => {
    if (isRunning) {
      spawnTimerRef.current = setInterval(() => {
        const newP = {
          ...generateRandomPacket(false),
          x: 0,
          y: Math.floor(Math.random() * 65) + 15, // Keep within center 15%-80% vertical range
          evaluated: false
        };
        setFlyingPackets((prev) => [...prev, newP]);
      }, spawnSpeed);
    }
    return () => clearInterval(spawnTimerRef.current);
  }, [isRunning, spawnSpeed]);

  // --- ACTION HANDLERS ---
  const handleForceAttack = () => {
    const attackP = {
      ...generateRandomPacket(true), // force standard threats
      x: 0,
      y: Math.floor(Math.random() * 65) + 15,
      evaluated: false
    };
    setFlyingPackets((prev) => [...prev, attackP]);
  };

  const addVisualEffect = (type, x, y, isThreat) => {
    const newEffect = {
      id: Math.random().toString(),
      type,
      x,
      y,
      isThreat
    };
    setEffects((prev) => [...prev, newEffect]);
    setTimeout(() => {
      setEffects((prev) => prev.filter((e) => e.id !== newEffect.id));
    }, 600);
  };

  const toggleRule = (id) => {
    setRules((prevRules) =>
      prevRules.map((r) => (r.id === id ? { ...r, active: !r.active } : r))
    );
  };

  const deleteRule = (id) => {
    setRules((prevRules) => prevRules.filter((r) => r.id !== id));
  };

  const moveRule = (index, direction) => {
    if (direction === "up" && index === 0) return;
    if (direction === "down" && index === rules.length - 1) return;

    const targetIndex = direction === "up" ? index - 1 : index + 1;
    const nextRules = [...rules];
    const temp = nextRules[index];
    nextRules[index] = nextRules[targetIndex];
    nextRules[targetIndex] = temp;
    setRules(nextRules);
  };

  const handleAddRuleSubmit = (e) => {
    e.preventDefault();
    const newId = `rule_${Math.random().toString(36).substring(2, 9)}`;
    const ruleToAdd = {
      ...newRule,
      id: newId,
      dstPort: newRule.dstPort === "" ? "*" : newRule.dstPort
    };

    setRules([ruleToAdd, ...rules]);
    setShowAddRuleModal(false);
    // Reset form
    setNewRule({
      name: "",
      protocol: "TCP",
      srcIp: "*",
      dstIp: "*",
      dstPort: "*",
      action: "ALLOW",
      active: true
    });
  };

  const resetAllStats = () => {
    setMetrics({
      total: 0,
      allowed: 0,
      blocked: 0,
      threatsBlocked: 0,
      threatsBypassed: 0
    });
    setProtocolCounts({ TCP: 0, UDP: 0, ICMP: 0 });
    setSeverityCounts({ low: 0, medium: 0, high: 0, critical: 0 });
    setAttackerStats({});
    setLogs([]);
    setFlyingPackets([]);
  };

  // Filters logs based on search input
  const filteredLogs = logs.filter((log) => {
    const searchString = logFilter.toLowerCase();
    return (
      log.src_ip.toLowerCase().includes(searchString) ||
      log.dest_ip.toLowerCase().includes(searchString) ||
      log.protocol.toLowerCase().includes(searchString) ||
      log.action.toLowerCase().includes(searchString) ||
      (log.threat_signature && log.threat_signature.toLowerCase().includes(searchString)) ||
      log.rule_name.toLowerCase().includes(searchString) ||
      String(log.dest_port).includes(searchString)
    );
  });

  // Calculate SVG Stroke properties for Donut Chart
  const totalProtocols = protocolCounts.TCP + protocolCounts.UDP + protocolCounts.ICMP;
  const tcpPercentage = totalProtocols > 0 ? (protocolCounts.TCP / totalProtocols) * 100 : 0;
  const udpPercentage = totalProtocols > 0 ? (protocolCounts.UDP / totalProtocols) * 100 : 0;
  const icmpPercentage = totalProtocols > 0 ? (protocolCounts.ICMP / totalProtocols) * 100 : 0;

  // Donut SVG constants
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const tcpOffset = circumference;
  const udpOffset = circumference - (tcpPercentage / 100) * circumference;
  const icmpOffset = udpOffset - (udpPercentage / 100) * circumference;

  // Sorted list of top attackers for progress bars
  const sortedAttackers = Object.entries(attackerStats)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);

  const maxAttackBlocks = sortedAttackers.length > 0 ? Math.max(...sortedAttackers.map(a => a[1])) : 1;

  return (
    <div className={`app-container ${shakePanel ? "shake" : ""}`}>
      {/* --- APP HEADER --- */}
      <header className="app-header glass-panel">
        <div className="logo-section">
          <Shield className="logo-icon" size={32} />
          <h1 className="logo-text">
            CYBER-WALL <span className="logo-badge">SIEM Controller</span>
          </h1>
        </div>

        <div className="header-controls">
          <div className={`status-indicator ${isRunning ? "active" : "paused"}`}>
            <span className="status-dot"></span>
            <span>SIMULATION: {isRunning ? "LIVE" : "PAUSED"}</span>
          </div>

          <button 
            className={`btn ${isRunning ? "btn-secondary" : "btn-primary"}`}
            onClick={() => setIsRunning(!isRunning)}
            title={isRunning ? "Pause Traffic" : "Resume Traffic"}
          >
            {isRunning ? <Pause size={16} /> : <Play size={16} />}
            {isRunning ? "Pause" : "Resume"}
          </button>

          <button 
            className="btn btn-danger" 
            onClick={handleForceAttack}
            title="Inject SQLi, XSS or DDoS payload"
          >
            <ShieldAlert size={16} />
            Force Attack
          </button>

          <button 
            className="btn btn-secondary btn-icon-only" 
            onClick={resetAllStats} 
            title="Reset All Metrics & Logs"
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </header>

      {/* --- SIEM METRICS CARDS ROW --- */}
      <section className="stats-row">
        <div className="stat-card glass-panel">
          <span className="stat-label">Total Handled</span>
          <span className="stat-val primary">{metrics.total}</span>
        </div>
        <div className="stat-card glass-panel">
          <span className="stat-label">Passed</span>
          <span className="stat-val success">{metrics.allowed}</span>
        </div>
        <div className="stat-card glass-panel">
          <span className="stat-label">Blocked</span>
          <span className="stat-val danger">{metrics.blocked}</span>
        </div>
        <div className="stat-card glass-panel">
          <span className="stat-label">Bypassed Threat Alerts</span>
          <span className={`stat-val ${metrics.threatsBypassed > 0 ? "danger" : "muted"}`}>
            {metrics.threatsBypassed}
          </span>
        </div>
      </section>

      {/* --- GRID ROW 1: LIVE CANVAS & FIREWALL RULES --- */}
      <div className="dashboard-grid">
        {/* PANEL: PACKET VISUALIZER */}
        <div className="glass-panel">
          <div className="panel-title">
            <Activity size={18} className="logo-icon" />
            Live Packet Visualizer
          </div>
          
          <div className="visualizer-container">
            <div className="visualizer-header-labels">
              <span>WAN (INTERNET)</span>
              <span>FIREWALL FILTER</span>
              <span>LAN (INTERNAL)</span>
            </div>

            <div className="network-zones">
              <div className="zone-label-col">WAN</div>
              <div className="zone-label-col"></div>
              <div className="zone-label-col">LAN</div>
            </div>

            {/* Vertical gridlanes */}
            <div style={{ left: "25%" }} className="network-lane-bg"></div>
            <div style={{ left: "75%" }} className="network-lane-bg"></div>

            {/* Firewall center neon line */}
            <div className={`firewall-barrier ${shieldActive ? "firewall-shield-active" : ""}`}></div>

            {/* Animated Packets */}
            {flyingPackets.map((pkt) => (
              <div
                key={pkt.id}
                className={`packet-node ${pkt.protocol.toLowerCase()} ${pkt.isThreat ? "threat" : ""}`}
                style={{ left: `${pkt.x}%`, top: `${pkt.y}%` }}
                onMouseEnter={() => setHoveredPacket(pkt)}
                onMouseLeave={() => setHoveredPacket(null)}
              >
                {pkt.protocol}
                {pkt.isThreat && (
                  <span className="threat-floating-badge">THREAT</span>
                )}
              </div>
            ))}

            {/* Render Visual Effects */}
            {effects.map((eff) => (
              <div
                key={eff.id}
                className={eff.type === "burst" ? "block-burst" : "allow-ripple"}
                style={{ 
                  left: `${eff.x}%`, 
                  top: `${eff.y}%`,
                  borderColor: eff.isThreat ? "var(--danger)" : undefined 
                }}
              />
            ))}

            {/* Interactive Tooltip */}
            {hoveredPacket && (
              <div 
                className="packet-tooltip"
                style={{ 
                  left: `${hoveredPacket.x + 3}%`, 
                  top: `${hoveredPacket.y - 12}%`,
                  borderColor: hoveredPacket.isThreat ? "var(--danger)" : "var(--primary)"
                }}
              >
                <div style={{ fontWeight: 'bold', color: hoveredPacket.isThreat ? 'var(--danger)' : 'var(--accent-cyan)' }}>
                  {hoveredPacket.isThreat ? "Malicious Packet" : "Standard Traffic"}
                </div>
                <div>IP: {hoveredPacket.srcIp}</div>
                <div>Port: {hoveredPacket.dstPort}</div>
                <div>Protocol: {hoveredPacket.protocol}</div>
                <div>Payload: {hoveredPacket.payload.substring(0, 30)}...</div>
              </div>
            )}
          </div>
          
          <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem', alignItems: 'center' }}>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span>Spawn Frequency:</span>
              <input 
                type="range" 
                min="300" 
                max="3000" 
                step="100" 
                value={spawnSpeed} 
                onChange={(e) => setSpawnSpeed(Number(e.target.value))}
                style={{ accentColor: "var(--primary)" }} 
              />
            </label>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--primary)' }}>
              {(spawnSpeed / 1000).toFixed(1)}s
            </span>
          </div>
        </div>

        {/* PANEL: FIREWALL RULES */}
        <div className="glass-panel">
          <div className="panel-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Shield size={18} className="logo-icon" />
              Access Control List (Rules)
            </div>
            <button 
              className="btn btn-primary" 
              style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
              onClick={() => setShowAddRuleModal(true)}
            >
              <Plus size={12} />
              Add Rule
            </button>
          </div>

          <div className="rules-list">
            {rules.map((rule, idx) => (
              <div key={rule.id} className={`rule-item ${rule.active ? "" : "inactive"}`}>
                <div className="rule-action-badge allow">
                  <span className={`rule-action-badge ${rule.action.toLowerCase()}`}>{rule.action}</span>
                </div>

                <div className="rule-info">
                  <span className="rule-name">{rule.name}</span>
                  <div className="rule-details">
                    <span>Proto: <strong>{rule.protocol}</strong></span>
                    <span>Src: <strong>{rule.srcIp}</strong></span>
                    <span>Dest Port: <strong>{rule.dstPort}</strong></span>
                  </div>
                </div>

                <div className="rule-actions-right">
                  {/* Reordering */}
                  <button 
                    onClick={() => moveRule(idx, "up")} 
                    disabled={idx === 0} 
                    className="btn btn-secondary btn-icon-only"
                    style={{ padding: '0.2rem' }}
                    title="Move rule up (Higher priority)"
                  >
                    <ArrowUp size={12} />
                  </button>
                  <button 
                    onClick={() => moveRule(idx, "down")} 
                    disabled={idx === rules.length - 1} 
                    className="btn btn-secondary btn-icon-only"
                    style={{ padding: '0.2rem' }}
                    title="Move rule down"
                  >
                    <ArrowDown size={12} />
                  </button>

                  {/* Switch */}
                  <label className="switch" title={rule.active ? "Deactivate Rule" : "Activate Rule"}>
                    <input 
                      type="checkbox" 
                      checked={rule.active} 
                      onChange={() => toggleRule(rule.id)} 
                    />
                    <span className="slider"></span>
                  </label>

                  {/* Delete */}
                  <button 
                    onClick={() => deleteRule(rule.id)} 
                    className="btn btn-secondary btn-icon-only"
                    style={{ padding: '0.3rem', color: 'var(--danger)' }}
                    title="Delete Rule"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* --- GRID ROW 2: SIEM TERMINAL & ANALYTICS CHARTS --- */}
      <div className="dashboard-grid">
        {/* PANEL: SIEM EVENT CONSOLE TERMINAL */}
        <div className="glass-panel terminal-card">
          <div className="terminal-header">
            <div className="panel-title" style={{ borderBottom: 'none', paddingBottom: 0, marginBottom: 0 }}>
              <Terminal size={18} className="logo-icon" />
              SIEM Real-Time Event Console
            </div>
            
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <Search size={14} style={{ color: 'var(--text-muted)' }} />
              <input 
                type="text" 
                placeholder="Search SIEM logs..." 
                className="terminal-search" 
                value={logFilter}
                onChange={(e) => setLogFilter(e.target.value)}
              />
              <button 
                className={`btn btn-secondary`} 
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem' }}
                onClick={() => setIsLogPaused(!isLogPaused)}
              >
                {isLogPaused ? "Resume Logs" : "Pause Logs"}
              </button>
              <button 
                className="btn btn-secondary" 
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem' }}
                onClick={() => setLogs([])}
              >
                Clear
              </button>
            </div>
          </div>

          <div className="terminal-console">
            {filteredLogs.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', textAlign: 'center', marginTop: '4rem' }}>
                --- NO EVENT LOGS RECORDED ---
              </div>
            ) : (
              filteredLogs.map((log) => (
                <div key={log.id} className="terminal-line">
                  <span className="log-time">[{log.timestamp.substring(11, 19)}]</span>
                  <span className={`log-badge ${log.action.toLowerCase()}`}>{log.action}</span>
                  <span className={`log-badge sev-${log.severity}`}>sev:{log.severity}</span>
                  <span className="log-msg">
                    Rule <span style={{ color: '#fff' }}>"{log.rule_name}"</span> matched: <span className="protocol">{log.protocol}</span> from <span className="ip">{log.src_ip}</span>:<span className="port">{log.src_port}</span> to <span className="ip">{log.dest_ip}</span>:<span className="port">{log.dest_port}</span>. Size: {log.packet_size}B. 
                    {log.threat_detected ? (
                      <span className="threat"> [SIGNATURE DETECTED: {log.threat_signature}]</span>
                    ) : (
                      <span> Data: "{log.payload.substring(0, 45)}"</span>
                    )}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* PANEL: SIEM ANALYTICS */}
        <div className="glass-panel metrics-card">
          <div className="panel-title">
            <Globe size={18} className="logo-icon" />
            Security Intelligence Analytics
          </div>

          <div className="metrics-content">
            {/* Subchart: Protocol Distribution */}
            <div className="chart-sub-panel">
              <span className="chart-title">Protocol Distribution</span>
              <div className="donut-chart-container">
                <div className="donut-svg-wrapper">
                  <svg className="donut-svg" width="110" height="110" viewBox="0 0 100 100">
                    {/* Background Circle */}
                    <circle cx="50" cy="50" r={radius} fill="transparent" stroke="rgba(255,255,255,0.03)" strokeWidth="12" />
                    
                    {/* TCP Circle */}
                    {tcpPercentage > 0 && (
                      <circle 
                        cx="50" cy="50" r={radius} 
                        fill="transparent" 
                        stroke="var(--primary)" 
                        strokeWidth="12" 
                        strokeDasharray={circumference} 
                        strokeDashoffset={tcpOffset}
                      />
                    )}
                    {/* UDP Circle */}
                    {udpPercentage > 0 && (
                      <circle 
                        cx="50" cy="50" r={radius} 
                        fill="transparent" 
                        stroke="var(--accent-cyan)" 
                        strokeWidth="12" 
                        strokeDasharray={circumference} 
                        strokeDashoffset={udpOffset}
                      />
                    )}
                    {/* ICMP Circle */}
                    {icmpPercentage > 0 && (
                      <circle 
                        cx="50" cy="50" r={radius} 
                        fill="transparent" 
                        stroke="var(--warning)" 
                        strokeWidth="12" 
                        strokeDasharray={circumference} 
                        strokeDashoffset={icmpOffset}
                      />
                    )}
                  </svg>
                  <div className="donut-center-text">
                    <div className="donut-center-val">{totalProtocols}</div>
                    <div className="donut-center-lbl">Packets</div>
                  </div>
                </div>

                <div className="donut-legend">
                  <div className="legend-item">
                    <span className="legend-dot tcp"></span>
                    <span>TCP: {protocolCounts.TCP} ({tcpPercentage.toFixed(0)}%)</span>
                  </div>
                  <div className="legend-item">
                    <span className="legend-dot udp"></span>
                    <span>UDP: {protocolCounts.UDP} ({udpPercentage.toFixed(0)}%)</span>
                  </div>
                  <div className="legend-item">
                    <span className="legend-dot icmp"></span>
                    <span>ICMP: {protocolCounts.ICMP} ({icmpPercentage.toFixed(0)}%)</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Subchart: Top Attackers Blocked */}
            <div className="chart-sub-panel">
              <span className="chart-title">Top Blocked Source IPs</span>
              <div className="bar-chart-container">
                {sortedAttackers.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textAlign: 'center', margin: 'auto 0' }}>
                    No attackers blocked yet.
                  </div>
                ) : (
                  sortedAttackers.map(([ip, count]) => {
                    const fillWidth = (count / maxAttackBlocks) * 100;
                    return (
                      <div className="bar-row" key={ip}>
                        <div className="bar-labels">
                          <span>{ip}</span>
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{count} blocks</span>
                        </div>
                        <div className="bar-track">
                          <div 
                            className="bar-fill danger" 
                            style={{ width: `${fillWidth}%` }}
                          />
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* --- MODAL: ADD RULE FORM --- */}
      {showAddRuleModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3 style={{ fontSize: '1.25rem', fontWeight: 800, marginBottom: '1.25rem', color: '#fff', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '0.5rem' }}>
              Create Firewall Filter Rule
            </h3>
            
            <form onSubmit={handleAddRuleSubmit}>
              <div className="form-group">
                <label>Rule Description / Name</label>
                <input 
                  type="text" 
                  required 
                  placeholder="e.g. Block SQL injection targeting DB" 
                  className="form-input" 
                  value={newRule.name}
                  onChange={(e) => setNewRule({...newRule, name: e.target.value})}
                />
              </div>

              <div className="form-row-2">
                <div className="form-group">
                  <label>Protocol</label>
                  <select 
                    className="form-input"
                    value={newRule.protocol}
                    onChange={(e) => setNewRule({...newRule, protocol: e.target.value})}
                  >
                    <option value="ANY">ANY</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                  </select>
                </div>

                <div className="form-group">
                  <label>Rule Action</label>
                  <select 
                    className="form-input"
                    value={newRule.action}
                    onChange={(e) => setNewRule({...newRule, action: e.target.value})}
                  >
                    <option value="ALLOW">ALLOW</option>
                    <option value="DENY">DENY (DROP)</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label>Source IP Address / CIDR Range</label>
                <input 
                  type="text" 
                  required 
                  placeholder="e.g. * or 198.51.100.0/24 or 192.168.1.15" 
                  className="form-input form-input-mono"
                  value={newRule.srcIp}
                  onChange={(e) => setNewRule({...newRule, srcIp: e.target.value})}
                />
              </div>

              <div className="form-row-2">
                <div className="form-group">
                  <label>Dest IP Address</label>
                  <input 
                    type="text" 
                    required 
                    placeholder="e.g. * or 10.0.0.10" 
                    className="form-input form-input-mono"
                    value={newRule.dstIp}
                    onChange={(e) => setNewRule({...newRule, dstIp: e.target.value})}
                  />
                </div>

                <div className="form-group">
                  <label>Dest Port</label>
                  <input 
                    type="text" 
                    required 
                    placeholder="e.g. * or 80 or 443" 
                    className="form-input form-input-mono"
                    value={newRule.dstPort}
                    onChange={(e) => setNewRule({...newRule, dstPort: e.target.value})}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end', marginTop: '1.75rem' }}>
                <button 
                  type="button" 
                  className="btn btn-secondary"
                  onClick={() => setShowAddRuleModal(false)}
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  className="btn btn-primary"
                >
                  Instantiate Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* --- FOOTER --- */}
      <footer className="app-footer">
        <p>
          Custom Cyber-Wall Shield Engine | SIEM Simulation Framework. Designed for pair-programming demonstration.
        </p>
      </footer>
    </div>
  );
}

export default App;
