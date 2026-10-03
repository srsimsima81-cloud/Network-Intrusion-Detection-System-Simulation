import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
  CartesianGrid,
  AreaChart,
  Area,
} from "recharts";

import "./styles.css";

const API = "http://localhost:8000/api";

const get = async (path) => {
  const response = await fetch(API + path);

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }

  return response.json();
};

/* =========================================================
   FORM COMPONENTS
========================================================= */

function Field({ label, children }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}

function TextField({ label, ...props }) {
  return (
    <Field label={label}>
      <input {...props} />
    </Field>
  );
}

/* =========================================================
   COLORS
========================================================= */

const severityColors = {
  INFO: "#25d9ff",
  LOW: "#4d7cff",
  MEDIUM: "#ffd166",
  HIGH: "#ff9f43",
  CRITICAL: "#ff5268",
};

const protocolColors = {
  TCP: "#25d9ff",
  UDP: "#a970ff",
  ICMP: "#39e6a5",
};

const riskColor = (score) => {
  if (score >= 81) return "#ff5268";
  if (score >= 61) return "#ff9f43";
  if (score >= 41) return "#ffd166";
  if (score >= 21) return "#4d7cff";
  return "#39e6a5";
};

/* =========================================================
   CUSTOM TOOLTIP
========================================================= */

function RiskTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null;

  const value = payload[0]?.value ?? 0;

  return (
    <div className="chart-tooltip">
      <div className="tooltip-title">{label}</div>

      <div className="tooltip-value">
        <span
          className="tooltip-dot"
          style={{ background: riskColor(value) }}
        />

        Risk Score

        <strong>{value}</strong>
      </div>
    </div>
  );
}

function SecurityTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null;

  return (
    <div className="chart-tooltip">
      <div className="tooltip-title">{label}</div>

      {payload.map((item, index) => (
        <div className="tooltip-row" key={index}>
          <span
            className="tooltip-dot"
            style={{
              background:
                severityColors[item.name] ||
                protocolColors[item.name] ||
                "#25d9ff",
            }}
          />

          {item.name}

          <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  );
}

/* =========================================================
   SEVERITY BADGE
========================================================= */

function SeverityBadge({ value }) {
  const color = severityColors[value] || "#8196ad";

  return (
    <span
      className="severity-badge"
      style={{
        color,
        borderColor: `${color}55`,
        background: `${color}12`,
      }}
    >
      <span
        className="severity-dot"
        style={{ background: color, boxShadow: `0 0 10px ${color}` }}
      />

      {value || "UNKNOWN"}
    </span>
  );
}

/* =========================================================
   STATUS BADGE
========================================================= */

function StatusBadge({ value }) {
  const colors = {
    NEW: "#25d9ff",
    INVESTIGATING: "#ffd166",
    RESOLVED: "#39e6a5",
    FALSE_POSITIVE: "#8196ad",
  };

  const color = colors[value] || "#8196ad";

  return (
    <span
      className="status-badge"
      style={{
        color,
        borderColor: `${color}55`,
        background: `${color}12`,
      }}
    >
      {value}
    </span>
  );
}

/* =========================================================
   DASHBOARD
========================================================= */

function Dashboard() {
  const [stats, setStats] = useState({});
  const [traffic, setTraffic] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [a, setA] = useState({});

  const [severity, setSeverity] = useState("");
  const [protocol, setProtocol] = useState("");
  const [status, setStatus] = useState("");
  const [type, setType] = useState("");

  const [error, setError] = useState("");

  async function load() {
    try {
      setError("");

      const [
        statsData,
        trafficData,
        dashboardAlerts,
      ] = await Promise.all([
        get("/dashboard/stats"),
        get("/dashboard/traffic"),
        get("/dashboard/alerts"),
      ]);

      setStats(statsData);
      setTraffic(trafficData);
      setA(dashboardAlerts);

      const q = new URLSearchParams();

      if (severity) q.set("severity", severity);
      if (protocol) q.set("protocol", protocol);
      if (status) q.set("status", status);
      if (type) q.set("alert_type", type);

      setAlerts(await get("/alerts?" + q.toString()));
    } catch (err) {
      console.error(err);
      setError(
        "Unable to connect to the IDS backend. Make sure FastAPI is running."
      );
    }
  }

  useEffect(() => {
    load();

    const id = setInterval(load, 3000);

    return () => clearInterval(id);
  }, [severity, protocol, status, type]);

  const statCards = [
    {
      label: "Total Network Flows",
      key: "total_flows",
      icon: "◈",
      className: "cyan",
    },
    {
      label: "Normal Traffic",
      key: "normal_flows",
      icon: "✓",
      className: "green",
    },
    {
      label: "Suspicious Traffic",
      key: "suspicious_flows",
      icon: "⚠",
      className: "orange",
    },
    {
      label: "Open Alerts",
      key: "open_alerts",
      icon: "!",
      className: "yellow",
    },
    {
      label: "Critical Alerts",
      key: "critical_alerts",
      icon: "◆",
      className: "red",
    },
    {
      label: "Average Risk Score",
      key: "average_risk_score",
      icon: "◎",
      className: "purple",
    },
  ];

  return (
    <main>
      {/* HEADER */}

      <div className="dashboard-header">
        <div>
          <div className="eyebrow">
            <span className="live-dot" />
            LIVE SECURITY MONITORING
          </div>

          <h1>Network IDS</h1>

          <p className="muted">
            SOC dashboard for synthetic network-flow detection and
            security-event analysis.
          </p>
        </div>

        <div className="monitor-status">
          <span className="pulse-ring" />
          <span>SIMULATION ACTIVE</span>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          <strong>Backend connection error</strong>
          <span>{error}</span>
        </div>
      )}

      {/* STAT CARDS */}

      <div className="cards">
        {statCards.map((item) => (
          <article
            className={`card stat-card ${item.className}`}
            key={item.key}
          >
            <div className="stat-top">
              <span>{item.label}</span>
              <span className="stat-icon">{item.icon}</span>
            </div>

            <b>{stats[item.key] ?? 0}</b>

            <div className="stat-line" />
          </article>
        ))}
      </div>

      {/* RISK TIMELINE */}

      <section className="panel chart-panel large-chart">
        <div className="panel-header">
          <div>
            <div className="panel-kicker">THREAT MONITOR</div>
            <h2>Risk Timeline</h2>
          </div>

          <div className="chart-live">
            <span />
            Updating every 3s
          </div>
        </div>

        <ResponsiveContainer width="100%" height={320}>
          <AreaChart data={traffic}>
            <defs>
              <linearGradient
                id="riskGradient"
                x1="0"
                y1="0"
                x2="0"
                y2="1"
              >
                <stop
                  offset="0%"
                  stopColor="#25d9ff"
                  stopOpacity={0.32}
                />

                <stop
                  offset="100%"
                  stopColor="#25d9ff"
                  stopOpacity={0}
                />
              </linearGradient>
            </defs>

            <CartesianGrid
              stroke="rgba(100,140,170,0.10)"
              vertical={false}
            />

            <XAxis
              dataKey="timestamp"
              tick={{ fill: "#71869c", fontSize: 10 }}
              axisLine={false}
              tickLine={false}
            />

            <YAxis
              domain={[0, 100]}
              tick={{ fill: "#71869c", fontSize: 10 }}
              axisLine={false}
              tickLine={false}
            />

            <Tooltip content={<RiskTooltip />} />

            <Area
              type="monotone"
              dataKey="risk_score"
              stroke="#25d9ff"
              strokeWidth={3}
              fill="url(#riskGradient)"
              dot={false}
              activeDot={{
                r: 6,
                fill: "#25d9ff",
                stroke: "#06101c",
                strokeWidth: 3,
              }}
              animationDuration={700}
            />
          </AreaChart>
        </ResponsiveContainer>
      </section>

      {/* CHARTS */}

      <div className="grid">
        {/* SEVERITY */}

        <section className="panel chart-panel">
          <div className="panel-header">
            <div>
              <div className="panel-kicker">ALERT ANALYTICS</div>
              <h2>Alerts by Severity</h2>
            </div>

            <span className="panel-icon">▥</span>
          </div>

          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={a.severity || []}>
              <defs>
                <linearGradient
                  id="severityGradient"
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop
                    offset="0%"
                    stopColor="#ff5268"
                    stopOpacity={1}
                  />
                  <stop
                    offset="100%"
                    stopColor="#ff9f43"
                    stopOpacity={0.45}
                  />
                </linearGradient>
              </defs>

              <CartesianGrid
                stroke="rgba(100,140,170,0.09)"
                vertical={false}
              />

              <XAxis
                dataKey="name"
                tick={{ fill: "#8196ad", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />

              <YAxis
                allowDecimals={false}
                tick={{ fill: "#8196ad", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />

              <Tooltip content={<SecurityTooltip />} />

              <Bar
                dataKey="value"
                name="Alerts"
                radius={[6, 6, 0, 0]}
                fill="url(#severityGradient)"
                animationDuration={700}
              />
            </BarChart>
          </ResponsiveContainer>
        </section>

        {/* PROTOCOL */}

        <section className="panel chart-panel">
          <div className="panel-header">
            <div>
              <div className="panel-kicker">NETWORK ANALYTICS</div>
              <h2>Protocol Distribution</h2>
            </div>

            <span className="panel-icon">◉</span>
          </div>

          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={a.protocols || []}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={65}
                outerRadius={105}
                paddingAngle={4}
                labelLine={false}
                label={({ name, percent }) =>
                  `${name} ${(percent * 100).toFixed(0)}%`
                }
                animationDuration={800}
              >
                {(a.protocols || []).map((entry, i) => (
                  <Cell
                    key={i}
                    fill={
                      protocolColors[entry.name] ||
                      ["#25d9ff", "#a970ff", "#39e6a5"][i % 3]
                    }
                    stroke="#07111f"
                    strokeWidth={3}
                  />
                ))}
              </Pie>

              <Tooltip content={<SecurityTooltip />} />

              <Legend
                verticalAlign="bottom"
                iconType="circle"
                wrapperStyle={{
                  color: "#8196ad",
                  fontSize: "11px",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </section>
      </div>

      {/* ALERT TABLE */}

      <section className="panel alerts-panel">
        <div className="panel-header">
          <div>
            <div className="panel-kicker">SOC QUEUE</div>
            <h2>Recent Alerts</h2>
          </div>

          <div className="alert-count">
            {alerts.length} displayed
          </div>
        </div>

        <div className="filters">
          <Field label="Severity">
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">All severities</option>

              {[
                "INFO",
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
              ].map((x) => (
                <option key={x}>{x}</option>
              ))}
            </select>
          </Field>

          <Field label="Protocol">
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
            >
              <option value="">All protocols</option>

              {["TCP", "UDP", "ICMP"].map((x) => (
                <option key={x}>{x}</option>
              ))}
            </select>
          </Field>

          <Field label="Alert status">
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="">All statuses</option>

              {[
                "NEW",
                "INVESTIGATING",
                "RESOLVED",
                "FALSE_POSITIVE",
              ].map((x) => (
                <option key={x}>{x}</option>
              ))}
            </select>
          </Field>

          <Field label="Alert type">
            <select
              value={type}
              onChange={(e) => setType(e.target.value)}
            >
              <option value="">All alert types</option>

              {(a.alert_types || []).map((x) => (
                <option key={x.name}>{x.name}</option>
              ))}
            </select>
          </Field>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Alert</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Status</th>
              </tr>
            </thead>

            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan="8" className="empty-state">
                    <div className="empty-icon">✓</div>
                    <strong>No alerts found</strong>
                    <span>
                      No security events match the current filters.
                    </span>
                  </td>
                </tr>
              ) : (
                alerts.map((x) => (
                  <tr key={x.alert_id}>
                    <td>
                      {new Date(x.created_at).toLocaleTimeString()}
                    </td>

                    <td>
                      <code>{x.source_ip}</code>
                    </td>

                    <td>
                      <code>{x.destination_ip}</code>
                    </td>

                    <td>
                      <span className="protocol-tag">
                        {x.protocol}
                      </span>
                    </td>

                    <td className="alert-name">
                      {x.alert_type}
                    </td>

                    <td>
                      <SeverityBadge value={x.severity} />
                    </td>

                    <td>
                      <span
                        className="risk-value"
                        style={{ color: riskColor(x.risk_score) }}
                      >
                        {x.risk_score}
                      </span>
                    </td>

                    <td>
                      <StatusBadge value={x.status} />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}

/* =========================================================
   INVESTIGATION
========================================================= */

function Investigation() {
  const [id, setId] = useState("");
  const [data, setData] = useState(null);
  const [note, setNote] = useState("");
  const [resolution, setResolution] = useState("");
  const [error, setError] = useState("");

  async function load() {
    if (!id) return;

    try {
      setError("");

      const result = await get("/alerts/" + id);

      setData(result);
    } catch (err) {
      console.error(err);
      setError("Alert could not be loaded.");
      setData(null);
    }
  }

  async function update(status) {
    if (!id) return;

    await fetch(API + "/alerts/" + id + "/status", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        status,
        resolution_notes: resolution || null,
      }),
    });

    load();
  }

  async function addNote() {
    if (!id || !note.trim()) return;

    await fetch(API + "/alerts/" + id + "/notes", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        note,
      }),
    });

    setNote("");

    load();
  }

  return (
    <main>
      <div className="dashboard-header">
        <div>
          <div className="eyebrow">
            <span className="live-dot" />
            SOC INVESTIGATION
          </div>

          <h1>Alert Investigation</h1>

          <p className="muted">
            Review detection evidence, record analyst notes,
            and manage the alert lifecycle.
          </p>
        </div>
      </div>

      <section className="panel investigation-search">
        <div className="panel-kicker">ALERT LOOKUP</div>

        <div className="filters">
          <TextField
            label="Alert ID"
            value={id}
            onChange={(e) => setId(e.target.value)}
            placeholder="ALT-..."
          />

          <button className="primary-button" onClick={load}>
            Load Alert
          </button>
        </div>

        {error && (
          <div className="error-banner">
            {error}
          </div>
        )}
      </section>

      {data && (
        <>
          <section className="investigation-grid">
            <div className="panel">
              <div className="panel-kicker">
                DETECTION EVENT
              </div>

              <h2>{data.alert.alert_type}</h2>

              <div className="evidence-grid">
                <div>
                  <span>Alert ID</span>
                  <strong>{data.alert.alert_id}</strong>
                </div>

                <div>
                  <span>Timestamp</span>
                  <strong>{data.alert.created_at}</strong>
                </div>

                <div>
                  <span>Source</span>
                  <strong>
                    {data.alert.source_ip}:
                    {data.alert.source_port}
                  </strong>
                </div>

                <div>
                  <span>Destination</span>
                  <strong>
                    {data.alert.destination_ip}:
                    {data.alert.destination_port}
                  </strong>
                </div>

                <div>
                  <span>Protocol</span>
                  <strong>{data.alert.protocol}</strong>
                </div>

                <div>
                  <span>Matched Rule</span>
                  <strong>{data.alert.rule_id}</strong>
                </div>
              </div>
            </div>

            <div
              className="panel risk-panel"
              style={{
                "--risk-color": riskColor(
                  data.alert.risk_score
                ),
              }}
            >
              <div className="panel-kicker">
                THREAT ASSESSMENT
              </div>

              <div className="risk-circle">
                <strong>{data.alert.risk_score}</strong>
                <span>/ 100</span>
              </div>

              <SeverityBadge value={data.alert.severity} />

              <StatusBadge value={data.alert.status} />
            </div>
          </section>

          <div className="grid">
            <section className="panel">
              <div className="panel-kicker">
                DETECTION EVIDENCE
              </div>

              <h2>Analysis Results</h2>

              <div className="metric-list">
                <div>
                  <span>Anomaly Score</span>
                  <strong>
                    {data.alert.anomaly_score ?? "N/A"}
                  </strong>
                </div>

                <div>
                  <span>ML Score</span>
                  <strong>
                    {data.alert.ml_score ??
                      "Disabled / unavailable"}
                  </strong>
                </div>

                <div>
                  <span>Risk Score</span>
                  <strong>
                    {data.alert.risk_score}/100
                  </strong>
                </div>
              </div>

              <div className="reason-box">
                <span>Detection Reason</span>
                <p>{data.alert.description}</p>
              </div>
            </section>

            <section className="panel">
              <div className="panel-kicker">
                ANALYST GUIDANCE
              </div>

              <h2>Recommended Investigation</h2>

              <ol className="investigation-list">
                <li>
                  Review related logs and historical
                  baseline.
                </li>

                <li>
                  Check whether the source is known and
                  expected.
                </li>

                <li>
                  Review firewall, authentication and
                  endpoint telemetry where authorized.
                </li>

                <li>
                  Document evidence before resolution or
                  escalation.
                </li>
              </ol>
            </section>
          </div>

          <section className="panel">
            <div className="panel-kicker">
              INCIDENT LIFECYCLE
            </div>

            <h2>Alert Status</h2>

            <div className="status-actions">
              <button onClick={() => update("NEW")}>
                NEW
              </button>

              <button onClick={() =>
                update("INVESTIGATING")
              }>
                INVESTIGATING
              </button>

              <button onClick={() => update("RESOLVED")}>
                RESOLVED
              </button>

              <button
                onClick={() =>
                  update("FALSE_POSITIVE")
                }
              >
                FALSE POSITIVE
              </button>
            </div>

            <div className="investigation-fields">
              <TextField
                label="Resolution notes"
                value={resolution}
                onChange={(e) =>
                  setResolution(e.target.value)
                }
                placeholder="Why was this alert resolved?"
              />

              <TextField
                label="Analyst note"
                value={note}
                onChange={(e) =>
                  setNote(e.target.value)
                }
                placeholder="Record investigation context..."
              />
            </div>

            <button
              className="primary-button"
              onClick={addNote}
            >
              Add Analyst Note
            </button>
          </section>

          <section className="panel timeline-panel">
            <div className="panel-kicker">
              INVESTIGATION HISTORY
            </div>

            <h2>Incident Timeline</h2>

            <div className="timeline">
              {data.notes.map((n) => (
                <div className="timeline-item" key={n.note_id}>
                  <div className="timeline-dot" />

                  <div>
                    <strong>
                      {new Date(
                        n.created_at
                      ).toLocaleString()}
                    </strong>

                    <p>{n.note}</p>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </main>
  );
}

/* =========================================================
   APP
========================================================= */

function App() {
  const [page, setPage] = useState("dashboard");

  return (
    <div className="app">
      <nav>
        <strong>
          <span className="brand-mark">◈</span>
          Network IDS
        </strong>

        <button
          className={
            page === "dashboard"
              ? "nav-active"
              : ""
          }
          onClick={() => setPage("dashboard")}
        >
          Dashboard
        </button>

        <button
          className={
            page === "investigation"
              ? "nav-active"
              : ""
          }
          onClick={() => setPage("investigation")}
        >
          Investigation
        </button>
      </nav>

      {page === "dashboard" ? (
        <Dashboard />
      ) : (
        <Investigation />
      )}
    </div>
  );
}

createRoot(document.getElementById("root")).render(
  <App />
);