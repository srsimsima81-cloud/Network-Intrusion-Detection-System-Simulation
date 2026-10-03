# Network Intrusion Detection System (IDS) Simulation

A defensive cybersecurity project that simulates network-flow monitoring and detects potentially suspicious activity using **signature-based rules, anomaly detection, and optional machine learning**.

The system generates synthetic network-flow records, extracts security-relevant features, evaluates traffic against multiple detection techniques, calculates risk scores, generates alerts, and provides a SOC-style dashboard for security monitoring and investigation.

> **Safety Notice:** This project uses synthetic network traffic only. It does not capture, scan, probe, exploit, or transmit malicious traffic against real systems or third-party infrastructure.

---

## Overview

Network Intrusion Detection Systems (IDS) monitor network activity to identify patterns that may indicate suspicious or potentially malicious behavior.

This project demonstrates the core concepts of a Network-Based IDS in a safe local environment by simulating network-flow data rather than inspecting real packets.

The system combines:

- Synthetic network-traffic generation
- Network-flow analysis
- Feature extraction
- Signature/rule-based detection
- Statistical anomaly detection
- Optional machine-learning detection
- Hybrid risk scoring
- Alert generation
- Alert correlation
- Security-event storage
- SOC-style investigation workflow
- Interactive cybersecurity dashboard

The project is designed for **learning, demonstration, portfolio development, and cybersecurity interview preparation**.

---

## Key Features

### Network Traffic Simulation

Generates synthetic network-flow records representing normal and suspicious scenarios.

Supported scenarios include:

- Normal Web Traffic
- Normal DNS Traffic
- Normal SSH Traffic
- Normal Email Traffic
- Normal Database Traffic
- High Connection Rate
- Repeated Failed Connections
- Multi-Port Probing Pattern
- SYN-Heavy Pattern
- Unusual Port Activity
- High Traffic Volume

The generated dataset contains **5,000+ synthetic network-flow records**.

---

### Feature Extraction

The system derives security-related features from network-flow records, including:

- Packet count
- Byte count
- Duration
- Bytes per second
- Packets per second
- Average packet size
- Connection count
- Failed connection count
- Failure ratio
- SYN count
- RST count
- SYN ratio
- Unique destination ports
- Unique destination IPs
- Connection rate

These features provide the basis for rule-based, anomaly-based, and machine-learning analysis.

---

## Detection Engine

The IDS uses a hybrid detection approach.

### 1. Signature / Rule-Based Detection

Predefined security rules identify recognizable suspicious patterns such as:

- Excessive connection rates
- Repeated failed connections
- High destination-port diversity
- SYN-heavy traffic
- Unusual service-port activity
- Excessive traffic volume

A rule match indicates that activity **requires investigation**; it does not automatically prove malicious intent.

---

### 2. Anomaly Detection

The system establishes behavioral baselines for network activity and identifies traffic that deviates significantly from expected patterns.

Analyzed characteristics include:

- Packet rate
- Byte rate
- Connection rate
- Failure ratio
- Port diversity

The anomaly detector produces an **anomaly score from 0–100**.

---

### 3. Machine Learning

An optional supervised machine-learning component can classify network-flow records.

Supported approaches include:

- Logistic Regression
- Random Forest

The project also supports an unsupervised anomaly-detection approach using Isolation Forest where applicable.

Model evaluation includes:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion matrix

Machine-learning metrics are calculated from the generated dataset and are not manually fabricated.

---

## Hybrid Risk Scoring

Detection results are combined into a unified risk score.

### With Machine Learning

| Detection Component | Weight |
|---|---:|
| Rule Detection | 40% |
| Anomaly Detection | 30% |
| Machine Learning | 30% |

### Without Machine Learning

| Detection Component | Weight |
|---|---:|
| Rule Detection | 60% |
| Anomaly Detection | 40% |

The resulting risk score ranges from **0–100**.

| Risk Score | Classification |
|---:|---|
| 0–20 | NORMAL |
| 21–40 | LOW RISK |
| 41–60 | SUSPICIOUS |
| 61–80 | HIGH RISK |
| 81–100 | CRITICAL INVESTIGATION |

These thresholds are configurable demonstration values.

---

## Alert Management

When suspicious activity is detected, the system creates a security alert containing information such as:

- Alert ID
- Timestamp
- Source IP
- Destination IP
- Protocol
- Source port
- Destination port
- Matched rule
- Alert type
- Severity
- Risk score
- Description
- Status

### Severity Levels

- INFO
- LOW
- MEDIUM
- HIGH
- CRITICAL

### Alert Status

- NEW
- INVESTIGATING
- RESOLVED
- FALSE_POSITIVE

---

## SOC-Style Investigation

The dashboard provides an investigation workflow for analysts.

An analyst can:

1. Load an alert using its Alert ID
2. Review source and destination information
3. Review the matched detection rule
4. Examine anomaly and ML scores
5. Review the calculated risk score
6. Add investigation notes
7. Change the alert status
8. Record resolution information
9. Review the investigation timeline

The workflow demonstrates the relationship between a detection event, an alert, and an investigation.

---

## Dashboard

The web dashboard provides a centralized view of simulated security activity.

### Key Metrics

- Total Network Flows
- Normal Traffic
- Suspicious Traffic
- Open Alerts
- Critical Alerts
- Average Risk Score

### Visual Analytics

The dashboard provides visualizations for:

- Risk over time
- Alerts by severity
- Protocol distribution
- Alert types
- Traffic classification
- Risk distribution
- Source activity
- Destination-port activity

### Alert Filtering

Analysts can filter alerts by:

- Severity
- Protocol
- Status
- Alert type

The dashboard periodically refreshes data to provide a near-real-time monitoring experience.

> The project uses polling for demonstration purposes rather than capturing live network packets.

---

## System Architecture

```text
┌───────────────────────────────┐
│   Synthetic Traffic Generator │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│       Flow Collector          │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│       Feature Extractor       │
└───────────────┬───────────────┘
                │
        ┌───────┼────────┐
        ▼       ▼        ▼
   ┌────────┐ ┌──────┐ ┌────────────┐
   │ Rules  │ │Anomaly│ │ ML Model  │
   │ Engine │ │Detector│ │(Optional) │
   └────┬───┘ └───┬──┘ └─────┬──────┘
        │         │          │
        └─────────┼──────────┘
                  ▼
        ┌───────────────────┐
        │   Risk Engine     │
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │   Alert Engine    │
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │    Database       │
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │   SOC Dashboard   │
        └───────────────────┘
```

---

## Technology Stack

### Backend

- Python
- FastAPI
- SQLAlchemy
- SQLite
- REST API

### Data Processing

- Pandas
- NumPy

### Machine Learning

- Scikit-learn
- Logistic Regression
- Random Forest
- Isolation Forest

### Frontend

- React
- Vite
- Recharts
- CSS

### Testing

- Pytest

### Development

- Git
- GitHub
- Python Virtual Environment

---

## Project Structure

```text
Network-IDS-Simulation/
│
├── simulator/
│   ├── traffic_simulator.py
│   └── generate_dataset.py
│
├── ids/
│   ├── feature_extractor.py
│   ├── rule_engine.py
│   ├── anomaly_detector.py
│   ├── risk_engine.py
│   ├── alert_engine.py
│   └── correlation.py
│
├── ml/
│   ├── train_model.py
│   ├── predict.py
│   └── evaluate.py
│
├── backend/
│   ├── app.py
│   ├── models/
│   ├── routes/
│   ├── services/
│   └── utils/
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   └── services/
│   ├── package.json
│   └── vite.config.js
│
├── data/
│   └── network_traffic.csv
│
├── models/
│
├── tests/
│
├── screenshots/
│
├── docs/
│
├── reports/
│
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Dataset

The project uses synthetic network-flow data.

Each record contains fields such as:

```text
flow_id
timestamp
source_ip
destination_ip
source_port
destination_port
protocol
packet_count
byte_count
duration_seconds
connection_count
failed_connection_count
syn_count
rst_count
average_packet_size
label
scenario_type
```

### Example

```json
{
  "flow_id": "FLOW-00001",
  "source_ip": "192.0.2.15",
  "destination_ip": "198.51.100.20",
  "source_port": 49152,
  "destination_port": 443,
  "protocol": "TCP",
  "packet_count": 42,
  "byte_count": 18450,
  "duration_seconds": 3.8,
  "connection_count": 4,
  "failed_connection_count": 0,
  "syn_count": 4,
  "rst_count": 0,
  "average_packet_size": 439.29,
  "label": "NORMAL",
  "scenario_type": "NORMAL_WEB"
}
```

The documentation ranges below are used for synthetic addressing:

```text
192.0.2.0/24
198.51.100.0/24
203.0.113.0/24
```

These ranges are intended for documentation/example use and are not real production hosts.

---

## API

The backend exposes REST endpoints for interacting with the IDS.

### Network Flows

```text
POST /api/flows
GET  /api/flows
GET  /api/flows/{id}
```

### Alerts

```text
GET /api/alerts
GET /api/alerts/{id}
PUT /api/alerts/{id}/status
POST /api/alerts/{id}/notes
```

### Dashboard

```text
GET /api/dashboard/stats
GET /api/dashboard/traffic
GET /api/dashboard/alerts
```

### Rules

```text
GET /api/rules
PUT /api/rules/{id}
```

---

## Installation

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd Network-IDS-Simulation
```

### 2. Create a Virtual Environment

Windows:

```bash
python -m venv .venv
```

Activate it:

```bash
.venv\Scripts\activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Generate the Dataset

```bash
python -m simulator.generate_dataset --rows 5000
```

The generated dataset will be saved to:

```text
data/network_traffic.csv
```

### 5. Train the Machine-Learning Model

```bash
python -m ml.train_model
```

The training process reports evaluation metrics such as:

```text
Accuracy
Precision
Recall
F1 Score
Confusion Matrix
```

---

## Running the Backend

Start the FastAPI server:

```bash
uvicorn backend.app:app --reload
```

The API will be available locally at:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

---

## Running the Frontend

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local Vite URL displayed in the terminal.

---

## Running the Traffic Simulator

With the backend running, start the synthetic traffic simulator:

```bash
python -m simulator.traffic_simulator --mode mixed --speed slow
```

The simulator generates synthetic network-flow records and sends them to the local IDS application for analysis.

No real network packets are transmitted.

---

## Demonstration Workflow

A typical demonstration can follow this workflow:

```text
1. Generate synthetic dataset
        ↓
2. Start FastAPI backend
        ↓
3. Start React dashboard
        ↓
4. Start synthetic traffic simulator
        ↓
5. Normal flows are classified
        ↓
6. Suspicious patterns trigger detection rules
        ↓
7. Anomaly analysis contributes to the risk score
        ↓
8. Optional ML model contributes to classification
        ↓
9. Alert is generated
        ↓
10. Alert appears in SOC dashboard
        ↓
11. Analyst opens the alert
        ↓
12. Investigation notes are added
        ↓
13. Alert status is updated
```

---

## Example Detection Scenarios

### Normal Web Traffic

Expected classification:

```text
NORMAL
```

Typical characteristics:

- Moderate packet rate
- Normal HTTPS destination port
- Low failure ratio
- Normal connection rate

---

### Repeated Failed Connections

Potential indicators:

```text
High failed connection count
High failure ratio
Repeated connection attempts
```

Expected result:

```text
SUSPICIOUS
```

---

### Multi-Port Activity

Potential indicators:

```text
High destination-port diversity
Unusual connection pattern
```

Expected result:

```text
SUSPICIOUS
```

---

### SYN-Heavy Pattern

Potential indicators:

```text
High SYN count
High SYN ratio
Unusual connection behavior
```

Expected result:

```text
SUSPICIOUS
```

These scenarios are simulated using generated records and do not represent actual attacks against real systems.

---

## Database Design

The application organizes security information into logical entities.

### NETWORK_FLOWS

Stores analyzed synthetic network-flow records.

### ALERTS

Stores generated security alerts.

### RULES

Stores configurable detection rules.

### INCIDENT_NOTES

Stores analyst investigation notes and timeline entries.

### MODEL_RESULTS

Can store machine-learning analysis results where enabled.

---

## Security Considerations

Although this is an educational simulation, the project demonstrates several security engineering principles:

- Input validation
- Secure environment-variable handling
- No hard-coded secrets
- No payload collection
- No real credential collection
- Least-privilege design
- Output sanitization
- API access controls
- Rate limiting considerations
- Audit logging
- Protection of security-event data
- Secure production transport using HTTPS
- Separation of detection and investigation functions

For a production deployment, additional controls would be required based on the environment and threat model.

---

## False Positives and False Negatives

An IDS cannot assume that every detected anomaly represents malicious activity.

### False Positive

Normal activity incorrectly classified as suspicious.

Possible causes:

- Legitimate traffic spikes
- Backup operations
- Administrative activity
- High-volume applications

### False Negative

Suspicious activity that is not detected.

Possible causes:

- Previously unseen behavior
- Insufficient features
- Weak detection thresholds
- Evasive behavior

The project therefore combines multiple detection approaches and provides analyst investigation rather than automatically declaring an event malicious.

---

## IDS vs IPS

| IDS | IPS |
|---|---|
| Detects suspicious activity | Detects and can actively block activity |
| Primarily monitoring and alerting | Monitoring plus prevention |
| Does not directly disrupt traffic | May block/drop traffic |
| Suitable for passive security monitoring | Used for active enforcement |

This project implements an **IDS simulation**, not an Intrusion Prevention System.

---

## Signature-Based vs Anomaly-Based Detection

| Signature-Based | Anomaly-Based |
|---|---|
| Uses predefined patterns/rules | Uses behavioral baselines |
| Effective for known patterns | Can identify unusual behavior |
| Easier to interpret | May require statistical/ML analysis |
| Can miss new patterns | Can generate more false positives |
| Rule-driven | Behavior-driven |

This project combines both approaches.

---

## SOC Integration Concept

The generated alerts can conceptually be forwarded to a SIEM or centralized security-monitoring platform.

Example alert representation:

```json
{
  "alert_id": "ALT-1001",
  "source_ip": "192.0.2.15",
  "destination_ip": "198.51.100.20",
  "severity": "HIGH",
  "rule": "High Connection Rate",
  "risk_score": 78
}
```

No commercial SIEM is required to run this project.

---

## MITRE ATT&CK Considerations

Where appropriate, detected behavior can be investigated against relevant MITRE ATT&CK techniques.

The project does **not automatically assign an ATT&CK technique solely from an anomaly score**.

Any mapping should be based on sufficient evidence from the observed behavior and supporting telemetry.

---

## Testing

Run the automated tests with:

```bash
pytest
```

Testing should cover:

- Dataset generation
- Feature extraction
- Rule detection
- Anomaly scoring
- Risk calculation
- Alert creation
- Alert filtering
- API behavior
- Input validation
- Status updates

---

## Limitations

This project is intentionally a simulation and therefore has several limitations:

- It does not capture live packets.
- It does not inspect real network payloads.
- Traffic is synthetically generated.
- Detection thresholds are demonstration-oriented.
- The ML model is trained on synthetic data.
- Results should not be interpreted as production IDS performance.
- Real-world environments require significantly more telemetry and tuning.

---

## Future Enhancements

Potential extensions include:

- PCAP-based offline analysis in an isolated lab
- Additional anomaly-detection algorithms
- Deep-learning-based network classification
- More advanced temporal correlation
- Authentication and role-based dashboard access
- Alert deduplication
- Threat-intelligence enrichment using authorized data
- SIEM integration
- Automated incident timelines
- Advanced detection-rule management
- Model drift monitoring
- Production database support
- Secure deployment architecture

---

## Learning Outcomes

This project demonstrates practical understanding of:

- Network security fundamentals
- Network traffic analysis
- Intrusion detection
- Security monitoring
- Feature engineering
- Signature-based detection
- Anomaly detection
- Machine-learning classification
- Risk scoring
- Alert management
- Security-event correlation
- SOC investigation workflows
- REST API development
- Database-backed security applications
- Security-focused dashboard development

---

## Project Classification

**Domain:** Cybersecurity

**Category:** Network Security / Intrusion Detection

**Type:** Defensive Security Simulation

**Architecture:** Network-Based Hybrid IDS

**Data:** Synthetic Network-Flow Data

**Detection:** Rule-Based + Anomaly-Based + Optional ML

**Interface:** SOC-Style Web Dashboard

**Deployment:** Local Development / Educational Environment

---

## Disclaimer

This project is intended strictly for **educational, defensive cybersecurity, and authorized laboratory use**.

All traffic used by the project is synthetic. The project does not provide functionality for unauthorized scanning, exploitation, credential theft, denial-of-service activity, or attacks against real systems.

Only use cybersecurity techniques and tools in environments where you have explicit authorization.

---

