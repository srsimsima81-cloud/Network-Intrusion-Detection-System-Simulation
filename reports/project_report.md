# Network Intrusion Detection System (IDS) Simulation

## Abstract
A safe, local Network-Based Hybrid IDS simulation using synthetic network-flow records. The system combines rule/signature detection, statistical anomaly detection, optional Random Forest classification, risk scoring, alert management, correlation, persistence and a SOC-style dashboard.

## Objectives
- Generate safe network-flow records without transmitting packets.
- Extract security-relevant features.
- Detect configurable suspicious patterns.
- Compare flows against a baseline.
- Produce explainable alerts and risk scores.
- Demonstrate a SOC analyst investigation workflow.

## Architecture
Synthetic Generator -> Flow API -> Feature Extraction -> Rules + Anomaly + Optional ML -> Risk Engine -> Alert Engine -> SQLite -> React SOC Dashboard.

## Detection
Rules cover connection rate, failed connection ratio, destination-port diversity, SYN ratio, uncommon service ports and high byte rate. Anomaly detection uses z-score deviation. ML evaluation calculates metrics from the generated dataset at runtime.

## Risk
Educational default weights are Rule 40%, Anomaly 30%, ML 30%. Without ML, Rule 60% and Anomaly 40% are used. Thresholds are project assumptions and must be calibrated in production.

## Safety
Only documentation/reserved IP ranges are used. The simulator emits JSON records and never sends network packets. No scanning, exploitation, flooding, credential theft or external targeting is included.

## Limitations
This is not a packet-inspection IDS such as Suricata or Snort. It does not capture live interfaces or inspect payloads. It is designed as a safe educational proof-of-work project.
