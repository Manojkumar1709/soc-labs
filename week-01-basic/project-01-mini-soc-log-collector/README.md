# Mini SOC Log Collector & Alert Engine

## 🚀 Week 1 - Project 1 | AXIORA SOC Labs

**Objective:** Build a lightweight Security Operations Center (SOC) log ingestion and alerting system on Raspberry Pi 5. This project mimics the core functionality of a Tier-1 SIEM (Security Information and Event Management) system: ingesting raw Linux telemetry, normalizing it, and running rule-based detection logic.

---

## 🏗 Architecture

The system follows a standard data pipeline used in enterprise SIEMs:

![Mini SOC Dashboard](screenshots/dashboard.png)

---

## 🛠 Tech Stack

**Platform:** Raspberry Pi 5 / Ubuntu Linux

**Language:** Python 3.x

**Log Source:** ```/var/log/auth.log```(Linux Authentication Logs)

**Output:** Structured JSON Alerts + Terminal Dashboard

---

## 🔍 Detection Logic

This engine currently implements:

#### 1. SSH Brute Force Detection
* *Logic:* Monitors `SSH_FAILED_LOGIN` events.
* *Trigger:* >3 failed attempts from the same source IP in a single batch.
* *Severity:* **HIGH**

#### 2. Privilege Escalation Monitoring
* *Logic:* Detects any usage of the `sudo` command.
* *Trigger:* Immediate on event.
* *Severity:* **MEDIUM**

#### 3. Successful Access Monitoring
* *Logic:* Tracks successful SSH entries for audit trails.
* *Severity:* **LOW**

---

## 📂 Project Structure

```text
week-01/
├── data/               # Sample log data for testing
├── src/
│   ├── log_parser.py       # Extracts User, IP, Timestamp from raw text
│   ├── event_normalizer.py # Standardizes events to AXIORA schema
│   ├── detection_engine.py # The "Brain": State & Logic rules
│   ├── alert_engine.py     # The "Voice": Saves & Prints alerts
│   └── main.py             # Pipeline Orchestrator
└── alerts/             # Generated security alerts (JSON)

```
---

## 🚀 How to Run

1. Setup Environment:
```
python3 --version
```

2. Run the SOC Engine:
```
python3 src/main.py
```

3. View Alerts:
```
cat alerts/alerts.json
```

## 📸 System Outputs

### 1. Log Parser Output
*Extracting raw logs into structured dictionaries.*
![Parser Output](screenshots/parser_output.png)

### 2. Event Normalizer
*Standardizing data for the Detection Engine.*
![Normalizer Output](screenshots/normalizer_output.png)

### 3. Detection Engine Test
*Simulating a Brute Force attack to trigger logic.*
![Detection Logic](screenshots/detection_output.png)

### 4. Main Dashboard (Live Execution)
*The full pipeline running against real logs.*
![Main Dashboard](screenshots/main_dashboard.png)

### 5. JSON Alert Output
*The final evidence stored for SOC analysts.*
![JSON Alerts](screenshots/alerts_json.png)