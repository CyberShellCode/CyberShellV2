                                          CyberShell v2.0 - Autonomous Bug Bounty & CTF Framework
<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-purple.svg" alt="License">
  <img src="https://img.shields.io/badge/mode-offensive-red.svg" alt="Mode">
</p>


<p align="center">
<pre>
┌───────────────────────────────────────────────┐
│ ~/cybershell                               ✦  |
├───────────────────────────────────────────────┤
│ $ _  CyberShell                               │
│      research → plan → pivot                  │
│      mapper • ODS • LLM                       │
└───────────────────────────────────────────────┘
</pre>
</p>

# CyberShell v2.0

**An enterprise-grade autonomous exploitation framework.**

CyberShell v2.0 is an enterprise-grade autonomous exploitation framework that combines machine learning, LLM intelligence, and continuous learning capabilities for advanced security testing. Designed for bug bounty hunters, CTF players, and security professionals, it provides automated vulnerability discovery with business impact analysis and compliance reporting.

## ⚡ What's New in v2.0

* **Intelligent Payload System:** Fingerprint-based payload selection with context adaptation.
* **Advanced IDOR Hunter:** JWT-aware IDOR detection with GraphQL support.
* **Business Impact Analysis:** ROI calculation and compliance violation detection.
* **Continuous Learning:** ML models that improve from every exploitation attempt.
* **External Tool Integration:** Rate-limited Nmap and SQLMap integration.
* **Performance Benchmarking:** Compare against Burp Suite, OWASP ZAP, and Nuclei.
* **WAF Bypass Engine:** Advanced evasion techniques with learning capabilities.

## 🏗️ System Architecture

### Core Components

* **Orchestrator (`orchestrator.py`)**
    * Central command system coordinating all operations.
    * Manages plugin execution, evidence scoring, and result aggregation.
    * Integrates LLM for intelligent planning.
* **Autonomous Agent (`agent.py`)**
    * Multi-phase exploitation: Recon → Discovery → Exploitation → Impact.
    * Sub-agent management for parallel vulnerability testing.
    * Automatic payload selection based on fingerprinting.
* **Payload Management (`payload_manager.py`, `enhanced_payload_manager.py`)**
    * Intelligent payload ranking based on target fingerprint.
    * Dynamic context adaptation (parameter, header, path injection).
    * Success history tracking for improved selection.
* **IDOR/BOLA Hunter (`advanced_idor_hunter.py`)**
    * Credential brute-forcing with lockout prevention.
    * JWT token analysis and manipulation.
    * GraphQL introspection and exploitation.
    * Endpoint discovery through JS analysis and crawling.
* **Learning Pipeline (`continuous_learning_pipeline.py`)**
    * Real-time model training from exploitation attempts.
    * Success probability prediction.
    * False positive detection.
    * Adaptive payload optimization.
* **Business Impact Reporter (`business_impact_reporter.py`)**
    * Financial impact calculation with ROI analysis.
    * Compliance violation assessment (GDPR, SOC2, ISO27001).
    * Executive-ready HTML/PDF reports with visualizations.
    * Risk matrix and remediation roadmap generation.
* **Benchmarking Framework (`benchmarking_framework.py`)**
    * Performance comparison with other security tools.
    * Resource usage monitoring.
    * Scalability testing with stress suites.
    * Grade-based performance assessment.

## 📊 Vulnerability Coverage

| Category | Types | Status |
|----------|-------|--------|
| **Injection** | SQL Injection (Union, Blind, Time-based), Command Injection, LDAP, NoSQL | ✅ Full Support |
| **XSS** | Reflected, Stored, DOM-based, Mutation | ✅ Full Support |
| **Authentication** | Bypass, JWT Vulnerabilities, Session Fixation, OAuth Flaws | ✅ Full Support |
| **Access Control** | IDOR, Privilege Escalation, Path Traversal | ✅ Full Support |
| **Server-Side** | SSRF, XXE, SSTI, Deserialization | ✅ Full Support |
| **File Operations** | Upload Vulnerabilities, LFI/RFI, Directory Traversal | ✅ Full Support |
| **Business Logic** | Race Conditions, Workflow Bypass, Price Manipulation | ✅ Full Support |
| **API/GraphQL** | GraphQL Injection, REST API Flaws, SOAP Injection | ✅ Full Support |

## 🛠️ Installation

### Prerequisites

* Python 3.8+
* Ollama (for LLM support)
* Nmap (optional, for network scanning)
* SQLMap (optional, for SQL injection)

### Quick Install

```bash
# Clone repository
git clone [https://github.com/CyberShellCode/CyberShellV2.git](https://github.com/CyberShellCode/CyberShellV2.git)
cd CyberShellV2

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-llm.txt          # For LLM support
pip install -r requirements-dashboard.txt    # For web dashboard

# Install Ollama and model
curl -fsSL [https://ollama.ai/install.sh](https://ollama.ai/install.sh) | sh
ollama pull dolphin-mixtral:8x7b

# Install external tools (optional)
sudo apt-get install nmap          # Linux
brew install nmap                  # macOS
pip install sqlmap                 # SQLMap

## 📁 Project Structure

```
Directory structure:
└── cybershellcode-cybershellv2/
    ├── README.md
    ├── __main__.py
    ├── config.yaml
    ├── fix_scope.py
    ├── LICENSE
    ├── Makefile
    ├── pyproject.toml
    ├── requirements-dashboard.txt
    ├── requirements.txt
    ├── run_ctf.py
    ├── setup.py
    ├── test_autonomous.py
    ├── .env.example
    ├── cybershell/
    │   ├── __init__.py
    │   ├── advanced_ai_orchestrator.py
    │   ├── agent.py
    │   ├── autonomous_orchestration_engine.py
    │   ├── benchmarking_framework.py
    │   ├── business_impact_reporter.py
    │   ├── bypass_techniques.py
    │   ├── chat.py
    │   ├── config.py
    │   ├── continuous_learning_pipeline.py
    │   ├── fingerprint.py
    │   ├── kb.py
    │   ├── learning.py
    │   ├── llm.py
    │   ├── llm_connectors.py
    │   ├── mapper.py
    │   ├── memory.py
    │   ├── miner.py
    │   ├── ods.py
    │   ├── orchestrator.py
    │   ├── payload_manager.py
    │   ├── philosophy.py
    │   ├── planner.py
    │   ├── plugin_loader.py
    │   ├── plugins.py
    │   ├── rate_limiter.py
    │   ├── reporting.py
    │   ├── schemas.py
    │   ├── scoring.py
    │   ├── signals.py
    │   ├── strategies.py
    │   ├── unified_config.py
    │   ├── validation_framework.py
    │   ├── vulnerability_kb.py
    │   └── adaptive/
    │       ├── __init__.py
    │       ├── hitl.py
    │       ├── metrics.py
    │       ├── persistence.py
    │       ├── statemachine.py
    │       └── train.py
    ├── dashboard/
    │   ├── streamlit_app.py
    │   └── components/
    │       ├── __init__.py
    │       ├── metrics.py
    │       ├── reports.py
    │       └── visualizations.py
    ├── docs/
    │   ├── FINGERPRINTING_AND_PAYLOAD_SELECTION.md
    │   └── targets_xss_idor_cmdi.md
    ├── knowledge_base/
    │   ├── vulnerability_kb.json
    │   └── custom_payloads/
    │       ├── rce_custom.json
    │       ├── request_smuggling_custom.json
    │       ├── sqli_custom.json
    │       ├── ssrf_custom.yaml
    │       └── xss_custom.json
    └── plugins_user/
        ├── advanced_payload_plugin.py
        ├── advanced_sqli_plugin.py
        ├── anti_automation_plugin.py
        ├── artifact_handling_plugin.py
        ├── business_logic_plugin.py
        ├── crypto_exploitation_plugin.py
        ├── cve_research_plugin.py
        ├── exploitation_chain_plugin.py
        ├── exploitation_plugins.py
        ├── protocol_specific_plugin.py
        ├── self_healing_plugin.py
        ├── state_manager_plugin.py
        └── TemplateEvidencePlugin.py

```

## 💻 Usage Modes

💻 Usage
CTF Mode
# Full CTF scan
python __main__.py ctf http://ctf.local:8080

# Target specific vulnerability
python __main__.py ctf http://ctf.local --vuln SQLI

# Available vulnerability types:
# SQLI, XSS, RCE, IDOR, SSRF, XXE, SSTI, LFI, AUTH, JWT, UPLOAD, DESERIAL, RACE, LOGIC

Bug Bounty Mode
# Comprehensive hunt with all features
python __main__.py hunt https://target.com \
    --scope "*.target.com,api.target.com" \
    --out-of-scope "test.target.com" \
    --min-cvss 7.0 \
    --confidence 0.8 \
    --parallel 10 \
    --chain-exploits \
    --extract-data

Dashboard
# Launch interactive dashboard
streamlit run dashboard/streamlit_app.py

# Access at http://localhost:8501

🔧 Advanced Features
External Tool Integration
CyberShell integrates with industry-standard tools through intelligent rate limiting:

Nmap Integration

# Automatically rate-limited and configured
# Uses --max-rate and --scan-delay for controlled scanning
# Maximum 2 concurrent Nmap instances

SQLMap Integration

# Automatic delay injection and thread limiting
# Prevents detection through controlled request rates

Intelligent Payload System
The framework uses a multi-layered approach for payload selection:

Target Fingerprinting: Identifies server, technologies, versions.

Payload Ranking: Scores payloads based on:

Version compatibility (35% weight)

Pattern matching (25% weight)

Base confidence (20% weight)

Historical success (5% weight)

Context Adaptation: Automatically adapts payloads for:

Database type (MySQL, PostgreSQL, MSSQL, Oracle)

Injection context (parameter, header, path, body)

Encoding requirements (URL, Base64, Unicode)

WAF evasion needs

WAF Bypass Engine
Advanced evasion techniques with learning capabilities:

Path Manipulation: Double slashes, traversal, trailing slashes.

Encoding Chains: Multi-layer encoding (URL→Unicode→Base64).

Header Injection: X-Original-URL, X-Forwarded-For manipulation.

Method Override: HTTP method tampering.

Parser Differential: Exploiting parser inconsistencies.

Smart Learning: Tracks successful bypass techniques.

Continuous Learning
The ML pipeline continuously improves through:

Experience Buffer: Stores up to 10,000 exploitation attempts.

Background Training: Automatic model retraining every 100 attempts.

Feature Extraction: 20+ features including timing, environment, payload characteristics.

Multi-Model Approach:

Vulnerability classifier (RandomForest, 100 estimators).

Success predictor (GradientBoosting).

False positive detector.

Payload optimizer.

Business Impact Analysis
Comprehensive reporting for enterprise environments:

Financial Metrics:

Potential breach costs by severity.

Remediation cost estimates.

Compliance fine calculations.

ROI analysis for security investment.

Risk Assessment:

Technical, business, compliance, reputation, operational risk scores.

Weighted overall risk calculation.

Mitigation prioritization.

Visualizations:

Risk heatmaps.

Severity distribution charts.

Financial impact breakdowns.

Remediation timelines.

Performance Benchmarking
Compare CyberShell against other tools:

# Run comprehensive benchmark
python -c "from cybershell.benchmarking_framework import run_comprehensive_benchmark; import asyncio; asyncio.run(run_comprehensive_benchmark())"

Benchmark suites:

Basic: Simple web applications.

Advanced: Complex APIs with authentication.

CTF: Challenge-specific scenarios.

Bug Bounty: Real-world simulation.

Stress: 100+ targets for scalability testing.

📊 Evidence Scoring System
CyberShell uses a sophisticated evidence aggregation system:

EMA (Exponential Moving Average): Recency-weighted evidence score.

Maximum Score Tracking: Highest confidence achieved.

Family-Based Grouping: Evidence organized by vulnerability family.

Multi-Signal Analysis: Combines multiple evidence sources.

🔒 Safety & Compliance
Scope Management: Automatic scope checking, private IP/localhost restrictions, out-of-scope filtering.

Rate Limiting: Global and per-host rate limiting with adaptive adjustment.

Ethical Guidelines: Only test systems with permission. Use --production flag for real targets.

Disclaimer: For authorized security testing only. The developers assume no liability for misuse.

📈 Performance Metrics
Based on benchmarking results:

Detection Accuracy: 85-95% F1 score.

Speed: 5-30 seconds per target (varies by complexity).

Resource Usage: <4GB RAM, <80% CPU.

Parallel Capacity: Up to 10 concurrent exploitations.

Success Rate: 70-90% for known vulnerabilities.

🚀 Roadmap
Cloud-native Kubernetes deployment

GraphQL mutation testing

Advanced mobile app testing

Blockchain smart contract analysis

Integration with bug bounty platforms APIs

Distributed scanning architecture

Advanced report templates

Real-time collaboration features

🤝 Contributing
Contributions are welcome! Please ensure all plugins follow the evidence scoring convention, new features include comprehensive tests, and documentation is updated.

📄 License
MIT License - See LICENSE file for details.

🙏 Acknowledgments
Powered by Ollama and dolphin-mixtral model. Integrates with Nmap and SQLMap. Built on scikit-learn, pandas, and modern Python libraries. Inspired by the bug bounty community.

---
Happy hunting 🛡️
