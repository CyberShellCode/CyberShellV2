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

# CyberShell v2.0 - Autonomous Bug Bounty & CTF Framework

## 🎯 Overview

CyberShell is an advanced autonomous exploitation framework designed for bug bounty hunting and CTF competitions. It combines intelligent planning, adaptive learning, and LLM-powered exploitation strategies to automatically discover and exploit vulnerabilities.

### 🆕 New in v2.0 - Enhanced Edition
- **Continuous Machine Learning Pipeline** - Learns from every exploitation attempt
- **Business Impact Reporting** - Executive-level reports with ROI analysis
- **Large-Scale Benchmarking** - Performance testing and comparison framework
- **Advanced AI Orchestration** - Multi-model AI integration with context management
- **True Autonomous Operation** - Self-directed exploitation with goal optimization
- **Real-World Validation** - Comprehensive evidence verification system

## ⚡ Key Features

### Core Capabilities
- 🤖 **Autonomous Exploitation**: Fully automated vulnerability discovery and exploitation
- 🧠 **LLM Integration**: Powered by Ollama (dolphin-mixtral:8x7b) for intelligent exploitation
- 🎮 **CTF Mode**: Specialized mode for capture-the-flag competitions
- 💰 **Bug Bounty Mode**: Professional vulnerability hunting with impact demonstration
- 🔗 **Exploit Chaining**: Automatically chains vulnerabilities for maximum impact
- 📊 **Evidence-Based Scoring**: Weighted evidence aggregation for confidence assessment
- 🔄 **Adaptive Learning**: ML-based vulnerability classification that improves over time

### Enhanced Capabilities (v2.0)
- 📈 **Continuous Learning**: Real-time model training and improvement
- 💼 **Business Analytics**: Financial impact assessment and compliance reporting
- ⚖️ **Benchmarking Suite**: Compare performance against other security tools
- 🤝 **Multi-Model AI**: Orchestrate multiple AI models for optimal results
- 🎯 **Goal-Driven Autonomy**: Self-directed decision making with objective optimization
- ✅ **Advanced Validation**: Multi-source evidence correlation and false positive reduction

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

## 🚀 Installation

### Prerequisites

```bash
# Python 3.8+ required
python --version

# Install Ollama (for LLM support)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull dolphin-mixtral:8x7b
```

### Quick Install

```bash
# Clone the repository
git clone https://github.com/CyberShellCode/CyberShell.git
cd cybershell

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Set encoding (important for Windows)
export PYTHONIOENCODING=utf-8  # Linux/Mac
# OR
set PYTHONIOENCODING=utf-8     # Windows CMD
# OR
$env:PYTHONIOENCODING="utf-8"  # PowerShell

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-llm.txt      # For LLM support
pip install -r requirements-dashboard.txt # For web dashboard

# Create necessary directories
mkdir -p models/adaptive
mkdir -p reports
mkdir -p benchmarks
```

### Using Make (Linux/macOS)

```bash
make install            # Basic installation
make install-llm        # Add LLM support
make install-dashboard  # Add dashboard support
make install-all        # Everything
```

## 📁 Project Structure

```
cybershell/
├── models/                              # ML models and training data
│   └── adaptive/                        # Adaptive learning models
├── reports/                             # Generated reports
├── benchmarks/                          # Benchmark results
├── cybershell/                          # Core framework
│   ├── __init__.py
│   ├── __main__.py                     # Entry point for module execution
│   ├── orchestrator.py                 # Main orchestration engine
│   ├── agent.py                        # Autonomous agent
│   ├── plugins.py                      # Plugin base classes
│   ├── scoring.py                      # Evidence scoring
│   ├── strategies.py                   # Planning strategies
│   ├── llm_connectors.py               # LLM integrations
│   ├── config.py                       # Configuration management
│   ├── reporting.py                    # Report generation
│   ├── adaptive/                       # Adaptive learning module
│   │   ├── __init__.py
│   │   ├── mapper.py
│   │   ├── miner.py
│   │   └── ods.py
│   ├── continuous_learning_pipeline.py # ML training pipeline
│   ├── business_impact_reporter.py     # Business reporting
│   ├── benchmarking_framework.py       # Performance benchmarking
│   ├── advanced_ai_orchestrator.py     # Multi-model AI
│   ├── autonomous_orchestration_engine.py # True autonomy
│   └── validation_framework.py         # NEW: Validation system
├── plugins_user/                        # User plugins directory
│   ├── exploitation_plugins.py         # Main exploit plugins
│   ├── business_logic_plugin.py        # Business logic testing
│   ├── anti_automation_plugin.py       # WAF bypass
│   └── custom_plugins.py               # Your custom plugins
├── dashboard/                           # Web dashboard
│   ├── streamlit_app.py
│   └── components/
├── docs/                               # Documentation
├── tests/                              # Test suite
├── __main__.py                         # Main entry point
├── main.py                             # Legacy entry point
├── run_ctf.py                          # CTF helper script
├── requirements.txt                    # Python dependencies
├── requirements-llm.txt                # LLM dependencies
├── requirements-dashboard.txt          # Dashboard dependencies
├── Makefile                           # Build automation
├── config.yaml                        # Configuration file
└── README.md                          # This file
```

## 🎮 Usage Modes

### 1️⃣ CTF Mode - Capture The Flag

#### Full CTF Scan
```bash
python __main__.py ctf http://ctf.local:8080
```

#### Targeted Vulnerability Testing
```bash
# Test specific vulnerability types
python __main__.py ctf http://ctf.local --vuln SQLI
python __main__.py ctf http://ctf.local --vuln XSS
python __main__.py ctf http://ctf.local --vuln RCE

# Available types: SQLI, XSS, RCE, IDOR, SSRF, XXE, SSTI, LFI, AUTH, JWT, UPLOAD, DESERIAL, RACE, LOGIC
```

#### Quick CTF Helper Script
```bash
python run_ctf.py http://ctf.local:1337          # Full scan
python run_ctf.py http://ctf.local:1337 SQLI     # SQLi only
```

### 2️⃣ Bug Bounty Hunt Mode

#### Autonomous Bug Bounty Hunting
```bash
# Basic hunt
python __main__.py hunt https://target.com

# Advanced hunt with all options
python __main__.py hunt https://target.com \
    --scope "*.target.com,api.target.com" \
    --out-of-scope "test.target.com" \
    --min-cvss 7.0 \
    --confidence 0.8 \
    --parallel 10 \
    --chain-exploits \
    --extract-data
```

#### Hunt Mode Options

| Option | Description | Default |
|--------|-------------|---------|
| `--scope` | Comma-separated in-scope domains | Target only |
| `--out-of-scope` | Comma-separated out-of-scope patterns | None |
| `--min-cvss` | Minimum CVSS score to exploit | 4.0 |
| `--confidence` | Confidence threshold (0-1) | 0.75 |
| `--parallel` | Number of parallel exploits | 5 |
| `--chain-exploits` | Enable vulnerability chaining | False |
| `--extract-data` | Extract data for proof of concept | False |

### 3️⃣ Standard Exploitation Mode

```bash
# Basic exploitation
python __main__.py exploit http://target.local

# Advanced exploitation
python __main__.py exploit http://target.local \
    --planner aggressive \
    --scorer bounty_value \
    --llm ollama \
    --output report.json
```

### 4️⃣ Autonomous Mode (NEW)

```python
# Create autonomous_run.py
from cybershell.autonomous_orchestration_engine import AutonomousOrchestrationEngine
import asyncio

async def run():
    engine = AutonomousOrchestrationEngine()
    result = await engine.run_autonomous_exploitation(
        target='http://target.com',
        objectives=['Find critical vulnerabilities', 'Achieve admin access'],
        constraints={'max_time': 3600}
    )
    print(result)

asyncio.run(run())
```

## 🧠 AI & LLM Configuration

### Ollama (Recommended)
```bash
# Start Ollama service
ollama serve

# Pull model
ollama pull dolphin-mixtral:8x7b

# Use in CyberShell
python __main__.py hunt http://target.com --llm ollama
```

### OpenAI
```bash
# Set API key
export OPENAI_API_KEY="your-api-key"

# Use in CyberShell
python __main__.py hunt http://target.com --llm openai
```

### Multi-Model Orchestration (NEW)
```python
from cybershell.advanced_ai_orchestrator import AdvancedAIOrchestrator

orchestrator = AdvancedAIOrchestrator()
# Automatically selects best model for each task
```

### No LLM (Standalone)
```bash
python __main__.py hunt http://target.com --llm none
```

## 🎯 Planning Strategies

| Strategy | Description | Best For |
|----------|-------------|----------|
| `depth_first` | Deep exploitation of each vulnerability | Thorough testing |
| `breadth_first` | Quick scan of all vulnerability types | Initial recon |
| `aggressive` | Immediate high-impact exploitation | CTFs |
| `adaptive` | Adjusts based on confidence levels | Bug bounties |

## 📊 Evidence Scoring Methods

| Scorer | Description | Use Case |
|--------|-------------|----------|
| `default` | Balanced scoring | General use |
| `weighted_signal` | Multi-signal analysis | Complex targets |
| `high_confidence` | Conservative, verified only | Production |
| `bounty_value` | Based on bug bounty values | Maximizing rewards |

## 🔌 Plugin Architecture

### Using Existing Plugins

The framework includes numerous pre-built plugins:

- **Exploitation Plugins**: SQLi, XSS, RCE, IDOR, SSRF, XXE, SSTI, etc.
- **Advanced Plugins**: Business Logic, Anti-Automation, Crypto Exploitation
- **Chain Plugins**: Automated vulnerability chaining
- **State Management**: Session and authentication handling

### Creating Custom Plugins

```python
# plugins_user/MyCustomPlugin.py
from cybershell.plugins import PluginBase, PluginResult

class MyCustomPlugin(PluginBase):
    name = "MyCustomPlugin"
    
    def run(self, **kwargs) -> PluginResult:
        target = kwargs.get("target", "")
        
        # Check scope
        if not self.in_scope(target):
            return PluginResult(self.name, False, {"reason": "out_of_scope"})
        
        # Your exploitation logic here
        evidence = self.exploit(target)
        
        return PluginResult(
            self.name,
            success=True,
            details={
                "evidence": evidence,
                "evidence_score": 0.85,  # 0-1 confidence
                "severity": "High",
                "impact_proof": "Demonstrated impact..."
            }
        )
```

## 📈 Dashboard & Monitoring

### Launch Web Dashboard
```bash
# Using make
make dashboard

# Or directly
streamlit run dashboard/streamlit_app.py
```

The dashboard provides:
- Real-time exploitation monitoring
- Evidence score visualization
- ML model performance metrics
- Vulnerability timeline
- Business impact analysis
- Export capabilities

## 🛡️ Safety Features

### Scope Control
```bash
# Production mode - no localhost/private IPs
python __main__.py hunt https://target.com --production

# Safe mode - less aggressive
python __main__.py hunt https://target.com --safe-mode

# Explicit scope definition
python __main__.py hunt https://target.com \
    --scope "*.target.com" \
    --out-of-scope "staging.target.com"
```

### ⚠️ Authorization Required
- **Always** ensure you have explicit authorization before testing
- Use `--production` flag for real targets
- Configure scope properly to avoid testing unauthorized assets
- The framework enforces scope checking at multiple levels

## 📝 Output Formats

### JSON Report (Default)
```bash
python __main__.py hunt https://target.com --output findings.json --format json
```

### Markdown Report
```bash
python __main__.py hunt https://target.com --output report.md --format markdown
```

### Business Impact Report (NEW)
```python
from cybershell.business_impact_reporter import BusinessImpactReporter

reporter = BusinessImpactReporter()
report = reporter.generate_executive_report(findings, metadata)
# Generates HTML, JSON, and PDF reports with financial analysis
```

## 🔧 Advanced Configuration

### Environment Variables
```bash
# Ollama configuration
export OLLAMA_MODEL="dolphin-mixtral:8x7b"
export OLLAMA_BASE_URL="http://localhost:11434"

# OpenAI configuration
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4"

# Proxy configuration
export HTTP_PROXY="http://proxy:8080"
export HTTPS_PROXY="http://proxy:8080"
```

### Configuration File (config.yaml)
```yaml
safety:
  allow_private_ranges: true
  allow_localhost: true
  additional_scope_hosts:
    - "*.example.com"
    - "api.example.com"

exploitation:
  max_parallel_exploits: 10
  min_cvss_for_exploit: 7.0
  confidence_threshold: 0.8
  chain_vulnerabilities: true
  extract_data_samples: true

llm:
  provider: "ollama"
  model: "dolphin-mixtral:8x7b"
  temperature: 0.7
  max_tokens: 2000

learning:
  enable_continuous_learning: true
  model_update_threshold: 100
  experience_buffer_size: 10000
```

## 🏆 CTF Competition Tips

### Quick Wins
```bash
# Start with aggressive mode for CTFs
python __main__.py ctf http://ctf.local --planner aggressive

# Scan for multiple vulnerability types
for vuln in SQLI XSS RCE SSTI LFI; do
    python __main__.py ctf http://ctf.local --vuln $vuln
done

# Grep for flags
python __main__.py ctf http://ctf.local | grep -E "flag{|FLAG{|ctf{|CTF{"
```

### Flag Patterns
The framework automatically searches for common CTF flag formats:
- `flag{...}`, `FLAG{...}`
- `ctf{...}`, `CTF{...}`
- `picoCTF{...}`, `htb{...}`, `thm{...}`
- MD5 hashes as flags
- Base64 encoded flags

## 📊 Benchmarking & Performance (NEW)

### Run Benchmark Suite
```python
from cybershell.benchmarking_framework import BenchmarkingFramework
import asyncio

async def benchmark():
    framework = BenchmarkingFramework()
    report = await framework.run_benchmark_suite('advanced', parallel=10)
    print(f"Performance Grade: {report['executive_summary']['overall_grade']}")

asyncio.run(benchmark())
```

### Compare with Other Tools
The benchmarking framework can compare CyberShell's performance against:
- Burp Suite
- OWASP ZAP
- Nuclei
- SQLMap
- Other security tools

## 🐛 Troubleshooting

### Common Issues

#### Ollama Connection Error
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Restart Ollama
systemctl restart ollama  # Linux
brew services restart ollama  # macOS
```

#### Module Import Errors
```bash
# Verify installation
python -c "from cybershell import orchestrator; print('✓ Installed')"

# Check specific module
python -c "from cybershell.continuous_learning_pipeline import ContinuousLearningPipeline; print('✓ ML Pipeline Ready')"
```

#### Plugin Not Found
```bash
# Verify plugin directory
ls plugins_user/

# Test plugin loading
python -c "from cybershell.plugin_loader import load_user_plugins; print(load_user_plugins('plugins_user').keys())"
```

#### Rate Limiting
```bash
# Use anti-automation plugin
python __main__.py hunt https://target.com --safe-mode

# Reduce parallelism
python __main__.py hunt https://target.com --parallel 1
```

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. All plugins follow the evidence scoring convention (0-1 scale)
2. New vulnerability types include both test and exploit plugins
3. Documentation is updated for new features
4. Code follows the existing style conventions
5. Tests are included for new functionality

### Development Setup
```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Code formatting
black cybershell/

# Linting
pylint cybershell/
```

## ⚖️ Legal Notice

**⚠️ IMPORTANT DISCLAIMER**

- Only use on systems you own or have explicit written permission to test
- Ensure compliance with local laws and regulations
- The developers assume no liability for misuse
- Bug bounty hunting must follow program rules and scope
- Violation of computer fraud laws can result in severe penalties

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

- Powered by [Ollama](https://ollama.ai) and dolphin-mixtral model
- Inspired by modern bug bounty methodologies
- Built for the security research community

## 🚀 Roadmap

### Coming Soon
- [ ] Cloud-native deployment options
- [ ] Advanced REST API
- [ ] Mobile application testing
- [ ] Kubernetes security testing
- [ ] Enhanced GraphQL exploitation
- [ ] Distributed scanning capabilities
- [ ] Integration with major bug bounty platforms

---
Happy hunting 🛡️
