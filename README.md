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

CyberShell is a modular, lab-safe research scaffold for authorized bug bounty workflows. It focuses on planning, reasoning, and evidence scoring—while real-world interaction and proof collection live in your plugins.

⚠️ Use only on assets you are explicitly authorized to test. The core is lab-safe; any live interaction must be implemented by you in plugins_user/.

Why CyberShell?

Modular planning: swap planner strategies (depth-first / breadth-first) without touching the kernel.

Outcome-Directed Search (ODS): pivots strategy based on numeric evidence scores from your plugins.

Pluggable scoring: choose or write scorers that align with a program’s evidence bar.

LLM adapters: OpenAI-compatible API, Ollama, or your own in-process model (no server).

Document Miner: local docs → summaries → planning context (no background web fetch).

Adaptive mapper: rules + online-friendly ML (TF-IDF + OvR) with partial_fit.

Dashboard: Streamlit app that visualizes ODS evidence (EMA / max) and shows plan & results.

Quickstart
1) Create & activate a virtual environment

Windows (Git Bash):

python -m venv .venv || py -3 -m venv .venv
source .venv/Scripts/activate


macOS/Linux:

python3 -m venv .venv
source .venv/bin/activate

2) Install dependencies
pip install -r requirements.txt
# Optional: dashboard
pip install -r requirements-dashboard.txt
# Optional: LLM APIs (if your project split these)
# pip install -r requirements-llm.txt

3) First run (lab-safe)
python -m cybershell http://localhost:8000 --planner depth_first --scorer weighted_signal --llm none

4) Open the dashboard (optional)
streamlit run dashboard/streamlit_app.py

File & Folder Layout
CyberShell/
├─ README.md                     # This file
├─ requirements.txt
├─ requirements-dashboard.txt
├─ Makefile                      # (optional helpers for *nix)
├─ run_demo.py                   # Convenience script (lab-safe)
│
├─ cybershell/                   # Core package
│  ├─ __init__.py
│  ├─ __main__.py               # CLI: python -m cybershell ...
│  ├─ orchestrator.py           # Wires everything together
│  ├─ config.py                 # Safety/Scope config
│  ├─ plugin_loader.py          # Autoloads plugins from plugins_user/
│  ├─ plugins.py                # PluginBase, PluginResult primitives
│  ├─ strategies.py             # Planner strategies (+ registry)
│  ├─ scoring.py                # Scorers (+ registry)
│  ├─ ods.py                    # Outcome-Directed Search loop + EvidenceAggregator
│  ├─ miner.py                  # Document Miner (local-only)
│  ├─ mapper.py                 # Rules + MLMapper (TF-IDF + OvR)
│  ├─ llm.py                    # LLMConnector base + prompts
│  ├─ llm_connectors.py         # OpenAI, Ollama, LocalFunctionConnector
│  ├─ adaptive/
│  │  ├─ train.py               # Offline training for the mapper
│  │  └─ hitl.py                # Human-in-the-loop update hooks
│  └─ schemas.py                # Shared data classes (PlanStep, Result, etc.)
│
├─ plugins_user/                 # Your authorized plugins (autoloaded)
│  ├─ TemplateEvidencePlugin.py  # Safe template (returns evidence_score)
│  └─ ...                        # Your additional plugins here
│
├─ docs/                         # Local docs for the Miner (txt/md/pdf/json/yaml/html)
│  └─ ...                        # Add guides/playbooks/CVEs you curated
│
└─ dashboard/
   └─ streamlit_app.py           # ODS evidence charts + plan/results viewer

Running the Tool
CLI
python -m cybershell <target> [--planner PLAN] [--scorer SCORER] [--doc-root PATH] [--llm none|openai|ollama|localfn]


Examples

# Thorough per-target pass
python -m cybershell http://localhost:8000 --planner depth_first --scorer weighted_signal --llm none

# Quick breadth scan with stricter evidence bar
python -m cybershell http://localhost:8000 --planner breadth_first --scorer high_confidence --llm none

# Use your local docs
python -m cybershell http://localhost:8000 --doc-root docs --planner depth_first --scorer weighted_signal --llm none


If you see “No module named cybershell.__main__”, ensure cybershell/__main__.py exists (it’s included) and run from the project root with the venv active.

LLM Options (choose one)
A) OpenAI-compatible API
export OPENAI_API_KEY="sk-..."
# optional:
# export OPENAI_MODEL="gpt-4o-mini"
# export OPENAI_BASE_URL="https://api.openai.com/v1"   # or compatible endpoint

python -m cybershell https://authorized-target --llm openai

B) Ollama (local model)
# Optional overrides:
# export OLLAMA_BASE_URL="http://localhost:11434"
# export OLLAMA_MODEL="llama3.1"
python -m cybershell http://localhost:8000 --llm ollama

C) Your own in-process LLM (no server)

Use LocalFunctionConnector to plug a Python function that returns model text:

from cybershell.orchestrator import CyberShell
from cybershell.config import SafetyConfig
from cybershell.llm_connectors import LocalFunctionConnector

def my_generate(prompt: str) -> str:
    # Return a JSON array of steps (lab-safe)
    return '[{"plugin":"TemplateEvidencePlugin","why":"local","params":{"hint":"baseline","confidence":0.5}}]'

bot = CyberShell(
    SafetyConfig(allow_localhost=True, allow_private_ranges=True),
    llm=LocalFunctionConnector(my_generate),
)
print(bot.execute('http://localhost:8000')['report'])


Want to call your own server that speaks the OpenAI API? Use OpenAICompatibleHTTPConnector (in llm_connectors.py) and pass your base_url + headers.

Planner Strategies (swap or extend)

Built-in: depth_first, breadth_first

Switch via CLI: --planner depth_first

Add your own in cybershell/strategies.py:

from dataclasses import dataclass
from .strategies import BasePlannerStrategy, STRATEGY_REGISTRY
from .schemas import PlanStep

@dataclass
class DepthThenBreadthPlanner(BasePlannerStrategy):
    def plan(self, target, recon, mapper=None, llm=None, kb=None, signals_text=None):
        steps = [PlanStep('HttpFingerprintPlugin', 'baseline FP', {'target': target})]
        # mapper-informed
        if mapper and signals_text:
            mapped = mapper.map(type('Evt', (), {'as_text': lambda self=None: signals_text})())
            for fam, _score in mapped.top_families[:2]:
                steps.append(PlanStep('TemplateEvidencePlugin', f'mapper suggests {fam}', {'target': target, 'hint': fam}))
        # single LLM suggestion
        if llm:
            for s in llm.suggest_steps(target, recon)[:1]:
                steps.append(PlanStep(s.get('plugin','TemplateEvidencePlugin'), s.get('why','llm'), {'target': target, **s.get('params',{})}))
        return steps

STRATEGY_REGISTRY['depth_then_breadth'] = DepthThenBreadthPlanner

Scoring & ODS (tune the “creativity engine”)

Scorers: default, weighted_signal, high_confidence

Switch via CLI: --scorer weighted_signal

Write your own in cybershell/scoring.py by subclassing BaseScorer and registering in SCORER_REGISTRY.

ODS config (in code via ODSConfig or pass when constructing CyberShell):

window, patience_steps, stagnation_rounds, min_improvement, stop_threshold, max_iterations

ODS pivots when evidence plateaus; it stops early when evidence ≥ threshold.

Important: Your plugins should return details["evidence_score"] in [0,1]. High-quality scoring → smarter pivots and earlier stops.

Document Miner (local only)

Put files in docs/ (supported: .txt, .md, .html, .pdf, .json, .yaml).

The Miner extracts summaries and titles; the planner pulls those into context.

Switch doc folder via --doc-root or CyberShell(..., doc_root='path').

Adaptive Learning Mapper

Rules + MLMapper (TF-IDF + OvR) with partial_fit for online updates.

Offline training example (cybershell/adaptive/train.py):

from cybershell.adaptive.train import load_nvd_json_folder, train_mapper
samples = load_nvd_json_folder('nvd_json_folder')
model, report, _ = train_mapper(samples)
bot.attach_trained_mapper(model)  # hot-swap runtime mapper

Build Your Own Plugin (template)

Drop a file in plugins_user/ and it auto-loads. Minimal safe template:

# plugins_user/MyEvidencePlugin.py
from cybershell.plugins import PluginBase, PluginResult

class MyEvidencePlugin(PluginBase):
    name = "MyEvidencePlugin"

    def run(self, **kwargs) -> PluginResult:
        target = kwargs.get("target", "")
        if not self.in_scope(target):
            return PluginResult(self.name, False, {"reason": "out_of_scope"})

        # Do authorized, lab-safe work here…
        details = {
            "hint_used": kwargs.get("hint"),
            "reflections": [],
            "error_tokens": [],
            "length_delta": 0.0,
            "headers": {},
            "evidence_score": 0.45,   # ← calibrate 0..1
        }
        return PluginResult(self.name, True, details)


Tip: make the loader resilient so a broken plugin won’t crash startup. In plugin_loader.py, wrap import with try/except and skip on error.

Troubleshooting

No module named cybershell.__main__
Ensure you’re in the project root and cybershell/__main__.py exists.

Venv not used / wrong Python
source .venv/Scripts/activate (Git Bash) or use ./.venv/Scripts/python.exe … explicitly.

ModuleNotFoundError in a user plugin
pip install <package> inside the venv or temporarily rename the plugin to .off.

SyntaxError in plugin template strings
Avoid f-strings for large HTML/JS; use str.format or string.Template.

Safety & Scope

The core never performs live exploitation or data exfiltration.

Real-world actions belong in your authorized plugins and must respect your program’s rules.

Always keep logs/evidence reproducible and avoid sensitive data in prompts or configs.

What’s next?

Add your first custom scorer tuned to your target program’s evidence criteria.

Train and attach a domain-specific mapper.

Drop internal playbooks into docs/ so the planner learns your style.

Build an auth/session plugin and a target inventory plugin when you’re ready.

Happy hunting 🛡️
