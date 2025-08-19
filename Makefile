# Simple helpers (Linux/macOS/WSL; on Windows use PowerShell equivalents)

PYTHON ?= python
PIP ?= pip

VENV := .venv
ACT := . $(VENV)/bin/activate

.PHONY: venv install install-llm install-dashboard run demo openai ollama dashboard clean

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(ACT) && $(PIP) install -r requirements.txt

install-llm: venv
	$(ACT) && $(PIP) install -r requirements-llm.txt

install-dashboard: venv
	$(ACT) && $(PIP) install -r requirements-dashboard.txt

run:
	$(ACT) && $(PYTHON) -m cybershell http://localhost:8000 --planner depth_first --scorer weighted_signal --llm none

demo: run

openai:
	# Requires OPENAI_API_KEY env var
	$(ACT) && $(PYTHON) -m cybershell http://localhost:8000 --planner depth_first --scorer weighted_signal --llm openai

ollama:
	# Make sure ollama is running locally
	$(ACT) && $(PYTHON) -m cybershell http://localhost:8000 --planner breadth_first --scorer high_confidence --llm ollama

dashboard:
	$(ACT) && streamlit run dashboard/streamlit_app.py

clean:
	rm -rf $(VENV) __pycache__ .pytest_cache .mypy_cache
	find . -name "__pycache__" -type d -prune -exec rm -rf {} \;
