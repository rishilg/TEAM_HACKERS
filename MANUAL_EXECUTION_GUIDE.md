# Manual Execution Guide - Security Drift Intelligence

## Prerequisites

### 1. Verify Python Installation
```powershell
# Check if Python is installed
py --version
# or
& "C:/Users/rishi/Anaconda python/python.exe" --version
```

### 2. Navigate to Project Root
```powershell
cd "C:\Users\rishi\OneDrive\Documents\New project\security-drift-intelligence"
```

---

## OPTION A: Run Full Pipeline (1 Command)

**Best for:** Complete analysis in one go

```powershell
& "C:/Users/rishi/Anaconda python/python.exe" scripts/run_pipeline.py
```

**What it does:**
1. ✅ Loads config drift events from `data/config_drift_events.csv`
2. ✅ Trains ML models (Random Forest + Isolation Forest)
3. ✅ Scores all 1,004 events through 6-layer risk engine
4. ✅ Generates executive audit report
5. ✅ Creates compliance violation mappings
6. ✅ Saves validation metrics

**Output:** 7 files in `reports/` + `reports/audit_reports/`

**Duration:** ~30-60 seconds

---

## OPTION B: Run Components Individually

### 1. Run Tests
```powershell
& "C:/Users/rishi/Anaconda python/python.exe" -m pytest tests/test_security_platform.py -v
```

**Tests:**
- Security rule engine (CloudTrail, MFA, encryption rules)
- Priority scoring logic
- Compliance mapping
- Anomaly detection

---

### 2. Train Models
```powershell
& "C:/Users/rishi/Anaconda python/python.exe" scripts/train_models.py
```

**What it does:**
1. Loads `data/config_drift_events.csv` (780 training events)
2. Trains **Random Forest** for ML risk scoring
3. Trains **Isolation Forest** for behavioral anomalies
4. Saves models to `models/` with metadata
5. Exports feature importance rankings

**Output:** 
- `models/random_forest.pkl` (1 MB)
- `models/random_forest.meta.json`
- `models/isolation_forest.pkl` (668 KB)
- `models/isolation_forest.meta.json`
- `reports/feature_importance.csv`
- `reports/model_metrics.json`

---

### 3. Score Events
```powershell
& "C:/Users/rishi/Anaconda python/python.exe" -c "
import sys
from pathlib import Path
import pandas as pd

ROOT = Path('.').resolve()
sys.path.insert(0, str(ROOT))

from backend.pipeline import DriftIntelligencePipeline

# Load test data
events = pd.read_csv(ROOT / 'data' / 'config_drift_events.csv')

# Initialize pipeline with pre-trained models
pipeline = DriftIntelligencePipeline(ROOT / 'models')

# Score events
scored = pipeline.score(events)

# Show results
print(f'Total events: {len(scored)}')
print(f'Critical: {(scored[\"priority_level\"] == \"CRITICAL\").sum()}')
print(f'High: {(scored[\"priority_level\"] == \"HIGH\").sum()}')
print(scored[['control_name', 'priority_level', 'priority_score']].head(10))
"
```

**What it does:**
1. Loads pre-trained models from `models/`
2. Enriches event features (timestamps, patterns)
3. Applies security rules (10 deterministic rules)
4. Runs ML risk scoring (Random Forest)
5. Detects behavioral anomalies (Isolation Forest)
6. Calculates final priority score (weighted combination)

**Output:** DataFrame with all scoring fields

---

### 4. Run Security Rules Engine (Standalone)
```powershell
& "C:/Users/rishi/Anaconda python/python.exe" -c "
import sys
from pathlib import Path
sys.path.insert(0, str(Path('.').resolve()))

from backend.security_rules import SecurityRuleEngine

# Initialize engine
engine = SecurityRuleEngine()

# Test with sample event
test_event = {
    'control_name': 'CloudTrail_Logging',
    'control_type': 'Logging',
    'change_type': 'Disable',
    'current_value': 'cloudtrail_enabled=false',
}

result = engine.evaluate(test_event)
print('Security Rule Evaluation:')
print(f'  Score: {result[\"security_rule_score\"]}/100')
print(f'  Level: {result[\"rule_risk_level\"]}')
print(f'  Matched Rules: {result[\"matched_rules\"]}')
print(f'  Remediation: {result[\"recommended_remediations\"]}')
print(f'  Compliance: {result[\"compliance_mappings\"]}')
"
```

**What it does:**
1. Tests a single event against all 10 security rules
2. Returns matching rules, scores, and remediation guidance
3. Maps to compliance frameworks (NIST, PCI-DSS, GDPR, CIS)

---

### 5. Test Anomaly Detection
```powershell
& "C:/Users/rishi/Anaconda python/python.exe" -c "
import sys
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path('.').resolve()))

from backend.anomaly_engine import BehavioralAnomalyEngine

# Load test data
events = pd.read_csv(Path('data/config_drift_events.csv').resolve())

# Initialize anomaly engine
anomaly = BehavioralAnomalyEngine(Path('models/isolation_forest.pkl').resolve())

# Predict anomalies
anomalies = anomaly.predict(events)

# Show results
print('Anomaly Detection:')
print(f'  Total events: {len(anomalies)}')
print(f'  Anomalies detected: {anomalies[\"anomaly_flag\"].sum()}')
print(f'  Mean anomaly score: {anomalies[\"anomaly_score\"].mean():.4f}')
print(f'  Mean confidence: {anomalies[\"anomaly_confidence\"].mean():.1f}%')
"
```

---

### 6. Generate Audit Reports
```powershell
& "C:/Users/rishi/Anaconda python/python.exe" -c "
import sys, json
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path('.').resolve()))

from backend.reporting import generate_executive_report, export_compliance_report
from backend.pipeline import DriftIntelligencePipeline

ROOT = Path('.').resolve()

# Load and score all events
events = pd.read_csv(ROOT / 'data' / 'config_drift_events.csv')
pipeline = DriftIntelligencePipeline(ROOT / 'models')
scored = pipeline.score(events)

# Generate reports
report_dir = ROOT / 'reports' / 'audit_reports'
report_dir.mkdir(parents=True, exist_ok=True)

# Executive summary
exec_path = generate_executive_report(scored, report_dir)
print(f'✅ Executive report: {exec_path.name}')

# Compliance mapping
comp_path = export_compliance_report(scored, report_dir)
print(f'✅ Compliance report: {comp_path.name}')

print(f'\nReports saved to: {report_dir}')
"
```

---

### 7. Validate Model (Test Suite)
```powershell
& "C:/Users/rishi/Anaconda python/python.exe" -c "
import sys
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path('.').resolve()))

from backend.validation_engine import ValidationEngine
from backend.pipeline import DriftIntelligencePipeline

ROOT = Path('.').resolve()

# Load test scenarios
scenarios = pd.read_csv(ROOT / 'data' / 'validation_scenarios.csv')

# Validate
pipeline = DriftIntelligencePipeline(ROOT / 'models')
validator = ValidationEngine(pipeline)
results, metrics = validator.validate(scenarios)

print(f'Validation Results:')
print(f'  Total scenarios: {metrics[\"total_scenarios\"]}')
print(f'  Passed: {metrics[\"passed_scenarios\"]}')
print(f'  Accuracy: {metrics[\"accuracy\"]:.1%}')
"
```

---

## OPTION C: Start Dashboard

### Method 1: Direct Command
```powershell
& "C:/Users/rishi/Anaconda python/python.exe" -m streamlit run dashboard/streamlit_app.py --server.port 8501
```

### Method 2: Via Script (if you create one)
```powershell
& "C:/Users/rishi/Anaconda python/python.exe" -c "
import subprocess
import sys

# Launch streamlit
subprocess.run([
    sys.executable, 
    '-m', 'streamlit', 'run',
    'dashboard/streamlit_app.py',
    '--server.port', '8501'
])
"
```

**After startup:**
1. Press `Enter` when prompted for email (skip onboarding)
2. Open browser: `http://localhost:8501`
3. Navigate 5 tabs:
   - **Executive Summary** → Risk distribution, heatmap
   - **Security Drift** → Anomaly timeline
   - **Compliance** → Framework exposure
   - **LLM Analyst** → AI narratives + remediation
   - **Model Assurance** → F1 score, accuracy

**Stop the dashboard:** Press `Ctrl+C` in terminal

---

## OPTION D: Parse Cloud Events (AWS + Azure)

```powershell
& "C:/Users/rishi/Anaconda python/python.exe" -c "
import sys
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path('.').resolve()))

from backend.cloudtrail_parser import CloudTrailParser
from backend.azure_parser import AzureAuditParser

ROOT = Path('.').resolve()

# Parse AWS CloudTrail
aws_parser = CloudTrailParser()
aws_events = aws_parser.parse_file(ROOT / 'data' / 'aws_cloudtrail_mock.json')
print(f'AWS CloudTrail events: {len(aws_events)}')

# Parse Azure Audit Logs
azure_parser = AzureAuditParser()
azure_events = azure_parser.parse_file(ROOT / 'data' / 'azure_audit_mock.json')
print(f'Azure Audit events: {len(azure_events)}')

# Convert to DataFrame
rows = [event.to_dict() for event in aws_events + azure_events]
df = pd.DataFrame(rows)
print(f'\nCombined cloud events: {len(df)}')
print(df[['source_system', 'control_type', 'change_type']].value_counts())
"
```

---

## Troubleshooting

### Issue: "Python was not found"
**Solution:** Use the full path or Anaconda Python:
```powershell
& "C:/Users/rishi/Anaconda python/python.exe" <command>
# or
py <command>
```

### Issue: "No module named 'backend'"
**Solution:** Ensure you're in the project root directory:
```powershell
cd "C:\Users\rishi\OneDrive\Documents\New project\security-drift-intelligence"
```

### Issue: "Model files not found"
**Solution:** Train models first:
```powershell
& "C:/Users/rishi/Anaconda python/python.exe" scripts/train_models.py
```

### Issue: Streamlit hangs on email prompt
**Solution:** Just press `Enter` to skip, or permanently disable in config:
```powershell
mkdir ~\.streamlit
"[browser]
gatherUsageStats = false" | Out-File ~\.streamlit\config.toml
```

---

## File Structure Reference

```
├── backend/
│   ├── anomaly_engine.py       (Isolation Forest anomaly detection)
│   ├── security_rules.py       (10 deterministic rules + remediation)
│   ├── priority_engine.py      (Risk scoring & prioritization)
│   ├── pipeline.py             (Orchestrates ML + rules)
│   ├── llm_copilot.py          (AI analysis narratives)
│   ├── reporting.py            (Report generation)
│   └── ...
├── dashboard/
│   └── streamlit_app.py        (Web UI with 5 tabs)
├── scripts/
│   ├── run_pipeline.py         (Full end-to-end execution)
│   └── train_models.py         (Model training)
├── data/
│   ├── config_drift_events.csv (780 training events)
│   ├── validation_scenarios.csv (26 test cases)
│   └── baseline_configs.json   (5 control baselines)
├── models/
│   ├── random_forest.pkl
│   ├── isolation_forest.pkl
│   └── *.meta.json
├── reports/
│   ├── scored_events.json      (Full analysis)
│   ├── model_metrics.json      (ML stats)
│   └── audit_reports/
│       ├── executive_audit_report.md
│       └── compliance_violations.csv
└── tests/
    └── test_security_platform.py
```

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| **Full pipeline** | `scripts/run_pipeline.py` |
| **Train models** | `scripts/train_models.py` |
| **Run tests** | `pytest tests/test_security_platform.py -v` |
| **Start dashboard** | `streamlit run dashboard/streamlit_app.py` |
| **Verify components** | `python verify_components.py` |
| **Check Python** | `py --version` |

---

**Need help with a specific file? Let me know which one!**
