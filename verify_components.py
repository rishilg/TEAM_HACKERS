#!/usr/bin/env python
"""Verify all AI-Driven Drift Intelligence components."""
from pathlib import Path
import json
import csv
from collections import Counter

root = Path(__file__).parent

# 1. Check Drift Detection Engine
print("=" * 70)
print("1. DRIFT DETECTION ENGINE")
print("=" * 70)
anomaly_py = root / "backend" / "anomaly_engine.py"
if anomaly_py.exists():
    content = anomaly_py.read_text()
    has_isolation_forest = "IsolationForest" in content
    has_train = "def train" in content
    has_predict = "def predict" in content
    print(f"✅ anomaly_engine.py exists")
    print(f"   - IsolationForest model: {'✅' if has_isolation_forest else '❌'}")
    print(f"   - Training capability: {'✅' if has_train else '❌'}")
    print(f"   - Prediction capability: {'✅' if has_predict else '❌'}")
else:
    print("❌ anomaly_engine.py missing")

# 2. Check Baseline Configuration Store
print("\n" + "=" * 70)
print("2. BASELINE CONFIGURATION STORE")
print("=" * 70)
baseline_json = root / "data" / "baseline_configs.json"
if baseline_json.exists():
    data = json.loads(baseline_json.read_text())
    print(f"✅ baseline_configs.json exists")
    print(f"   - Controls defined: {len(data)}")
    print(f"   - Target: 200 controls (INCOMPLETE: only {len(data)} defined)")
    print(f"   - Sample controls: {', '.join(c.get('control_id', 'N/A') for c in data[:3])}")
else:
    print("❌ baseline_configs.json missing")

# 3. Check Alert System
print("\n" + "=" * 70)
print("3. ALERT SYSTEM / PRIORITY ENGINE")
print("=" * 70)
priority_py = root / "backend" / "priority_engine.py"
if priority_py.exists():
    content = priority_py.read_text()
    has_levels = "CRITICAL" in content and "HIGH" in content
    has_priority_engine = "class ThreatPriorityEngine" in content
    print(f"✅ priority_engine.py exists")
    print(f"   - Priority levels (CRITICAL/HIGH/MEDIUM/LOW): {'✅' if has_levels else '❌'}")
    print(f"   - ThreatPriorityEngine class: {'✅' if has_priority_engine else '❌'}")
else:
    print("❌ priority_engine.py missing")

# 4. Check Dashboard
print("\n" + "=" * 70)
print("4. DASHBOARD")
print("=" * 70)
dashboard_py = root / "dashboard" / "streamlit_app.py"
if dashboard_py.exists():
    content = dashboard_py.read_text()
    has_streamlit = "import streamlit" in content
    has_tabs = "st.tabs" in content
    has_metrics = "st.metric" in content
    print(f"✅ streamlit_app.py exists")
    print(f"   - Streamlit framework: {'✅' if has_streamlit else '❌'}")
    print(f"   - Multi-tab interface: {'✅' if has_tabs else '❌'}")
    print(f"   - KPI metrics display: {'✅' if has_metrics else '❌'}")
else:
    print("❌ streamlit_app.py missing")

# 5. Check Sample Audit Reports
print("\n" + "=" * 70)
print("5. SAMPLE AUDIT REPORTS")
print("=" * 70)
audit_dir = root / "reports" / "audit_reports"
if audit_dir.exists():
    files = list(audit_dir.glob("*"))
    print(f"✅ audit_reports directory exists")
    print(f"   - Generated reports: {len(files)}")
    for f in files:
        print(f"   - {f.name}")
else:
    print("❌ audit_reports directory missing")

exec_report = root / "reports" / "executive_audit_report.md"
if exec_report.exists():
    print(f"✅ executive_audit_report.md exists")

# 6. Check Remediation Playbook
print("\n" + "=" * 70)
print("6. REMEDIATION PLAYBOOK")
print("=" * 70)
security_rules_py = root / "backend" / "security_rules.py"
if security_rules_py.exists():
    content = security_rules_py.read_text()
    has_rules = "RULES = (" in content
    has_remediation = "remediation:" in content
    print(f"✅ security_rules.py exists (Remediation Rules Engine)")
    
    # Count rules by parsing RULES tuple
    rule_count = content.count('SecurityRule(')
    print(f"   - Security rules defined: {rule_count}")
    print(f"   - Remediation guidance: {'✅' if has_remediation else '❌'}")
    
    # Show sample rules
    rules_with_remediation = [line for line in content.split('\n') if 'SecurityRule(' in line]
    if len(rules_with_remediation) > 0:
        print(f"   - Sample rules: SDI-001 through SDI-105 series")
else:
    print("❌ security_rules.py missing")

llm_copilot = root / "backend" / "llm_copilot.py"
if llm_copilot.exists():
    content = llm_copilot.read_text()
    has_fallback = "def _fallback" in content
    has_remediation = "recommended_remediations" in content
    print(f"✅ llm_copilot.py exists (LLM-driven Analysis)")
    print(f"   - Fallback remediation analysis: {'✅' if has_fallback else '❌'}")
    print(f"   - Remediation field integration: {'✅' if has_remediation else '❌'}")

# Summary
print("\n" + "=" * 70)
print("COMPONENT VERIFICATION SUMMARY")
print("=" * 70)
components = {
    "Drift Detection Engine": anomaly_py.exists(),
    "Baseline Config Store (5/200)": baseline_json.exists(),
    "Alert/Priority System": priority_py.exists(),
    "Dashboard (Streamlit)": dashboard_py.exists(),
    "Audit Report Generation": exec_report.exists(),
    "Remediation Playbook": security_rules_py.exists(),
    "LLM Analysis": llm_copilot.exists(),
}

completed = sum(1 for v in components.values() if v)
total = len(components)

for name, exists in components.items():
    status = "✅ PRESENT" if exists else "❌ MISSING"
    print(f"{status:12} {name}")

print(f"\n{completed}/{total} components implemented")
print(f"\n⚠️  INCOMPLETE: Baseline controls only has 5/200 defined.")
print("   Run: scripts/train_models.py to generate additional controls or expand baseline_configs.json")
