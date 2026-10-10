import json
from unittest.mock import patch

from dotenv import load_dotenv

load_dotenv()

import detect

rules = detect.load_rules("rules.yaml")
events = detect.load_events("events.jsonl")
findings = detect.detect_findings(rules, events)
incidents = detect.correlate_findings(
    findings,
    correlation_window_minutes=60,
)

if not incidents:
    raise SystemExit("No incidents were generated.")

test_incident = incidents[:1]

print(f"Testing fallback for {test_incident[0]['incident_id']}...")

with patch(
    "detect.analyze_with_gemini",
    side_effect=RuntimeError("Simulated Gemini outage"),
):
    detect.summarize_incidents(test_incident)

incident = test_incident[0]

print("\nAnalysis engine:", incident.get("analysis_engine"))
print("\nSummary:")
print(json.dumps(incident.get("llm_summary"), indent=2))

if incident.get("analysis_engine") == "Groq Fallback":
    print("\nSUCCESS: Groq fallback is working!")
elif incident.get("analysis_engine") == "Rule-Based Fallback":
    print("\nWARNING: Groq also failed; inspect the terminal errors.")
else:
    print("\nUnexpected analysis engine. Inspect the orchestration logic.")