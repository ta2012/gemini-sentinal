# detect.py

# Core detection engine for Gemini Sentinel.

#

# Architecture:

# Events

#   -> Deterministic security rules

#   -> Findings

#   -> Correlated incidents

#   -> Gemini Sentinel reasoning

#   -> Groq fallback

#   -> Rule-based fallback

#

# Gemini is responsible for correlating multiple findings,

# reconstructing attack chains, assessing risk, predicting impact,

# and recommending a response.

from dotenv import load_dotenv

load_dotenv()


import os

import json
import time

import yaml

from datetime import datetime, timedelta

from dotenv import load_dotenv





# ---------------------------------------------------------

# Optional Gemini SDK

# ---------------------------------------------------------

try:

    from google import genai

    from google.genai import types



    HAS_GEMINI = True

except ImportError:

    HAS_GEMINI = False





# ---------------------------------------------------------

# Optional Groq SDK

# ---------------------------------------------------------

try:

    from groq import Groq



    HAS_GROQ = True

except ImportError:

    HAS_GROQ = False





# Load environment variables

load_dotenv()





# ---------------------------------------------------------

# Severity ranking

# ---------------------------------------------------------

SEVERITY_MAP = {

    "info": 1,

    "low": 2,

    "medium": 3,

    "high": 4,

    "critical": 5

}





# =========================================================

# BASIC FILE / DATA HELPERS

# =========================================================



def parse_timestamp(ts_str):

    """

    Convert ISO timestamp into datetime.

    Supports timestamps ending in Z and timestamps with milliseconds.

    """



    if ts_str.endswith("Z"):

        ts_str = ts_str[:-1]



    try:

        return datetime.strptime(

            ts_str,

            "%Y-%m-%dT%H:%M:%S"

        )

    except ValueError:

        return datetime.strptime(

            ts_str.split(".")[0],

            "%Y-%m-%dT%H:%M:%S"

        )





def load_rules(rules_path):

    """

    Load YAML security detection rules.

    """



    with open(rules_path, "r", encoding="utf-8") as f:

        return yaml.safe_load(f)





def load_events(events_path):

    """

    Load JSONL security events.

    """



    events = []



    with open(events_path, "r", encoding="utf-8") as f:

        for idx, line in enumerate(f):



            if line.strip():

                ev = json.loads(line)



                # Add a stable event ID.

                ev["event_id"] = idx



                events.append(ev)



    events.sort(

        key=lambda x: parse_timestamp(x["timestamp"])

    )



    return events





# =========================================================

# BASELINE DETECTION

# =========================================================



def check_baseline_deviation(
    agent_history,
    current_event,
    metric,
    threshold_multiplier,
    min_baseline_samples,
):
    """
    Evaluate baseline deviation while safely handling invalid telemetry.

    Historical period:
        Before the most recent 60-minute window.

    Current period:
        The most recent 60-minute window.

    Missing, nonnumeric, boolean, NaN, and infinite token costs
    are excluded from token-cost calculations.
    Call counts remain independent of token-cost validity.
    """

    import math

    def valid_number(value):
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
        )

    # Validate timestamps before performing calculations.
    try:
        t_curr = parse_timestamp(current_event["timestamp"])

        valid_history = []

        for event in agent_history:
            timestamp = event.get("timestamp")

            if not isinstance(timestamp, str):
                continue

            try:
                event_time = parse_timestamp(timestamp)
            except (ValueError, TypeError, AttributeError):
                continue

            valid_history.append((event_time, event))

        if not valid_history:
            return False, 0.0, 0.0, []

        valid_history.sort(key=lambda item: item[0])

        t_start = valid_history[0][0]

    except (KeyError, ValueError, TypeError, AttributeError):
        return False, 0.0, 0.0, []

    t_hist_end = t_curr - timedelta(minutes=60)

    if t_hist_end <= t_start:
        return False, 0.0, 0.0, []

    total_seconds = (t_hist_end - t_start).total_seconds()
    num_bins = int(total_seconds // 3600)

    if num_bins < min_baseline_samples:
        return False, 0.0, 0.0, []

    bin_values = [0.0] * num_bins

    # ---------------------------------------------------------
    # Historical baseline
    # ---------------------------------------------------------

    for event_time, event in valid_history:

        if event_time >= t_hist_end:
            continue

        bin_idx = int(
            (event_time - t_start).total_seconds() // 3600
        )

        if not (0 <= bin_idx < num_bins):
            continue

        if metric == "call_count":
            value = 1

        else:
            value = event.get(metric)

            if not valid_number(value):
                continue

        bin_values[bin_idx] += value

    hist_avg = sum(bin_values) / num_bins

    if hist_avg <= 0:
        return False, 0.0, hist_avg, []

    # ---------------------------------------------------------
    # Current window
    # ---------------------------------------------------------

    curr_val = 0.0
    matched_events = []

    for event_time, event in valid_history:

        if not (t_hist_end <= event_time <= t_curr):
            continue

        if metric == "call_count":
            value = 1

        else:
            value = event.get(metric)

            if not valid_number(value):
                continue

        curr_val += value
        matched_events.append(event)

    # ---------------------------------------------------------
    # Threshold comparison
    # ---------------------------------------------------------

    threshold = threshold_multiplier * hist_avg

    if curr_val >= threshold:
        return (
            True,
            curr_val,
            hist_avg,
            matched_events,
        )

    return (
        False,
        curr_val,
        hist_avg,
        [],
    )




# =========================================================

# RULE ENGINE

# =========================================================



def detect_findings(rules, events):

    """

    Run deterministic security rules over all events.

    """



    findings = []

    agent_histories = {}



    for i, ev in enumerate(events):



        agent_id = ev["agent_id"]



        if agent_id not in agent_histories:

            agent_histories[agent_id] = []



        agent_histories[agent_id].append(ev)



        for rule in rules:



            rule_id = rule["rule_id"]

            rule_type = rule["type"]

            severity = rule["severity"]



            # -------------------------------------------------

            # AI001 / AI002

            # -------------------------------------------------

            if rule_type == "baseline-deviation":



                if ev["action"] == "tool_call":



                    metric = rule["metric"]

                    mult = rule["threshold_multiplier"]

                    min_samples = rule["min_baseline_samples"]



                    (

                        is_spike,

                        curr,

                        avg,

                        matched

                    ) = check_baseline_deviation(

                        agent_histories[agent_id],

                        ev,

                        metric,

                        mult,

                        min_samples

                    )



                    if is_spike:



                        desc = (

                            f"Spike in {metric}: "

                            f"current window has {curr} "

                            f"(average baseline: {avg:.2f})"

                        )



                        findings.append({

                            "rule_id": rule_id,

                            "name": rule["name"],

                            "agent_id": agent_id,

                            "severity": severity,

                            "matched_events": matched,

                            "description": desc,

                            "timestamp": ev["timestamp"],

                            "gemini_context": rule.get(

                                "gemini_context",

                                ""

                            )

                        })



            # -------------------------------------------------

            # AI003 Scope Violation

            # -------------------------------------------------

            elif rule_type == "scope-violation":



                if ev["action"] == "tool_call":



                    tool = ev.get("tool_name")

                    allowed = ev.get(

                        "allowed_tools",

                        []

                    )



                    if tool and tool not in allowed:



                        desc = (

                            f"Scope violation: tool "

                            f"'{tool}' is not in allowed "

                            f"list {allowed}."

                        )



                        findings.append({

                            "rule_id": rule_id,

                            "name": rule["name"],

                            "agent_id": agent_id,

                            "severity": severity,

                            "matched_events": [ev],

                            "description": desc,

                            "timestamp": ev["timestamp"],

                            "gemini_context": rule.get(

                                "gemini_context",

                                ""

                            )

                        })



            # -------------------------------------------------

            # AI004 Missing Approval

            # -------------------------------------------------

            elif rule_type == "missing-approval":



                risk = ev.get("risk_scope")

                approved = ev.get(

                    "human_approved",

                    False

                )



                risk_scopes = rule.get(

                    "risk_scopes",

                    []

                )



                if (

                    risk in risk_scopes

                    and not approved

                ):



                    desc = (

                        f"Missing approval: High-risk "

                        f"action in scope '{risk}' "

                        f"performed without human sign-off."

                    )



                    findings.append({

                        "rule_id": rule_id,

                        "name": rule["name"],

                        "agent_id": agent_id,

                        "severity": severity,

                        "matched_events": [ev],

                        "description": desc,

                        "timestamp": ev["timestamp"],

                        "gemini_context": rule.get(

                            "gemini_context",

                            ""

                        )

                    })



            # -------------------------------------------------

            # AI005 Memory Poisoning

            # -------------------------------------------------

            elif rule_type == "origin-mismatch":



                is_write = ev.get(

                    "memory_write",

                    False

                )



                source = ev.get(

                    "memory_source"

                )



                untrusted = rule.get(

                    "untrusted_sources",

                    []

                )



                if (

                    is_write

                    and source in untrusted

                ):



                    desc = (

                        f"Memory poisoning: Context "

                        f"written from untrusted source "

                        f"'{source}'."

                    )



                    findings.append({

                        "rule_id": rule_id,

                        "name": rule["name"],

                        "agent_id": agent_id,

                        "severity": severity,

                        "matched_events": [ev],

                        "description": desc,

                        "timestamp": ev["timestamp"],

                        "gemini_context": rule.get(

                            "gemini_context",

                            ""

                        )

                    })



    return findings





# =========================================================

# FINDING CORRELATION

# =========================================================



def correlate_findings(
    findings,
    correlation_window_minutes=60,
):
    """
    Groups findings from the same agent into incidents.

    A finding joins an incident only if it falls within the
    configured window measured from that incident's start time.

    This prevents repeated findings from extending a single
    incident indefinitely.
    """

    if not findings:
        return []

    findings.sort(
        key=lambda finding: parse_timestamp(
            finding["timestamp"]
        )
    )

    incidents = []
    agent_incidents = {}

    window_seconds = correlation_window_minutes * 60

    for finding in findings:
        agent_id = finding["agent_id"]
        finding_time = parse_timestamp(
            finding["timestamp"]
        )

        matched_incident = None

        # Inspect recent incidents for this agent.
        for incident in reversed(
            agent_incidents.get(agent_id, [])
        ):
            incident_start = parse_timestamp(
                incident["start_time"]
            )

            elapsed_seconds = (
                finding_time - incident_start
            ).total_seconds()

            if 0 <= elapsed_seconds <= window_seconds:
                matched_incident = incident
                break

        if matched_incident is None:
            incident_id = (
                f"INC-{len(incidents) + 1:03d}"
            )

            matched_incident = {
                "incident_id": incident_id,
                "agent_id": agent_id,
                "severity": finding["severity"],
                "start_time": finding["timestamp"],
                "end_time": finding["timestamp"],
                "findings": [],
                "llm_summary": None,
            }

            incidents.append(matched_incident)

            agent_incidents.setdefault(
                agent_id, []
            ).append(matched_incident)

        # Add the finding to its incident.
        matched_incident["findings"].append(
            finding
        )

        # Preserve the latest event timestamp.
        if finding_time > parse_timestamp(
            matched_incident["end_time"]
        ):
            matched_incident["end_time"] = (
                finding["timestamp"]
            )

        # Preserve the highest severity among findings.
        current_rank = SEVERITY_MAP.get(
            matched_incident["severity"].lower(),
            0,
        )

        finding_rank = SEVERITY_MAP.get(
            finding["severity"].lower(),
            0,
        )

        if finding_rank > current_rank:
            matched_incident["severity"] = (
                finding["severity"]
            )

    return incidents



# =========================================================

# EVENT PREPARATION FOR GEMINI

# =========================================================



def build_incident_context(incident):

    """

    Convert an incident into a compact structured

    representation for Gemini.

    """



    findings_summary = []



    for f in incident["findings"]:



        finding_data = {

            "rule_id": f["rule_id"],

            "rule_name": f["name"],

            "severity": f["severity"],

            "description": f["description"],

            "timestamp": f["timestamp"],

            "gemini_context": f.get(

                "gemini_context",

                ""

            ),

            "events": []

        }



        for ev in f.get(

            "matched_events",

            []

        ):



            finding_data["events"].append({

                "event_id": ev.get("event_id"),

                "timestamp": ev.get("timestamp"),

                "action": ev.get("action"),

                "tool_name": ev.get("tool_name"),

                "allowed_tools": ev.get(

                    "allowed_tools"

                ),

                "target_resource": ev.get(

                    "target_resource"

                ),

                "invoked_by": ev.get(

                    "invoked_by"

                ),

                "token_cost": ev.get(

                    "token_cost"

                ),

                "human_approved": ev.get(

                    "human_approved"

                ),

                "risk_scope": ev.get(

                    "risk_scope"

                ),

                "memory_write": ev.get(

                    "memory_write"

                ),

                "memory_source": ev.get(

                    "memory_source"

                ),

                "raw_msg": ev.get(

                    "raw_msg"

                )

            })



        findings_summary.append(

            finding_data

        )



    return {

        "incident_id": incident["incident_id"],

        "agent_id": incident["agent_id"],

        "severity": incident["severity"],

        "start_time": incident["start_time"],

        "end_time": incident["end_time"],

        "findings": findings_summary

    }





# =========================================================

# FALLBACK SUMMARY

# =========================================================



def generate_fallback_summary(

    agent_id,

    findings

):

    """

    Rule-based fallback when Gemini and Groq

    are unavailable.

    """



    primary_finding = findings[0]



    verdict = (

        f"Alert: Detected "

        f"{primary_finding['name']} and other "

        f"potential policy violations for agent "

        f"{agent_id}."

    )



    severity_reasoning = (

        f"Incident marked as "

        f"{primary_finding['severity'].upper()} "

        f"severity due to {len(findings)} "

        f"correlated security event(s), including "

        f"rule {primary_finding['rule_id']} "

        f"({primary_finding['name']})."

    )



    evidence = []



    for f in findings:



        for ev in f.get(

            "matched_events",

            []

        ):



            time_str = ev.get(

                "timestamp",

                ""

            )



            tool = ev.get(

                "tool_name",

                "None"

            )



            if f["rule_id"] in [

                "AI001",

                "AI002"

            ]:



                evidence.append(

                    f"[{time_str}] "

                    f"Tool/cost spike: "

                    f"{f['description']}"

                )



            elif f["rule_id"] == "AI003":



                evidence.append(

                    f"[{time_str}] "

                    f"Scope Violation: "

                    f"Tool '{tool}' ran outside "

                    f"allowed list "

                    f"{ev.get('allowed_tools')}"

                )



            elif f["rule_id"] == "AI004":



                evidence.append(

                    f"[{time_str}] "

                    f"Missing Approval: "

                    f"Tool '{tool}' in risk scope "

                    f"'{ev.get('risk_scope')}' "

                    f"executed without approval"

                )



            elif f["rule_id"] == "AI005":



                evidence.append(

                    f"[{time_str}] "

                    f"Memory Poisoning: "

                    f"Memory write triggered from "

                    f"untrusted source "

                    f"'{ev.get('memory_source')}'"

                )



    unique_evidence = list(

        dict.fromkeys(evidence)

    )[:5]



    if not unique_evidence:



        unique_evidence = [

            f"Matched rule "

            f"{primary_finding['rule_id']} "

            f"for agent {agent_id}"

        ]



    suggested_action = (

        "Review agent prompts and system "

        "configurations. Set up additional "

        "human-in-the-loop validation barriers."

    )



    rule_ids = {

        f["rule_id"]

        for f in findings

    }



    if "AI003" in rule_ids:



        suggested_action = (

            "Audit the agent's tool execution "

            "permissions immediately. Restrict "

            "unauthorized tool access."

        )



    elif "AI005" in rule_ids:



        suggested_action = (

            "Invalidate the affected session "

            "memory context. Investigate recent "

            "documents or inputs matching the "

            "untrusted memory source."

        )



    return {

        "verdict": verdict,

        "severity_reasoning": severity_reasoning,

        "evidence": unique_evidence,

        "suggested_action": suggested_action,



        # Gemini Sentinel-compatible fields

        "attack_chain": [],

        "risk_score": SEVERITY_MAP.get(

            primary_finding["severity"].lower(),

            3

        ) * 20,

        "confidence": 60,

        "potential_impact": (

            "Potential security impact requires "

            "analyst investigation."

        ),

        "predicted_next_step": (

            "Investigate correlated events "

            "and restrict suspicious agent activity."

        ),

        "response_priority": (

            primary_finding["severity"].upper()

        )

    }





# =========================================================

# GEMINI SENTINEL

# =========================================================



def analyze_with_gemini(

    incident,

    context

):

    """

    Ask Gemini to perform security reasoning over

    the correlated incident.



    Gemini does NOT replace deterministic rules.

    It reasons over the evidence produced by those rules.

    """



    api_key = os.environ.get(

        "GEMINI_API_KEY"

    )



    if not HAS_GEMINI:

        raise RuntimeError(

            "google-genai package is not installed."

        )



    if not api_key:

        raise RuntimeError(

            "GEMINI_API_KEY is not configured."

        )



    model_name = os.environ.get(

        "GEMINI_MODEL",

        "gemini-3.8-flash"

    )



    client = genai.Client(

        api_key=api_key

    )



    prompt = f"""

You are Gemini Sentinel, an AI-agent security

reasoning engine operating inside a SOC.



Your job is NOT to blindly trust the rule names.

The deterministic rules provide evidence.



You must correlate the evidence and determine

whether multiple events form a meaningful attack chain.



Analyze the following incident:



{json.dumps(context, indent=2)}



IMPORTANT SECURITY REASONING REQUIREMENTS:



1. Reconstruct the chronological sequence.

2. Identify relationships between separate findings.

3. Distinguish isolated policy violations from a

   coordinated attack chain.

4. Pay special attention to:

   - prompt injection

   - memory poisoning

   - privilege escalation

   - scope violations

   - missing human approval

   - sensitive actions

   - attempts to delete evidence

5. Do not invent events that are not present.

6. Base your confidence on the supplied evidence.

7. Explain why the sequence is dangerous.

8. Predict the most plausible next security consequence.

9. Recommend a practical SOC response.

10. If the evidence does NOT support a coordinated attack,

    explicitly say so.



Return ONLY valid JSON.



Use EXACTLY this structure:



{{

  "verdict": "One concise security verdict.",

  "severity_reasoning": "Detailed explanation of why the incident has its severity.",

  "evidence": [

    "Specific evidence item 1",

    "Specific evidence item 2",

    "Specific evidence item 3"

  ],

  "suggested_action": "Recommended immediate SOC action.",

  "attack_chain": [

    "Step 1",

    "Step 2",

    "Step 3"

  ],

  "risk_score": 0,

  "confidence": 0,

  "potential_impact": "What could happen if the behavior continues.",

  "predicted_next_step": "Most plausible next attacker/agent action.",

  "response_priority": "LOW | MEDIUM | HIGH | CRITICAL"

}}



risk_score must be an integer from 0 to 100.

confidence must be an integer from 0 to 100.

"""



    # Retry temporary Gemini availability/rate-limit errors before falling back.
    max_retries = 3
    response = None

    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    response_mime_type="application/json"
                )
            )
            break
        except Exception as exc:
            if attempt == max_retries - 1:
                raise

            wait_time = 2 ** attempt
            print(
                f"Gemini temporary failure (attempt {attempt + 1}/{max_retries}): "
                f"{exc}. Retrying in {wait_time}s..."
            )
            time.sleep(wait_time)



    content = response.text.strip()



    # Defensive cleanup in case the model returns markdown.

    if content.startswith("```"):



        lines = content.splitlines()



        if lines and lines[0].startswith("```"):

            lines = lines[1:]



        if lines and lines[-1].startswith("```"):

            lines = lines[:-1]



        content = "\n".join(

            lines

        ).strip()



    parsed = json.loads(content)



    # Make sure required keys exist.

    parsed.setdefault(

        "verdict",

        "Gemini generated no verdict."

    )



    parsed.setdefault(

        "severity_reasoning",

        "No severity reasoning returned."

    )



    parsed.setdefault(

        "evidence",

        []

    )



    parsed.setdefault(

        "suggested_action",

        "Investigate the incident."

    )



    parsed.setdefault(

        "attack_chain",

        []

    )



    parsed.setdefault(

        "risk_score",

        0

    )



    parsed.setdefault(

        "confidence",

        0

    )



    parsed.setdefault(

        "potential_impact",

        "Unknown."

    )



    parsed.setdefault(

        "predicted_next_step",

        "Continue investigation."

    )



    parsed.setdefault(

        "response_priority",

        incident["severity"].upper()

    )



    return parsed





# =========================================================

# GROQ FALLBACK

# =========================================================



def analyze_with_groq(

    incident,

    context

):

    """

    Existing Groq LLM path preserved as fallback.

    """



    api_key = os.environ.get(

        "GROQ_API_KEY"

    )



    if not HAS_GROQ:

        raise RuntimeError(

            "Groq package is not installed."

        )



    if not api_key:

        raise RuntimeError(

            "GROQ_API_KEY is not configured."

        )



    client = Groq(

        api_key=api_key

    )



    prompt = f"""

You are a professional SOC security analyst.



Analyze this AI-agent security incident:



{json.dumps(context, indent=2)}



Return ONLY valid JSON with these keys:



{{

  "verdict": "...",

  "severity_reasoning": "...",

  "evidence": ["...", "..."],

  "suggested_action": "...",

  "attack_chain": ["...", "..."],

  "risk_score": 0,

  "confidence": 0,

  "potential_impact": "...",

  "predicted_next_step": "...",

  "response_priority": "LOW | MEDIUM | HIGH | CRITICAL"

}}



Do not invent evidence.

Use only the supplied events and findings.

"""



    response = client.chat.completions.create(

        model="openai/gpt-oss-120b",

        messages=[

            {

                "role": "system",

                "content": (

                    "You are a professional SOC "

                    "security copilot. Output raw "

                    "JSON only."

                )

            },

            {

                "role": "user",

                "content": prompt

            }

        ],

        temperature=0.1

    )



    content = (

        response

        .choices[0]

        .message

        .content

        .strip()

    )



    if content.startswith("```"):



        lines = content.splitlines()



        if lines and lines[0].startswith("```"):

            lines = lines[1:]



        if lines and lines[-1].startswith("```"):

            lines = lines[:-1]



        content = "\n".join(

            lines

        ).strip()



    return json.loads(content)





# =========================================================

# LLM / GEMINI ORCHESTRATION

# =========================================================



def summarize_incidents(incidents):

    """

    Analyze incidents using:



    1. Gemini Sentinel

    2. Groq fallback

    3. Rule-based fallback



    This keeps the application functional even when

    an external LLM is unavailable.

    """



    for inc in incidents:



        agent_id = inc["agent_id"]



        context = build_incident_context(

            inc

        )



        # -------------------------------------------------

        # PRIMARY: GEMINI

        # -------------------------------------------------

        try:



            print(

                f"Analyzing incident "

                f"{inc['incident_id']} "

                f"with Gemini Sentinel..."

            )



            parsed_summary = analyze_with_gemini(

                inc,

                context

            )



            inc["llm_summary"] = (

                parsed_summary

            )



            # Explicitly mark the engine.

            inc["analysis_engine"] = (

                "Gemini Sentinel"

            )



            print(

                f"Gemini Sentinel successfully "

                f"analyzed incident "

                f"{inc['incident_id']}."

            )



            continue



        except Exception as gemini_error:



            print(

                f"Gemini analysis failed for "

                f"{inc['incident_id']}: "

                f"{gemini_error}"

            )



        # -------------------------------------------------

        # SECONDARY: GROQ

        # -------------------------------------------------

        try:



            print(

                f"Trying Groq fallback for "

                f"{inc['incident_id']}..."

            )



            parsed_summary = analyze_with_groq(

                inc,

                context

            )



            inc["llm_summary"] = (

                parsed_summary

            )



            inc["analysis_engine"] = (

                "Groq Fallback"

            )



            print(

                f"Groq successfully analyzed "

                f"incident {inc['incident_id']}."

            )



            continue



        except Exception as groq_error:



            print(

                f"Groq analysis failed for "

                f"{inc['incident_id']}: "

                f"{groq_error}"

            )



        # -------------------------------------------------

        # FINAL: RULE-BASED FALLBACK

        # -------------------------------------------------

        inc["llm_summary"] = (

            generate_fallback_summary(

                agent_id,

                inc["findings"]

            )

        )



        inc["analysis_engine"] = (

            "Rule-Based Fallback"

        )



        print(

            f"Using rule-based fallback for "

            f"incident {inc['incident_id']}."

        )





# =========================================================

# MAIN DETECTION PIPELINE

# =========================================================



def run_detection_pipeline(

    rules_path="rules.yaml",

    events_path="events.jsonl",

    output_path="incidents.json"

):

    """

    Complete Gemini Sentinel detection pipeline.

    """



    print(

        "Starting Gemini Sentinel detection pipeline..."

    )



    # -------------------------------------------------

    # Load

    # -------------------------------------------------

    rules = load_rules(

        rules_path

    )



    events = load_events(

        events_path

    )



    print(

        f"Loaded {len(rules)} rules "

        f"and {len(events)} events."

    )



    # -------------------------------------------------

    # Deterministic detection

    # -------------------------------------------------

    findings = detect_findings(

        rules,

        events

    )



    print(

        f"Detected {len(findings)} "

        f"policy violations/findings."

    )



    # -------------------------------------------------

    # Correlation

    # -------------------------------------------------

    incidents = correlate_findings(

        findings,

        correlation_window_minutes=60

    )



    print(

        f"Correlated findings into "

        f"{len(incidents)} unique incident(s)."

    )



    # -------------------------------------------------

    # Gemini Sentinel reasoning

    # -------------------------------------------------

    summarize_incidents(

        incidents

    )



    # -------------------------------------------------

    # Save output

    # -------------------------------------------------

    with open(

        output_path,

        "w",

        encoding="utf-8"

    ) as f:



        json.dump(

            incidents,

            f,

            indent=2

        )



    print(

        f"Successfully wrote incidents "

        f"output to {output_path}"

    )



    return incidents





# =========================================================

# CLI ENTRY POINT

# =========================================================



if __name__ == "__main__":



    run_detection_pipeline()