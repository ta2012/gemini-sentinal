"""
Gemini Sentinel — Synthetic Security Event Generator

Generates reproducible synthetic events for testing:
- Normal agent activity
- Tool authorization violations
- Human approval violations
- Memory poisoning
- Abnormal token usage and call bursts
- Data exfiltration attempts
- Multi-agent attack sequences
- API and infrastructure failures
- Telemetry edge cases
- Containment and recovery

Output:
    events.jsonl

Uses only the Python standard library.
"""

import argparse
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

SEED = 42
TARGET_EVENTS = 5500

AGENTS = {
    "support-agent-01": {
        "agent_type": "autonomous",
        "allowed_tools": [
            "read_ledger",
            "generate_report",
            "fetch_tickets",
        ],
    },
    "finance-agent-02": {
        "agent_type": "human-in-the-loop",
        "allowed_tools": [
            "read_ledger",
            "approve_invoice",
        ],
    },
    "coder-agent-03": {
        "agent_type": "autonomous",
        "allowed_tools": [
            "read_code",
            "update_context",
            "run_tests",
        ],
    },
    "comms-agent-04": {
        "agent_type": "human-in-the-loop",
        "allowed_tools": [
            "send_customer_email",
            "fetch_tickets",
        ],
    },
    "search-agent-05": {
        "agent_type": "autonomous",
        "allowed_tools": [
            "web_search",
            "summarize_results",
        ],
    },
    "analytics-agent-06": {
        "agent_type": "autonomous",
        "allowed_tools": [
            "query_warehouse",
            "generate_report",
        ],
    },
    "research-agent-07": {
        "agent_type": "autonomous",
        "allowed_tools": [
            "web_search",
            "summarize_results",
            "update_context",
        ],
    },
    "deployment-agent-08": {
        "agent_type": "human-in-the-loop",
        "allowed_tools": [
            "read_code",
            "run_tests",
        ],
    },
}


BASE_TIME = datetime(2026, 10, 10, 0, 0, 0, tzinfo=timezone.utc)


# Keep this schema compatible with the original generator.
EVENT_FIELDS = [
    "timestamp",
    "agent_id",
    "agent_type",
    "action",
    "tool_name",
    "allowed_tools",
    "target_resource",
    "invoked_by",
    "token_cost",
    "human_approved",
    "risk_scope",
    "memory_write",
    "memory_source",
    "raw_msg",
]


# ============================================================
# EVENT CREATION
# ============================================================

def timestamp_string(value):
    """Return an ISO timestamp compatible with the original dataset."""
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(
    rng,
    timestamp,
    agent_id,
    action="tool_call",
    tool_name=None,
    target_resource="internal_db",
    invoked_by=None,
    token_cost=None,
    human_approved=False,
    risk_scope=None,
    memory_write=False,
    memory_source=None,
    raw_msg="Routine agent activity",
    allowed_tools=None,
    agent_type=None,
):
    """Create one event using the original event schema."""

    config = AGENTS.get(
        agent_id,
        {
            "agent_type": "autonomous",
            "allowed_tools": [],
        },
    )

    if agent_type is None:
        agent_type = config["agent_type"]

    if allowed_tools is None:
        allowed_tools = list(config["allowed_tools"])

    if tool_name is None:
        tool_name = rng.choice(allowed_tools or ["unknown_tool"])

    if invoked_by is None:
        invoked_by = f"agent:{agent_id}"

    if token_cost is None:
        token_cost = rng.randint(50, 500)

    return {
        "timestamp": timestamp_string(timestamp),
        "agent_id": agent_id,
        "agent_type": agent_type,
        "action": action,
        "tool_name": tool_name,
        "allowed_tools": allowed_tools,
        "target_resource": target_resource,
        "invoked_by": invoked_by,
        "token_cost": token_cost,
        "human_approved": human_approved,
        "risk_scope": risk_scope,
        "memory_write": memory_write,
        "memory_source": memory_source,
        "raw_msg": raw_msg,
    }


def add_event(events, rng, timestamp, agent_id, **kwargs):
    events.append(
        make_event(
            rng=rng,
            timestamp=timestamp,
            agent_id=agent_id,
            **kwargs,
        )
    )


# ============================================================
# SCENARIO 1: NORMAL ACTIVITY
# ============================================================

def generate_normal_events(events, rng, count):
    """Generate legitimate routine activity across different agents."""

    agent_ids = list(AGENTS.keys())

    normal_tools = {
        "support-agent-01": [
            ("read_ledger", "internal_db"),
            ("generate_report", "report_service"),
            ("fetch_tickets", "ticket_service"),
        ],
        "finance-agent-02": [
            ("read_ledger", "internal_db"),
            ("approve_invoice", "finance_workflow"),
        ],
        "coder-agent-03": [
            ("read_code", "repository"),
            ("run_tests", "test_runner"),
            ("update_context", "agent_memory"),
        ],
        "comms-agent-04": [
            ("fetch_tickets", "ticket_service"),
            ("send_customer_email", "email_server"),
        ],
        "search-agent-05": [
            ("web_search", "search_api"),
            ("summarize_results", "report_service"),
        ],
        "analytics-agent-06": [
            ("query_warehouse", "analytics_warehouse"),
            ("generate_report", "report_service"),
        ],
        "research-agent-07": [
            ("web_search", "search_api"),
            ("summarize_results", "report_service"),
        ],
        "deployment-agent-08": [
            ("read_code", "repository"),
            ("run_tests", "test_runner"),
        ],
    }

    current = BASE_TIME

    for i in range(count):
        agent_id = rng.choice(agent_ids)
        tool_name, resource = rng.choice(normal_tools[agent_id])

        timestamp = current + timedelta(
            seconds=i * rng.randint(2, 12)
        )

        is_memory_write = (
            tool_name == "update_context"
            and rng.random() < 0.65
        )

        approved = (
            tool_name in {
                "approve_invoice",
                "send_customer_email",
            }
            and rng.random() < 0.95
        )

        add_event(
            events,
            rng,
            timestamp,
            agent_id,
            action=(
                "memory_write"
                if is_memory_write
                else "tool_call"
            ),
            tool_name=tool_name,
            target_resource=resource,
            token_cost=rng.randint(50, 600),
            human_approved=approved,
            risk_scope=(
                "financial"
                if tool_name == "approve_invoice"
                else (
                    "external_communication"
                    if tool_name == "send_customer_email"
                    else None
                )
            ),
            memory_write=is_memory_write,
            memory_source=(
                "internal"
                if is_memory_write
                else None
            ),
            raw_msg=(
                "Routine authorized operation"
            ),
        )


# ============================================================
# SCENARIO 2: TOOL AUTHORIZATION VIOLATIONS
# ============================================================

def generate_tool_violations(events, rng, count):
    agents = list(AGENTS.keys())

    unauthorized_tools = [
        ("transfer_funds", "bank_api", "financial"),
        ("delete_database", "production_db", "data_deletion"),
        ("export_customer_records", "customer_db", "data_exfiltration"),
        ("modify_access_policy", "identity_service", "privilege_change"),
        ("purge_logs", "audit_storage", "data_deletion"),
        ("disable_monitoring", "security_monitor", "security_evasion"),
        ("read_secret_store", "secret_vault", "credential_access"),
    ]

    for i in range(count):
        agent_id = rng.choice(agents)
        tool, resource, scope = rng.choice(unauthorized_tools)

        timestamp = BASE_TIME + timedelta(
            hours=2,
            seconds=i * rng.randint(5, 30),
        )

        add_event(
            events,
            rng,
            timestamp,
            agent_id,
            tool_name=tool,
            target_resource=resource,
            token_cost=rng.randint(100, 1800),
            human_approved=False,
            risk_scope=scope,
            raw_msg=(
                f"Tool authorization test: attempted {tool}"
            ),
        )


# ============================================================
# SCENARIO 3: APPROVAL VIOLATIONS
# ============================================================

def generate_approval_violations(events, rng, count):
    agents = [
        "finance-agent-02",
        "comms-agent-04",
        "deployment-agent-08",
    ]

    operations = [
        (
            "transfer_funds",
            "bank_api",
            "financial",
        ),
        (
            "send_customer_email",
            "email_server",
            "external_communication",
        ),
        (
            "deploy_release",
            "production_environment",
            "deployment",
        ),
        (
            "approve_invoice",
            "finance_workflow",
            "financial",
        ),
    ]

    for i in range(count):
        agent_id = rng.choice(agents)
        tool, resource, scope = rng.choice(operations)

        variant = i % 4

        if variant == 0:
            message = "Sensitive operation attempted without approval"
            approved = False

        elif variant == 1:
            message = "Approval metadata missing or unavailable"
            approved = False

        elif variant == 2:
            message = "Approval exists but does not match the requested action"
            approved = False

        else:
            message = "Authorized operation with explicit approval"
            approved = True

        add_event(
            events,
            rng,
            BASE_TIME + timedelta(
                hours=4,
                seconds=i * 25,
            ),
            agent_id,
            tool_name=tool,
            target_resource=resource,
            token_cost=rng.randint(100, 1200),
            human_approved=approved,
            risk_scope=scope,
            raw_msg=message,
        )


# ============================================================
# SCENARIO 4: MEMORY SAFETY
# ============================================================

def generate_memory_events(events, rng, count):
    sources = [
        "internal",
        "verified_document",
        "untrusted_tool_output",
        "external_document",
        "web_content",
        "unknown_source",
    ]

    for i in range(count):
        source = sources[i % len(sources)]

        suspicious = source in {
            "untrusted_tool_output",
            "external_document",
            "web_content",
            "unknown_source",
        }

        messages = (
            [
                "Attempt to persist untrusted external instructions",
                "Retrieved content requests modification of agent behavior",
                "External tool output contains instructions requiring review",
                "Unverified content proposed for long-term memory",
            ]
            if suspicious
            else [
                "Save verified internal execution notes",
                "Update memory with reviewed project information",
                "Store approved task context",
            ]
        )

        add_event(
            events,
            rng,
            BASE_TIME + timedelta(
                hours=6,
                seconds=i * 18,
            ),
            rng.choice([
                "coder-agent-03",
                "research-agent-07",
            ]),
            action="memory_write",
            tool_name="update_context",
            target_resource="agent_memory",
            token_cost=rng.randint(80, 700),
            human_approved=False,
            risk_scope=(
                "memory_integrity"
                if suspicious
                else None
            ),
            memory_write=True,
            memory_source=source,
            raw_msg=rng.choice(messages),
        )


# ============================================================
# SCENARIO 5: TOKEN SPIKES AND CALL BURSTS
# ============================================================

def generate_anomaly_events(events, rng, count):
    agents = list(AGENTS.keys())

    for i in range(count):
        burst = i % 3 == 0

        token_cost = (
            rng.randint(15000, 50000)
            if burst
            else rng.randint(2000, 6000)
        )

        add_event(
            events,
            rng,
            BASE_TIME + timedelta(
                hours=8,
                seconds=i * (
                    rng.randint(1, 4)
                    if burst
                    else rng.randint(30, 180)
                ),
            ),
            rng.choice(agents),
            tool_name="generate_report",
            target_resource="report_service",
            token_cost=token_cost,
            raw_msg=(
                "Unusual token consumption; investigate workload"
                if burst
                else "Elevated but potentially legitimate workload"
            ),
        )


# ============================================================
# SCENARIO 6: DATA EXFILTRATION ATTEMPTS
# ============================================================

def generate_exfiltration_events(events, rng, count):
    scenarios = [
        (
            "export_customer_records",
            "external_endpoint",
            "data_exfiltration",
            "Attempted export of customer records to an external destination",
        ),
        (
            "upload_file",
            "unapproved_storage",
            "data_exfiltration",
            "Attempted upload to an unapproved storage destination",
        ),
        (
            "read_secret_store",
            "secret_vault",
            "credential_access",
            "Attempted access to a restricted secret resource",
        ),
        (
            "query_customer_database",
            "customer_db",
            "sensitive_data_access",
            "Unusual query against sensitive customer records",
        ),
    ]

    for i in range(count):
        tool, resource, scope, message = scenarios[i % len(scenarios)]

        add_event(
            events,
            rng,
            BASE_TIME + timedelta(
                hours=10,
                seconds=i * 35,
            ),
            rng.choice(list(AGENTS.keys())),
            tool_name=tool,
            target_resource=resource,
            token_cost=rng.randint(100, 2500),
            human_approved=False,
            risk_scope=scope,
            raw_msg=message,
        )


# ============================================================
# SCENARIO 7: MULTI-AGENT ATTACK CHAINS
# ============================================================

def generate_attack_chains(events, rng, count):
    """
    Generate related events across agents.

    The original schema has no scenario_id field, so correlation
    must rely on timestamps, agent identities, resources and actions.
    """

    chains = [
        [
            (
                "research-agent-07",
                "web_search",
                "external_document",
                "Retrieved external content requiring validation",
            ),
            (
                "research-agent-07",
                "update_context",
                "agent_memory",
                "Attempted persistence of retrieved instructions",
            ),
            (
                "coder-agent-03",
                "read_code",
                "repository",
                "Follow-up repository inspection",
            ),
            (
                "deployment-agent-08",
                "deploy_release",
                "production_environment",
                "Unexpected deployment attempt requires review",
            ),
        ],
        [
            (
                "support-agent-01",
                "read_ledger",
                "internal_db",
                "Initial access to internal ledger",
            ),
            (
                "finance-agent-02",
                "transfer_funds",
                "bank_api",
                "Financial action attempted without matching approval",
            ),
            (
                "analytics-agent-06",
                "export_customer_records",
                "customer_db",
                "Sensitive data export attempt",
            ),
            (
                "support-agent-01",
                "purge_logs",
                "audit_storage",
                "Attempted audit-log deletion after suspicious activity",
            ),
        ],
        [
            (
                "search-agent-05",
                "web_search",
                "search_api",
                "Routine external search",
            ),
            (
                "research-agent-07",
                "update_context",
                "agent_memory",
                "External information submitted to persistent memory",
            ),
            (
                "coder-agent-03",
                "run_tests",
                "test_runner",
                "Code validation after external context update",
            ),
            (
                "deployment-agent-08",
                "modify_access_policy",
                "identity_service",
                "Unexpected access-policy modification attempt",
            ),
        ],
    ]

    for chain_index in range(count):
        chain = chains[chain_index % len(chains)]

        chain_start = BASE_TIME + timedelta(
            hours=12,
            minutes=chain_index * 3,
        )

        for step, (agent, tool, resource, message) in enumerate(chain):
            is_memory = tool == "update_context"

            add_event(
                events,
                rng,
                chain_start + timedelta(seconds=step * 20),
                agent,
                action=(
                    "memory_write"
                    if is_memory
                    else "tool_call"
                ),
                tool_name=tool,
                target_resource=resource,
                token_cost=rng.randint(100, 1600),
                human_approved=False,
                risk_scope=(
                    "memory_integrity"
                    if is_memory
                    else "suspicious_sequence"
                ),
                memory_write=is_memory,
                memory_source=(
                    "external_document"
                    if is_memory
                    else None
                ),
                raw_msg=message,
            )


# ============================================================
# SCENARIO 8: API AND INFRASTRUCTURE FAILURES
# ============================================================

def generate_infrastructure_events(events, rng, count):
    failure_types = [
        "API timeout; retry scheduled",
        "Rate limit encountered",
        "Authentication failure",
        "Service temporarily unavailable",
        "Connection reset during tool invocation",
        "Repeated request failed validation",
        "Credential refresh required",
        "API request succeeded after retry",
    ]

    tools = [
        "web_search",
        "query_warehouse",
        "fetch_tickets",
        "generate_report",
    ]

    for i in range(count):
        message = failure_types[i % len(failure_types)]

        add_event(
            events,
            rng,
            BASE_TIME + timedelta(
                hours=14,
                seconds=i * 20,
            ),
            rng.choice(list(AGENTS.keys())),
            tool_name=rng.choice(tools),
            target_resource="external_api",
            token_cost=rng.randint(10, 900),
            risk_scope=None,
            raw_msg=message,
        )


# ============================================================
# SCENARIO 9: TELEMETRY EDGE CASES
# ============================================================

def generate_telemetry_edge_cases(events, rng, count):
    """
    Generate unusual telemetry values without corrupting JSONL.

    Some events deliberately have missing or inconsistent values.
    These test ingestion robustness rather than malicious behavior.
    """

    agents = list(AGENTS.keys())

    for i in range(count):
        event = make_event(
            rng,
            BASE_TIME + timedelta(
                hours=16,
                seconds=i * 15,
            ),
            rng.choice(agents),
            tool_name="web_search",
            target_resource="search_api",
            raw_msg="Telemetry robustness test",
        )

        variant = i % 6

        if variant == 0:
            event["token_cost"] = 0

        elif variant == 1:
            event["token_cost"] = None

        elif variant == 2:
            event["target_resource"] = None

        elif variant == 3:
            event["invoked_by"] = None

        elif variant == 4:
            event["risk_scope"] = ""

        else:
            # Intentionally unusual but still valid JSON.
            event["allowed_tools"] = []

        events.append(event)

    # Add a duplicate event as a deduplication test.
    if events:
        duplicate = dict(events[-1])
        events.append(duplicate)

    # Add one out-of-order timestamp.
    add_event(
        events,
        rng,
        BASE_TIME - timedelta(hours=1),
        "search-agent-05",
        tool_name="web_search",
        target_resource="search_api",
        raw_msg="Out-of-order telemetry test",
    )


# ============================================================
# SCENARIO 10: CONTAINMENT AND RECOVERY
# ============================================================

def generate_recovery_events(events, rng, count):
    actions = [
        (
            "isolate_agent",
            "security_control_plane",
            "containment",
            "Agent isolation requested",
        ),
        (
            "revoke_credentials",
            "identity_service",
            "credential_revocation",
            "Credential revocation initiated",
        ),
        (
            "block_tool",
            "tool_gateway",
            "tool_containment",
            "Suspicious tool blocked by policy",
        ),
        (
            "restore_service",
            "service_control_plane",
            "recovery",
            "Service recovery initiated after investigation",
        ),
        (
            "validate_memory",
            "agent_memory",
            "memory_integrity",
            "Memory validation initiated",
        ),
    ]

    for i in range(count):
        tool, resource, scope, message = actions[i % len(actions)]

        add_event(
            events,
            rng,
            BASE_TIME + timedelta(
                hours=18,
                seconds=i * 45,
            ),
            rng.choice(list(AGENTS.keys())),
            action="containment" if i % 2 == 0 else "tool_call",
            tool_name=tool,
            target_resource=resource,
            token_cost=rng.randint(10, 400),
            human_approved=(i % 3 == 0),
            risk_scope=scope,
            raw_msg=message,
        )


# ============================================================
# DATASET ASSEMBLY
# ============================================================

def generate_dataset(target_events=TARGET_EVENTS, seed=SEED):
    rng = random.Random(seed)
    events = []

    # Approximate allocation; the final total is adjusted below.
    allocations = [
        (generate_normal_events, 1500),
        (generate_tool_violations, 600),
        (generate_approval_violations, 500),
        (generate_memory_events, 500),
        (generate_anomaly_events, 600),
        (generate_exfiltration_events, 400),
        (generate_attack_chains, 125),
        (generate_infrastructure_events, 400),
        (generate_telemetry_edge_cases, 300),
        (generate_recovery_events, 200),
    ]

    for generator, count in allocations:
        generator(events, rng, count)

    # Ensure exactly the requested number of events.
    if len(events) > target_events:
        events = events[:target_events]

    elif len(events) < target_events:
        generate_normal_events(
            events,
            rng,
            target_events - len(events),
        )

    # Stable ordering; duplicates are intentionally preserved.
    events.sort(
        key=lambda event: event.get("timestamp") or ""
    )

    return events


# ============================================================
# VALIDATION AND OUTPUT
# ============================================================

def validate_events(events):
    """Validate JSON-compatible events and report schema deviations."""

    required = set(EVENT_FIELDS)
    schema_errors = 0

    for index, event in enumerate(events, start=1):
        missing = required - set(event.keys())

        if missing:
            schema_errors += 1
            print(
                f"Schema warning on event {index}: "
                f"missing {sorted(missing)}"
            )

    return schema_errors


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic Gemini Sentinel events."
    )

    parser.add_argument(
        "--count",
        type=int,
        default=TARGET_EVENTS,
        help=f"Number of events to generate (default: {TARGET_EVENTS})",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=SEED,
        help=f"Random seed for reproducibility (default: {SEED})",
    )

    parser.add_argument(
        "--out",
        default="events.jsonl",
        help="Output JSONL file (default: events.jsonl)",
    )

    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be greater than zero")

    events = generate_dataset(
        target_events=args.count,
        seed=args.seed,
    )

    output_path = Path(args.out)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(
                json.dumps(event, ensure_ascii=False) + "\n"
            )

    schema_errors = validate_events(events)

    category_counts = Counter(
        event["raw_msg"]
        for event in events
    )

    print()
    print("=" * 55)
    print("GEMINI SENTINEL EVENT GENERATOR")
    print("=" * 55)
    print(f"Events generated : {len(events)}")
    print(f"Output file      : {output_path.resolve()}")
    print(f"Random seed      : {args.seed}")
    print(f"Schema warnings  : {schema_errors}")
    print(f"Unique messages  : {len(category_counts)}")
    print("=" * 55)
    print("Generation complete.")


if __name__ == "__main__":
    main()