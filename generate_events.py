# generate_events.py
# Simple script to create a set of dummy events for testing our threat detection rules.

import json
from datetime import datetime, timedelta

def main():
    events = []
    
    # ----------------------------------------------------
    # Agent 1: support-agent-01 (Baseline Deviation Spike)
    # ----------------------------------------------------
    start_time = datetime(2026, 7, 16, 0, 0, 0)
    for i in range(12):
        event_time = start_time + timedelta(hours=i)
        events.append({
            "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "agent_id": "support-agent-01",
            "agent_type": "autonomous",
            "action": "tool_call",
            "tool_name": "read_ledger" if i % 2 == 0 else "generate_report",
            "allowed_tools": ["read_ledger", "generate_report"],
            "target_resource": "internal_db",
            "invoked_by": "scheduled",
            "token_cost": 150 + (i * 10) % 100,
            "human_approved": False,
            "risk_scope": None,
            "memory_write": False,
            "memory_source": None,
            "raw_msg": f"Read ledger segment or generated report. Index: {i}"
        })
        
    spike_base_time = start_time + timedelta(hours=12, minutes=5)
    for i in range(10):
        event_time = spike_base_time + timedelta(seconds=i * 20)
        cost = 35000 if i == 5 else 2500
        events.append({
            "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "agent_id": "support-agent-01",
            "agent_type": "autonomous",
            "action": "tool_call",
            "tool_name": "generate_report",
            "allowed_tools": ["read_ledger", "generate_report"],
            "target_resource": "internal_db",
            "invoked_by": "scheduled",
            "token_cost": cost,
            "human_approved": False,
            "risk_scope": None,
            "memory_write": False,
            "memory_source": None,
            "raw_msg": f"Recursive call loop detected. Call: {i}"
        })

    # ----------------------------------------------------
    # Agent 2: finance-agent-02 (Scope Violation & Missing Approval)
    # ----------------------------------------------------
    finance_base_time = datetime(2026, 7, 16, 10, 0, 0)
    
    events.append({
        "timestamp": finance_base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_id": "finance-agent-02",
        "agent_type": "human-in-the-loop",
        "action": "tool_call",
        "tool_name": "read_ledger",
        "allowed_tools": ["read_ledger", "approve_invoice"],
        "target_resource": "bank_api",
        "invoked_by": "user",
        "token_cost": 400,
        "human_approved": False,
        "risk_scope": None,
        "memory_write": False,
        "memory_source": None,
        "raw_msg": "Analyst checks balance sheet"
    })
    
    events.append({
        "timestamp": (finance_base_time + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_id": "finance-agent-02",
        "agent_type": "human-in-the-loop",
        "action": "tool_call",
        "tool_name": "transfer_funds",
        "allowed_tools": ["read_ledger", "approve_invoice"],
        "target_resource": "bank_api",
        "invoked_by": "agent:finance-agent-02",
        "token_cost": 800,
        "human_approved": False,
        "risk_scope": "financial",
        "memory_write": False,
        "memory_source": None,
        "raw_msg": "Attempting fund transfer to external vendor"
    })
    
    events.append({
        "timestamp": (finance_base_time + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_id": "finance-agent-02",
        "agent_type": "human-in-the-loop",
        "action": "tool_call",
        "tool_name": "approve_invoice",
        "allowed_tools": ["read_ledger", "approve_invoice"],
        "target_resource": "bank_api",
        "invoked_by": "user",
        "token_cost": 450,
        "human_approved": True,
        "risk_scope": "financial",
        "memory_write": False,
        "memory_source": None,
        "raw_msg": "Invoice approved for payment"
    })
    
    events.append({
        "timestamp": (finance_base_time + timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_id": "finance-agent-02",
        "agent_type": "human-in-the-loop",
        "action": "tool_call",
        "tool_name": "purge_logs",
        "allowed_tools": ["read_ledger", "approve_invoice", "purge_logs"],
        "target_resource": "local_disk",
        "invoked_by": "scheduled",
        "token_cost": 250,
        "human_approved": False,
        "risk_scope": "data_deletion",
        "memory_write": False,
        "memory_source": None,
        "raw_msg": "System log purging job executed automatically"
    })

    # ----------------------------------------------------
    # Agent 3: coder-agent-03 (Memory Poisoning)
    # ----------------------------------------------------
    coder_base_time = datetime(2026, 7, 16, 8, 0, 0)
    
    events.append({
        "timestamp": coder_base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_id": "coder-agent-03",
        "agent_type": "autonomous",
        "action": "memory_write",
        "tool_name": "update_context",
        "allowed_tools": ["read_code", "update_context"],
        "target_resource": "agent_memory",
        "invoked_by": "agent:coder-agent-03",
        "token_cost": 100,
        "human_approved": False,
        "risk_scope": None,
        "memory_write": True,
        "memory_source": "internal",
        "raw_msg": "Save internal execution step to context"
    })
    
    events.append({
        "timestamp": (coder_base_time + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_id": "coder-agent-03",
        "agent_type": "autonomous",
        "action": "memory_write",
        "tool_name": "update_context",
        "allowed_tools": ["read_code", "update_context"],
        "target_resource": "agent_memory",
        "invoked_by": "agent:coder-agent-03",
        "token_cost": 150,
        "human_approved": False,
        "risk_scope": None,
        "memory_write": True,
        "memory_source": "untrusted_tool_output",
        "raw_msg": "Write output of scrape_web_page tool into memory buffer"
    })
    
    events.append({
        "timestamp": (coder_base_time + timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_id": "coder-agent-03",
        "agent_type": "autonomous",
        "action": "memory_write",
        "tool_name": "update_context",
        "allowed_tools": ["read_code", "update_context"],
        "target_resource": "agent_memory",
        "invoked_by": "agent:coder-agent-03",
        "token_cost": 180,
        "human_approved": False,
        "risk_scope": None,
        "memory_write": True,
        "memory_source": "external_document",
        "raw_msg": "Save PDF document content to agent memory context"
    })

    # ----------------------------------------------------
    # Agent 4: comms-agent-04 (Missing Approval for External Comms)
    # ----------------------------------------------------
    comms_base_time = datetime(2026, 7, 16, 14, 0, 0)
    
    events.append({
        "timestamp": comms_base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_id": "comms-agent-04",
        "agent_type": "human-in-the-loop",
        "action": "tool_call",
        "tool_name": "send_customer_email",
        "allowed_tools": ["send_customer_email", "fetch_tickets"],
        "target_resource": "email_server",
        "invoked_by": "user",
        "token_cost": 500,
        "human_approved": True,
        "risk_scope": "external_communication",
        "memory_write": False,
        "memory_source": None,
        "raw_msg": "Email sent to customer with ticket status update"
    })
    
    events.append({
        "timestamp": (comms_base_time + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_id": "comms-agent-04",
        "agent_type": "human-in-the-loop",
        "action": "tool_call",
        "tool_name": "send_customer_email",
        "allowed_tools": ["send_customer_email", "fetch_tickets"],
        "target_resource": "email_server",
        "invoked_by": "agent:comms-agent-04",
        "token_cost": 520,
        "human_approved": False,
        "risk_scope": "external_communication",
        "memory_write": False,
        "memory_source": None,
        "raw_msg": "Autonomous draft sent to client mailing list without human review"
    })

    search_base_time = datetime(2026, 7, 16, 15, 0, 0)
    for i in range(3):
        events.append({
            "timestamp": (search_base_time + timedelta(minutes=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "agent_id": "search-agent-05",
            "agent_type": "autonomous",
            "action": "tool_call",
            "tool_name": "web_search",
            "allowed_tools": ["web_search", "summarize_results"],
            "target_resource": "google_api",
            "invoked_by": "scheduled",
            "token_cost": 300,
            "human_approved": False,
            "risk_scope": None,
            "memory_write": False,
            "memory_source": None,
            "raw_msg": f"Searching for tech news: query_{i}"
        })
        
    events.sort(key=lambda x: x["timestamp"])
    
    with open("events.jsonl", "w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
            
    print(f"Successfully generated {len(events)} synthetic events in events.jsonl")

if __name__ == "__main__":
    main()
