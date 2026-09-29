"""
orchestrator.py patch - Additional registrations and C2 transport integration

Apply these changes on top of the existing orchestrator.py from the Linux patch.
"""

# ════════════════════════════════════════════════════════════════════════════
# PATCH 1: Extend _MODULE_REGISTRY to include byovd_detector
# ════════════════════════════════════════════════════════════════════════════
# Add this line to the existing _MODULE_REGISTRY dict:

# "byovd_detector":      "agent.modules.byovd_detector",


# ════════════════════════════════════════════════════════════════════════════
# PATCH 2: Extend run_task() to call C2Transport.send() after completion
# ════════════════════════════════════════════════════════════════════════════
# Replace the existing run_task() return statement with this version:

import json
from c2.transport import C2Transport

def run_task(manifest: dict, case_id: str, agent: str, c2_transport: object = None) -> dict:
    """
    Execute a task manifest.
    
    After all modules complete, if c2_transport is configured, sends results
    via the configured C2 channel.
    """
    ordered = _topo_sort(manifest["modules"])
    ledger:           list[dict] = []
    module_summaries: dict       = {}
    acquired_paths:   dict[str, str] = {}

    for spec in ordered:
        name   = spec["name"]
        params = dict(spec.get("params", {}))

        # ── Cross-module parameter injection ───────────────────────────────

        # Windows: mft_forensics uses the raw MFT file mft_acquire wrote
        if name == "mft_forensics" and "mft_raw" in acquired_paths:
            params["mft_source"] = acquired_paths["mft_raw"]

        # Windows: usn_parser can use the MFT CSV for name enrichment
        if name == "usn_parser" and "mft_timeline_csv" in acquired_paths:
            params.setdefault("mft_csv", acquired_paths["mft_timeline_csv"])

        # rule_engine: inject ALL log-source paths (evtx + Linux syslog)
        if name == "rule_engine":
            log_paths = [
                e["meta"]["out_path"]
                for e in ledger
                if e["kind"] in ("evtx_jsonl", "linux_log_jsonl")
                and "out_path" in e.get("meta", {})
            ]
            if log_paths:
                existing = list(params.get("log_sources") or [])
                params["log_sources"] = list(dict.fromkeys(existing + log_paths))

            # Retro-scan: all YARA-scannable artifact blobs from this task
            params["ledger_entries"] = [
                e for e in ledger if e["kind"] in _SCANNABLE_KINDS
            ]

        instance    = load_module(name)
        result      = instance.run(params)
        new_entries = store_artifacts(case_id, agent, name, result)
        ledger.extend(new_entries)

        # ── Track filesystem paths produced by each module ─────────────────
        for entry in new_entries:
            meta = entry.get("meta", {})
            kind = entry["kind"]

            # Windows acquisition
            if kind == "mft_raw" and "out_path" in meta:
                acquired_paths["mft_raw"] = meta["out_path"]
            if kind == "mft_timeline" and "out_path" not in acquired_paths:
                acquired_paths["mft_timeline_csv"] = "artifacts/mft_timeline.csv"

            # Linux: track primary output paths for cross-module use
            if kind == "linux_fs_timeline" and "out_path" in meta:
                acquired_paths["linux_fs_timeline"] = meta["out_path"]
            if kind == "linux_proc_list" and "out_path" in meta:
                acquired_paths["linux_proc_list"] = meta["out_path"]
            if kind == "linux_persistence" and "out_path" in meta:
                acquired_paths["linux_persistence"] = meta["out_path"]

        module_summaries[name] = {
            "artifacts": len(new_entries),
            "anomalies": len(result.anomalies),
        }

    result_dict = {
        "case_id":         case_id,
        "agent":           agent,
        "modules":         module_summaries,
        "total_artifacts": len(ledger),
    }

    # ──────────────────────────────────────────────────────────────────────
    # NEW: Send results via C2Transport if configured
    # ──────────────────────────────────────────────────────────────────────
    if c2_transport:
        try:
            payload = json.dumps({
                "task_id": manifest.get("task_id"),
                "case_id": case_id,
                "agent_id": agent,
                "result": result_dict,
                "artifacts_count": len(ledger)
            }).encode()
            c2_transport.send(payload)
        except Exception as e:
            # Silently fail if C2 send fails
            pass

    return result_dict


# ════════════════════════════════════════════════════════════════════════════
# PATCH 3: Update _MODULE_REGISTRY to include byovd_detector
# ════════════════════════════════════════════════════════════════════════════
# The complete updated _MODULE_REGISTRY should look like:

_MODULE_REGISTRY = {
    # ── Windows (existing) ────────────────────────────────
    "mft_acquire":         "agent.modules.mft_acquire",
    "mft_forensics":       "agent.modules.mft_parser",
    "evtx_collector":      "agent.modules.evtx_collector",
    "usn_parser":          "agent.modules.usn_parser",
    "rule_engine":         "agent.modules.rule_engine",
    # ── Linux (existing) ───────────────────────────────────
    "linux_syslog_collector": "agent.modules.linux_syslog_collector",
    "linux_fs_timeline":       "agent.modules.linux_fs_timeline",
    "linux_proc_snapshot":     "agent.modules.linux_proc_snapshot",
    "linux_persistence_scan":  "agent.modules.linux_persistence_scan",
    # ── New cross-platform ─────────────────────────────────
    "byovd_detector":      "agent.modules.byovd_detector",
}

# And add byovd_detector to _SCANNABLE_KINDS if needed:
_SCANNABLE_KINDS = {
    # Windows (existing)
    "mft_resident_data",
    "mft_slack",
    "memory_region",
    "usn_timeline",
    # Linux (existing)
    "linux_persistence_blob",
    "linux_proc_list",
    # New
    "byovd_hit",
}
