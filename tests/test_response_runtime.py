from __future__ import annotations

import subprocess

import agents.response_runtime as response_runtime
from agents.response_runtime import ResponseAgent


def _event():
    return {
        "event_id": "evt-1",
        "raw_event": {"src_ip": "203.0.113.99", "dest_ip": "192.168.56.1"},
        "asset_context": {},
    }


def test_response_skips_benign_and_dry_runs_external_block(monkeypatch, demo_output):
    actions = []
    monkeypatch.setattr(response_runtime, "RESPONSE_MODE", "dry_run")
    monkeypatch.setattr(response_runtime, "log_action", actions.append)
    agent = ResponseAgent()

    benign = agent.plan_or_execute(_event(), {"verdict": "benign"}, {})
    malicious = agent.plan_or_execute(
        _event(),
        {"verdict": "malicious", "recommended_action": "block_source_ip_on_firewall"},
        {
            "src_ip_role": "external",
            "dest_ip_role": "managed",
            "allowed_actions": ["block_source_ip_on_firewall"],
            "remote_executor_type": "ssh",
            "target_asset": {"asset_id": "edge-firewall", "hostname": "edge-firewall"},
        },
    )

    assert benign["status"] == "skipped"
    assert malicious["action"] == "block_source_ip_on_firewall"
    assert malicious["status"] == "dry_run"
    assert len(actions) == 1
    demo_output(
        "Response policy decisions",
        {
            "benign": {"action": benign["action"], "status": benign["status"], "command": benign["command_summary"]},
            "malicious": {
                "action": malicious["action"],
                "status": malicious["status"],
                "executor": malicious["executor"],
                "command": malicious["command_summary"],
            },
            "audit_records_logged": len(actions),
        },
    )


def test_response_execute_mode_powershell_is_mocked(monkeypatch, demo_output):
    def fake_run(command, **kwargs):
        assert command[0] == "powershell"
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(response_runtime, "RESPONSE_MODE", "execute")
    monkeypatch.setattr(response_runtime.subprocess, "run", fake_run)
    monkeypatch.setattr(response_runtime, "log_action", lambda action: None)

    result = ResponseAgent().plan_or_execute(
        _event(),
        {"verdict": "malicious", "recommended_action": "block_source_ip_on_host"},
        {
            "src_ip_role": "internal",
            "dest_ip_role": "managed",
            "allowed_actions": ["block_source_ip_on_host"],
            "remote_executor_type": "local_powershell",
            "target_asset": {"asset_id": "host-1", "hostname": "host-1"},
        },
    )

    assert result["status"] == "completed"
    assert result["executor"] == "local_powershell"
    demo_output(
        "Execute mode is safely mocked",
        {"action": result["action"], "executor": result["executor"], "status": result["status"]},
    )
