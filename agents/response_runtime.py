from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from typing import Dict, Tuple

from utils.config import RESPONSE_MODE
from utils.db_logger import log_action


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ResponseAgent:
    ACTION_CATALOG = {
        "block_source_ip_on_firewall",
        "block_source_ip_on_host",
        "quarantine_managed_endpoint",
        "kill_suspicious_process",
        "disable_service",
        "isolate_host",
        "collect_artifacts",
        "notify_operator",
    }

    def __init__(self) -> None:
        self.name = "ResponseAgent"

    def execute_action(self, event: Dict, action_type: str, reason: str = "") -> Dict:
        detection_result = {
            "verdict": "malicious",
            "recommended_action": action_type,
            "reasons": [reason] if reason else ["manual_execute_action"],
        }
        return self.plan_or_execute(event, detection_result, event.get("asset_context", {}))

    def plan_or_execute(self, event: Dict, detection_result: Dict, asset_context: Dict) -> Dict:
        verdict = detection_result.get("verdict")
        if verdict not in {"malicious", "suspicious"}:
            return self._result(
                action="notify_operator",
                target_asset=None,
                target_indicator=event["raw_event"].get("src_ip"),
                executor="policy",
                mode=RESPONSE_MODE,
                status="skipped",
                command_summary="No autonomous response required",
                evidence_link=event["event_id"],
            )

        action = self._pick_action(detection_result, asset_context)
        target_asset = asset_context.get("target_asset")
        target_indicator = event["raw_event"].get("src_ip") or event["raw_event"].get("dest_ip")
        executor = self._executor_for_action(action, asset_context)
        command_summary, execution_status = self._perform_action(action, target_indicator, asset_context, executor)

        result = self._result(
            action=action,
            target_asset=target_asset.get("asset_id") if target_asset else None,
            target_indicator=target_indicator,
            executor=executor,
            mode=RESPONSE_MODE,
            status=execution_status,
            command_summary=command_summary,
            evidence_link=event["event_id"],
        )
        log_action(result)
        return result

    def _pick_action(self, detection_result: Dict, asset_context: Dict) -> str:
        allowed = set(asset_context.get("allowed_actions", []))
        src_role = asset_context.get("src_ip_role")
        dest_role = asset_context.get("dest_ip_role")
        recommended = detection_result.get("recommended_action") or "notify_operator"

        if src_role == "external" and "block_source_ip_on_firewall" in allowed:
            return "block_source_ip_on_firewall"
        if dest_role == "managed" and "block_source_ip_on_host" in allowed:
            return "block_source_ip_on_host"
        if dest_role == "managed" and "quarantine_managed_endpoint" in allowed:
            return "quarantine_managed_endpoint"
        if recommended in self.ACTION_CATALOG and recommended in allowed:
            return recommended
        return "notify_operator"

    def _executor_for_action(self, action: str, asset_context: Dict) -> str:
        if action == "notify_operator":
            return "policy"
        return asset_context.get("remote_executor_type", "policy")

    def _perform_action(self, action: str, target_indicator: str | None, asset_context: Dict, executor: str) -> Tuple[str, str]:
        if action == "notify_operator":
            return "Escalated incident to operator queue", "completed"

        if RESPONSE_MODE != "execute":
            return f"DRY RUN via {executor}: {self._command_preview(action, target_indicator, asset_context)}", "dry_run"

        if executor == "local_powershell":
            command = self._powershell_command(action, target_indicator)
            if not command:
                return f"Unsupported local action: {action}", "blocked"
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if completed.returncode == 0:
                return command, "completed"
            return f"{command} | stderr={completed.stderr.strip()}", "failed"

        return self._command_preview(action, target_indicator, asset_context), "pending_remote_execution"

    def _command_preview(self, action: str, target_indicator: str | None, asset_context: Dict) -> str:
        asset = asset_context.get("target_asset") or {}
        asset_name = asset.get("hostname", "managed-asset")
        if action == "block_source_ip_on_firewall":
            return f"Block remote IP {target_indicator} at firewall {asset_name}"
        if action == "block_source_ip_on_host":
            return f"Block remote IP {target_indicator} on host {asset_name}"
        if action == "quarantine_managed_endpoint":
            return f"Quarantine managed endpoint {asset_name}"
        if action == "collect_artifacts":
            return f"Collect forensic artifacts from {asset_name}"
        return f"Execute {action} on {asset_name}"

    def _powershell_command(self, action: str, target_indicator: str | None) -> str | None:
        if action in {"block_source_ip_on_firewall", "block_source_ip_on_host"} and target_indicator:
            return (
                "$rule='AutoSentry-" + target_indicator.replace(".", "-") + "';"
                "if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) "
                "{ New-NetFirewallRule -DisplayName $rule -Direction Inbound "
                f"-RemoteAddress {target_indicator} -Action Block | Out-Null }}"
            )
        return None

    def _result(
        self,
        *,
        action: str,
        target_asset: str | None,
        target_indicator: str | None,
        executor: str,
        mode: str,
        status: str,
        command_summary: str,
        evidence_link: str,
    ) -> Dict:
        timestamp = _utc_now()
        return {
            "action": action,
            "target_asset": target_asset,
            "target_indicator": target_indicator,
            "executor": executor,
            "mode": mode,
            "status": status,
            "command_summary": command_summary,
            "evidence_link": evidence_link,
            "audit_id": f"audit-{evidence_link}",
            "started_at": timestamp,
            "finished_at": timestamp,
        }
