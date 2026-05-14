from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import ASSET_INVENTORY_PATH, INTERNAL_SUBNETS, LOCAL_MANAGED_ASSET_ID


def _safe_networks() -> List[ipaddress._BaseNetwork]:
    networks = []
    for subnet in INTERNAL_SUBNETS:
        try:
            networks.append(ipaddress.ip_network(subnet, strict=False))
        except ValueError:
            continue
    return networks


NETWORKS = _safe_networks()


@lru_cache(maxsize=1)
def load_assets() -> List[Dict[str, Any]]:
    path = Path(ASSET_INVENTORY_PATH)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def is_internal_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in network for network in NETWORKS)


def lookup_asset_by_ip(ip_address: Optional[str]) -> Optional[Dict[str, Any]]:
    if not ip_address:
        return None
    for asset in load_assets():
        if asset.get("ip") == ip_address:
            return asset
    return None


def _role_for_ip(ip_address: Optional[str]) -> str:
    if not ip_address:
        return "unknown"
    if lookup_asset_by_ip(ip_address):
        return "managed"
    if is_internal_ip(ip_address):
        return "internal"
    return "external"


def enrich_asset_context(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    src_ip = raw_event.get("src_ip")
    dest_ip = raw_event.get("dest_ip")
    src_asset = lookup_asset_by_ip(src_ip)
    dest_asset = lookup_asset_by_ip(dest_ip)
    managed_asset = dest_asset or src_asset
    local_asset_id = LOCAL_MANAGED_ASSET_ID or None

    allowed_actions = managed_asset.get("allowed_actions", []) if managed_asset else ["notify_operator"]
    executor_type = managed_asset.get("remote_executor_type", "none") if managed_asset else "none"

    return {
        "src_ip_role": _role_for_ip(src_ip),
        "dest_ip_role": _role_for_ip(dest_ip),
        "managed_host_id": managed_asset.get("asset_id") if managed_asset else None,
        "asset_owner": managed_asset.get("asset_owner", "unknown") if managed_asset else "unknown",
        "os_type": managed_asset.get("os_type", "unknown") if managed_asset else "unknown",
        "criticality": managed_asset.get("criticality", "low") if managed_asset else "low",
        "allowed_actions": allowed_actions,
        "remote_executor_type": executor_type,
        "target_asset": managed_asset,
        "source_asset": src_asset,
        "destination_asset": dest_asset,
        "local_managed_asset_id": local_asset_id,
    }
