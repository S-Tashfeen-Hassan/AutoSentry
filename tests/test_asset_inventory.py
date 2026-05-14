from __future__ import annotations

import json

import utils.asset_inventory as inventory


def test_asset_inventory_classifies_managed_internal_external(monkeypatch, asset_file):
    monkeypatch.setattr(inventory, "ASSET_INVENTORY_PATH", asset_file)
    inventory.load_assets.cache_clear()

    context = inventory.enrich_asset_context({"src_ip": "203.0.113.99", "dest_ip": "192.168.56.1"})

    assert inventory.is_internal_ip("192.168.56.1") is True
    assert inventory.is_internal_ip("203.0.113.99") is False
    assert context["src_ip_role"] == "external"
    assert context["dest_ip_role"] == "managed"
    assert context["target_asset"]["asset_id"] == "edge-firewall"
    assert "block_source_ip_on_firewall" in context["allowed_actions"]


def test_asset_inventory_handles_missing_and_invalid_inventory(monkeypatch, tmp_path):
    missing = tmp_path / "missing.json"
    monkeypatch.setattr(inventory, "ASSET_INVENTORY_PATH", missing)
    inventory.load_assets.cache_clear()

    assert inventory.load_assets() == []
    assert inventory.enrich_asset_context({"src_ip": "bad-ip", "dest_ip": None})["src_ip_role"] == "external"

    invalid = tmp_path / "managed_assets.json"
    invalid.write_text("{not-json", encoding="utf-8")
    monkeypatch.setattr(inventory, "ASSET_INVENTORY_PATH", invalid)
    inventory.load_assets.cache_clear()

    assert inventory.load_assets() == []
