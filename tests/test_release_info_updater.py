"""Tests for the release_info.py updater script."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "update_release_info.py"


def load_updater():
    """Load the updater script as a test module."""
    spec = importlib.util.spec_from_file_location("update_release_info", SCRIPT_PATH)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["update_release_info"] = module
    spec.loader.exec_module(module)
    return module


def test_update_release_info_source_updates_required_values():
    """Updater rewrites release constants while preserving unrelated code."""
    updater = load_updater()
    source = '''"""Release info."""

LATEST_VERSION = "1.0"

STIX20 = {
    "enterprise": {"1.0": "old-enterprise-20"},
    "mobile": {"1.0": "old-mobile-20"},
    "ics": {"1.0": "old-ics-20"},
    "pre": {"1.0": "old-pre-20"},
}

STIX21 = {
    "enterprise": {"1.0": "old-enterprise-21"},
    "mobile": {"1.0": "old-mobile-21"},
    "ics": {"1.0": "old-ics-21"},
}


def keep_me():
    return "unchanged"
'''
    release_hashes = {
        "STIX20": {
            "enterprise": "new-enterprise-20",
            "mobile": "new-mobile-20",
            "ics": "new-ics-20",
        },
        "STIX21": {
            "enterprise": "new-enterprise-21",
            "mobile": "new-mobile-21",
            "ics": "new-ics-21",
        },
    }

    updated = updater.update_release_info_source(source, version="2.0", release_hashes=release_hashes)

    assert 'LATEST_VERSION = "2.0"' in updated
    assert "'2.0': 'new-enterprise-20'" in updated
    assert "'2.0': 'new-mobile-20'" in updated
    assert "'2.0': 'new-ics-20'" in updated
    assert "'2.0': 'new-enterprise-21'" in updated
    assert "'2.0': 'new-mobile-21'" in updated
    assert "'2.0': 'new-ics-21'" in updated
    assert "'pre': {'1.0': 'old-pre-20'}" in updated
    assert 'return "unchanged"' in updated


def test_find_domain_asset_accepts_current_and_versioned_names():
    """Asset lookup accepts release asset naming variants from ATT&CK data repos."""
    updater = load_updater()
    assets = [
        {"name": "enterprise-attack-2.0.json"},
        {"name": "mobile-attack.json"},
    ]

    assert updater.find_domain_asset(assets, domain="enterprise", version="2.0")["name"] == "enterprise-attack-2.0.json"
    assert updater.find_domain_asset(assets, domain="mobile", version="2.0")["name"] == "mobile-attack.json"
