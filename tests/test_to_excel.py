"""
Tests for ATT&CK to Excel export functionality.

This module contains tests for verifying that ATT&CK domains (enterprise, mobile, ICS, legacy)
are correctly exported to Excel spreadsheets using the attackToExcel module.
"""

from pathlib import Path

import pytest
import stix2
from loguru import logger

from mitreattack.attackToExcel import attackToExcel

# tmp_path is a built-in pytest tixture
# https://docs.pytest.org/en/7.1.x/how-to/tmp_path.html


def check_excel_files_exist(excel_folder: Path, domain: str):
    """
    Check that all expected Excel files for the given ATT&CK domain exist in the specified folder.

    Parameters
    ----------
    excel_folder : Path
        The directory containing the exported Excel files.
    domain : str
        The ATT&CK domain (e.g., "enterprise-attack", "mobile-attack", "ics-attack").

    Raises
    ------
    AssertionError
        If any expected file does not exist.

    Notes
    -----
    For "ics-attack", also checks for the existence of the assets file.
    """
    assert (excel_folder / f"{domain}.xlsx").exists()
    if domain == "ics-attack":
        # Only ICS has Assets
        assert (excel_folder / f"{domain}-assets.xlsx").exists()
    assert (excel_folder / f"{domain}-datacomponents.xlsx").exists()
    assert (excel_folder / f"{domain}-campaigns.xlsx").exists()
    assert (excel_folder / f"{domain}-groups.xlsx").exists()
    assert (excel_folder / f"{domain}-matrices.xlsx").exists()
    assert (excel_folder / f"{domain}-mitigations.xlsx").exists()
    assert (excel_folder / f"{domain}-relationships.xlsx").exists()
    assert (excel_folder / f"{domain}-software.xlsx").exists()
    assert (excel_folder / f"{domain}-tactics.xlsx").exists()
    assert (excel_folder / f"{domain}-techniques.xlsx").exists()
    assert (excel_folder / f"{domain}-analytics.xlsx").exists()
    assert (excel_folder / f"{domain}-detectionstrategies.xlsx").exists()


def test_enterprise_latest(tmp_path: Path, memstore_enterprise_latest: stix2.MemoryStore):
    """Test most recent enterprise to excel spreadsheet functionality."""
    logger.debug(f"{tmp_path=}")
    domain = "enterprise-attack"

    attackToExcel.export(domain=domain, output_dir=str(tmp_path), mem_store=memstore_enterprise_latest)

    excel_folder = tmp_path / domain
    check_excel_files_exist(excel_folder=excel_folder, domain=domain)


def test_mobile_latest(tmp_path: Path, memstore_mobile_latest: stix2.MemoryStore):
    """Test most recent mobile to excel spreadsheet functionality."""
    logger.debug(f"{tmp_path=}")
    domain = "mobile-attack"

    attackToExcel.export(domain="mobile-attack", output_dir=str(tmp_path), mem_store=memstore_mobile_latest)

    excel_folder = tmp_path / domain
    check_excel_files_exist(excel_folder=excel_folder, domain=domain)


def test_ics_latest(tmp_path: Path, memstore_ics_latest: stix2.MemoryStore):
    """Test most recent ics to excel spreadsheet functionality."""
    logger.debug(f"{tmp_path=}")
    domain = "ics-attack"

    attackToExcel.export(domain="ics-attack", output_dir=str(tmp_path), mem_store=memstore_ics_latest)

    excel_folder = tmp_path / domain
    check_excel_files_exist(excel_folder=excel_folder, domain=domain)


def test_normalize_attack_version_adds_missing_prefix():
    """ATT&CK release versions should be normalized to release directory names."""
    assert attackToExcel.normalize_attack_version("19.0") == "v19.0"
    assert attackToExcel.normalize_attack_version("v19.0") == "v19.0"


def test_export_release_uses_existing_local_stix_files(tmp_path: Path, monkeypatch):
    """Release export should use existing local STIX files without downloading."""
    stix_base_dir = tmp_path / "attack-releases" / "stix-2.0" / "v19.0"
    stix_base_dir.mkdir(parents=True)
    for domain in ["enterprise-attack", "mobile-attack"]:
        (stix_base_dir / f"{domain}.json").write_text("{}", encoding="utf-8")

    calls = {}

    def fake_download_domains(**kwargs):
        calls.setdefault("downloads", []).append(kwargs)

    def fake_export(**kwargs):
        calls.setdefault("exports", []).append(kwargs)

    monkeypatch.setattr(attackToExcel, "download_domains", fake_download_domains)
    monkeypatch.setattr(attackToExcel, "export", fake_export)

    attackToExcel.export_release(
        version="19.0",
        stix_base_dir=str(stix_base_dir),
        output_dir=str(tmp_path / "output"),
        domains=["enterprise-attack", "mobile-attack"],
    )

    assert "downloads" not in calls
    assert [call["domain"] for call in calls["exports"]] == ["enterprise-attack", "mobile-attack"]
    assert calls["exports"][0]["stix_file"] == str(stix_base_dir / "enterprise-attack.json")
    assert calls["exports"][0]["version"] == "v19.0"
    assert calls["exports"][0]["output_dir"] == str(tmp_path / "output" / "v19.0")


def test_export_release_downloads_only_missing_domains_to_temporary_directory(tmp_path: Path, monkeypatch):
    """Missing release STIX files should be downloaded per missing domain into a temporary tree."""
    stix_base_dir = tmp_path / "attack-releases" / "stix-2.0" / "v19.0"
    stix_base_dir.mkdir(parents=True)
    (stix_base_dir / "enterprise-attack.json").write_text("{}", encoding="utf-8")
    calls = {}

    def fake_download_domains(**kwargs):
        calls["download"] = kwargs
        release_dir = Path(kwargs["download_dir"]) / "v19.0"
        release_dir.mkdir(parents=True)
        for domain in kwargs["domains"]:
            (release_dir / f"{domain}-attack.json").write_text("{}", encoding="utf-8")

    def fake_export(**kwargs):
        calls.setdefault("exports", []).append(kwargs)
        assert Path(kwargs["stix_file"]).exists()

    monkeypatch.setattr(attackToExcel, "download_domains", fake_download_domains)
    monkeypatch.setattr(attackToExcel, "export", fake_export)

    attackToExcel.export_release(
        version="v19.0",
        stix_base_dir=str(stix_base_dir),
        output_dir=str(tmp_path / "output"),
        domains=["enterprise-attack", "mobile-attack", "ics-attack"],
    )

    assert calls["download"]["domains"] == ["mobile", "ics"]
    assert calls["download"]["all_versions"] is False
    assert calls["download"]["stix_version"] == "2.0"
    assert calls["download"]["attack_versions"] == ["19.0"]
    assert calls["exports"][0]["stix_file"] == str(stix_base_dir / "enterprise-attack.json")
    assert calls["exports"][1]["stix_file"].endswith("stix-2.0/v19.0/mobile-attack.json")
    assert calls["exports"][2]["stix_file"].endswith("stix-2.0/v19.0/ics-attack.json")
    assert not Path(calls["exports"][1]["stix_file"]).exists()


def test_export_release_moves_versioned_outputs_to_domain_directory(tmp_path: Path, monkeypatch):
    """Default release export should flatten domain-version folders into domain folders."""

    def fake_export(**kwargs):
        output_dir = Path(kwargs["output_dir"])
        versioned_dir = output_dir / f"{kwargs['domain']}-{kwargs['version']}"
        versioned_dir.mkdir(parents=True)
        (versioned_dir / f"{kwargs['domain']}-{kwargs['version']}.xlsx").write_text("excel", encoding="utf-8")

    stix_base_dir = tmp_path / "stix"
    stix_base_dir.mkdir()
    (stix_base_dir / "enterprise-attack.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(attackToExcel, "export", fake_export)

    attackToExcel.export_release(
        version="v19.0",
        stix_base_dir=str(stix_base_dir),
        output_dir=str(tmp_path / "output"),
        domains=["enterprise-attack"],
    )

    assert not (tmp_path / "output" / "v19.0" / "enterprise-attack-v19.0").exists()
    assert (tmp_path / "output" / "v19.0" / "enterprise-attack" / "enterprise-attack-v19.0.xlsx").exists()


def test_export_release_rejects_invalid_domain():
    """Release export should validate selected ATT&CK domains."""
    with pytest.raises(ValueError, match="Invalid ATT&CK domain"):
        attackToExcel.export_release(domains=["pre-attack"])
