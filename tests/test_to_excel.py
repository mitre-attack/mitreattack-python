from pathlib import Path

import stix2
from loguru import logger

from mitreattack.attackToExcel import attackToExcel

# tmp_path is a built-in pytest tixture
# https://docs.pytest.org/en/7.1.x/how-to/tmp_path.html


def check_excel_files_exist(excel_folder: Path, domain: str):
    assert (excel_folder / f"{domain}.xlsx").exists()
    # TODO: add in check for assets for ICS after ATT&CK v14 is released
    if domain == "ics-attack":
        # Only ICS has Assets
        assert (excel_folder / f"{domain}-assets.xlsx").exists()
    assert (excel_folder / f"{domain}-datasources.xlsx").exists()
    assert (excel_folder / f"{domain}-campaigns.xlsx").exists()
    assert (excel_folder / f"{domain}-groups.xlsx").exists()
    assert (excel_folder / f"{domain}-matrices.xlsx").exists()
    assert (excel_folder / f"{domain}-mitigations.xlsx").exists()
    assert (excel_folder / f"{domain}-relationships.xlsx").exists()
    assert (excel_folder / f"{domain}-software.xlsx").exists()
    assert (excel_folder / f"{domain}-tactics.xlsx").exists()
    assert (excel_folder / f"{domain}-techniques.xlsx").exists()


def test_enterprise_latest(tmp_path: Path, memstore_enterprise_latest: stix2.MemoryStore):
    """Test most recent enterprise to excel spreadsheet functionality"""
    logger.debug(f"{tmp_path=}")
    domain = "enterprise-attack"

    attackToExcel.export(domain=domain, output_dir=str(tmp_path), mem_store=memstore_enterprise_latest)

    excel_folder = tmp_path / domain
    check_excel_files_exist(excel_folder=excel_folder, domain=domain)


def test_mobile_latest(tmp_path: Path, memstore_mobile_latest: stix2.MemoryStore):
    """Test most recent mobile to excel spreadsheet functionality"""
    logger.debug(f"{tmp_path=}")
    domain = "mobile-attack"

    attackToExcel.export(domain="mobile-attack", output_dir=str(tmp_path), mem_store=memstore_mobile_latest)

    excel_folder = tmp_path / domain
    check_excel_files_exist(excel_folder=excel_folder, domain=domain)


def test_ics_latest(tmp_path: Path, memstore_ics_latest: stix2.MemoryStore):
    """Test most recent ics to excel spreadsheet functionality"""
    logger.debug(f"{tmp_path=}")
    domain = "ics-attack"

    attackToExcel.export(domain="ics-attack", output_dir=str(tmp_path), mem_store=memstore_ics_latest)

    excel_folder = tmp_path / domain
    check_excel_files_exist(excel_folder=excel_folder, domain=domain)


def test_enterprise_legacy(tmp_path: Path):
    """Test enterprise v9.0 to excel spreadsheet functionality"""
    logger.debug(f"{tmp_path=}")
    version = "v9.0"

    attackToExcel.export(domain="enterprise-attack", version=version, output_dir=str(tmp_path))

    excel_folder = tmp_path / f"enterprise-attack-{version}"
    assert (excel_folder / f"enterprise-attack-{version}.xlsx").exists()
    assert (excel_folder / f"enterprise-attack-{version}-techniques.xlsx").exists()
    assert (excel_folder / f"enterprise-attack-{version}-tactics.xlsx").exists()
    assert (excel_folder / f"enterprise-attack-{version}-software.xlsx").exists()
    assert (excel_folder / f"enterprise-attack-{version}-relationships.xlsx").exists()
    assert (excel_folder / f"enterprise-attack-{version}-mitigations.xlsx").exists()
    assert (excel_folder / f"enterprise-attack-{version}-matrices.xlsx").exists()
    assert (excel_folder / f"enterprise-attack-{version}-groups.xlsx").exists()