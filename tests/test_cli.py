"""Tests for CLI export and generation functionality.

This module contains pytest-based tests for the MITRE ATT&CK Navigator CLI tools,
including export and overview generation for various domains and resource types.

Functions
---------
All functions are test cases for CLI commands, verifying output file creation
and correct operation for SVG, Excel, overview, mapped, and batch generation modes.

"""

from pathlib import Path

import pytest

from mitreattack.attackToExcel import attackToExcel
from mitreattack.navlayers import Layer, layerExporter_cli
from mitreattack.navlayers.layerExporter_cli import main as LEC_main
from mitreattack.navlayers.layerGenerator_cli import main as LGC_main


@pytest.mark.slow
def test_export_svg(tmp_path: Path, layer_v43: Layer, stix_file_enterprise_latest: str):
    """Test SVG Export capabilities from CLI."""
    demo_file = tmp_path / "demo_file.json"
    test_export_svg_file = tmp_path / "test_export_svg.svg"

    layer_v43.to_file(str(demo_file))
    LEC_main(
        [
            str(demo_file),
            "-m",
            "svg",
            "--source",
            "local",
            "--resource",
            stix_file_enterprise_latest,
            "--output",
            str(test_export_svg_file),
        ]
    )

    assert test_export_svg_file.exists()


def test_export_excel(monkeypatch, tmp_path: Path, layer_v43: Layer):
    """Test excel export argument wiring from CLI."""
    demo_file = tmp_path / "demo_file.json"
    test_export_xlsx_file = tmp_path / "test_export_excel.xlsx"
    calls = {}

    class FakeToExcel:
        def __init__(self, **kwargs):
            calls["init"] = kwargs

        def to_xlsx(self, layer, filepath):
            calls["to_xlsx"] = {"layer": layer, "filepath": filepath}
            Path(filepath).write_text("xlsx", encoding="utf-8")

    monkeypatch.setattr(layerExporter_cli, "ToExcel", FakeToExcel)

    layer_v43.to_file(str(demo_file))
    LEC_main(
        [
            str(demo_file),
            "-m",
            "excel",
            "--source",
            "local",
            "--resource",
            "enterprise-attack.json",
            "--output",
            str(test_export_xlsx_file),
        ]
    )

    assert calls["init"] == {
        "domain": "enterprise-attack",
        "source": "local",
        "resource": "enterprise-attack.json",
    }
    assert calls["to_xlsx"]["filepath"] == str(test_export_xlsx_file)
    assert test_export_xlsx_file.exists()


def test_generate_overview_group(tmp_path: Path, stix_file_mobile_latest: str):
    """Test CLI group overview generation."""
    output_layer_file = tmp_path / "test_overview_group.json"
    LGC_main(
        [
            "--domain",
            "mobile",
            "--source",
            "local",
            "--resource",
            stix_file_mobile_latest,
            "--overview-type",
            "group",
            "--output",
            str(output_layer_file),
        ]
    )
    assert output_layer_file.exists()


def test_generate_overview_software(tmp_path: Path, stix_file_mobile_latest: str):
    """Test CLI software overview generation."""
    output_layer_file = tmp_path / "test_overview_software.json"
    LGC_main(
        [
            "--domain",
            "mobile",
            "--source",
            "local",
            "--resource",
            stix_file_mobile_latest,
            "--overview-type",
            "software",
            "--output",
            str(output_layer_file),
        ]
    )
    assert output_layer_file.exists()


@pytest.mark.slow
def test_generate_overview_mitigation(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI mitigation overview generation."""
    output_layer_file = tmp_path / "test_overview_mitigation.json"
    LGC_main(
        [
            "--domain",
            "enterprise",
            "--source",
            "local",
            "--resource",
            stix_file_enterprise_latest,
            "--overview-type",
            "mitigation",
            "--output",
            str(output_layer_file),
        ]
    )
    assert output_layer_file.exists()


@pytest.mark.slow
def test_generate_overview_datasource(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI datasource overview generation."""
    output_layer_file = tmp_path / "test_overview_datasource.json"
    LGC_main(
        [
            "--domain",
            "enterprise",
            "--source",
            "local",
            "--resource",
            stix_file_enterprise_latest,
            "--overview-type",
            "datasource",
            "--output",
            str(output_layer_file),
        ]
    )
    assert output_layer_file.exists()


@pytest.mark.slow
def test_generate_mapped_group(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI group mapped generation (APT1)."""
    output_layer_file = tmp_path / "test_mapped_group.json"
    LGC_main(
        [
            "--domain",
            "enterprise",
            "--source",
            "local",
            "--resource",
            stix_file_enterprise_latest,
            "--mapped-to",
            "APT1",
            "--output",
            str(output_layer_file),
        ]
    )
    assert output_layer_file.exists()


@pytest.mark.slow
def test_generate_mapped_software(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI software mapped generation (S0202)."""
    output_layer_file = tmp_path / "test_mapped_software.json"
    LGC_main(
        [
            "--domain",
            "enterprise",
            "--source",
            "local",
            "--resource",
            stix_file_enterprise_latest,
            "--mapped-to",
            "S0202",
            "--output",
            str(output_layer_file),
        ]
    )
    assert output_layer_file.exists()


def test_generate_mapped_mitigation(tmp_path: Path, stix_file_mobile_latest: str):
    """Test CLI mitigation mapped generation (M1013)."""
    output_layer_file = tmp_path / "test_mapped_mitigation.json"
    LGC_main(
        [
            "--domain",
            "mobile",
            "--source",
            "local",
            "--resource",
            stix_file_mobile_latest,
            "--mapped-to",
            "M1013",
            "--output",
            str(output_layer_file),
        ]
    )
    assert output_layer_file.exists()


@pytest.mark.slow
def test_generate_mapped_datasource(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI datasource mapped generation."""
    output_layer_file = tmp_path / "test_mapped_datasource.json"
    LGC_main(
        [
            "--domain",
            "enterprise",
            "--source",
            "local",
            "--resource",
            stix_file_enterprise_latest,
            "--mapped-to",
            "x-mitre-data-component--0f72bf50-35b3-419d-ab95-70f9b6a818dd",
            "--output",
            str(output_layer_file),
        ]
    )
    assert output_layer_file.exists()


def test_attack_to_excel_cli_all_domains(monkeypatch, tmp_path: Path):
    """attackToExcel_cli should support release batch export options."""
    calls = {}

    def fake_export_release(**kwargs):
        calls["export_release"] = kwargs

    monkeypatch.setattr(attackToExcel, "export_release", fake_export_release)

    attackToExcel.main(
        [
            "--all-domains",
            "-version",
            "v19.0",
            "--stix-version",
            "2.0",
            "-output",
            str(tmp_path),
        ]
    )

    assert calls["export_release"] == {
        "version": "v19.0",
        "stix_version": "2.0",
        "output_dir": str(tmp_path),
        "stix_base_dir": None,
        "domains": None,
        "versioned_output_dir": False,
    }


def test_attack_to_excel_cli_all_domains_selected_domains(monkeypatch, tmp_path: Path):
    """attackToExcel_cli should pass selected batch domains to release export."""
    calls = {}

    def fake_export_release(**kwargs):
        calls["export_release"] = kwargs

    monkeypatch.setattr(attackToExcel, "export_release", fake_export_release)

    attackToExcel.main(
        [
            "--all-domains",
            "--domains",
            "mobile-attack",
            "ics-attack",
            "-output",
            str(tmp_path),
            "--versioned-output-dir",
        ]
    )

    assert calls["export_release"]["domains"] == ["mobile-attack", "ics-attack"]
    assert calls["export_release"]["versioned_output_dir"] is True


def test_attack_to_excel_cli_all_domains_defaults_output_to_output_dir(monkeypatch):
    """Batch release export should use the release export default output directory."""
    calls = {}

    def fake_export_release(**kwargs):
        calls["export_release"] = kwargs

    monkeypatch.setattr(attackToExcel, "export_release", fake_export_release)

    attackToExcel.main(["--all-domains"])

    assert calls["export_release"]["output_dir"] == "output"


def test_attack_to_excel_cli_all_domains_rejects_remote():
    """Batch release export should reject remote Workbench input."""
    with pytest.raises(SystemExit):
        attackToExcel.main(["--all-domains", "-remote", "http://localhost:3000"])


def test_attack_to_excel_cli_domains_requires_all_domains():
    """Selected batch domains should only be valid for batch release export."""
    with pytest.raises(SystemExit):
        attackToExcel.main(["--domains", "mobile-attack"])


def test_attack_to_excel_cli_single_domain_still_exports(monkeypatch, tmp_path: Path):
    """Existing single-domain CLI behavior should continue to call export."""
    calls = {}

    def fake_export(**kwargs):
        calls["export"] = kwargs

    monkeypatch.setattr(attackToExcel, "export", fake_export)

    attackToExcel.main(["-domain", "mobile-attack", "-version", "v19.0", "-output", str(tmp_path)])

    assert calls["export"] == {
        "domain": "mobile-attack",
        "version": "v19.0",
        "output_dir": str(tmp_path),
        "remote": None,
        "stix_file": None,
    }


@pytest.mark.skip("layerGenerator_cli does not support ICS domain yet")
def test_generate_batch_group(tmp_path: Path, stix_file_ics_latest: str):
    """Test CLI group batch generation."""
    output_layers_dir = tmp_path / "test_batch_group"
    LGC_main(
        [
            "--domain",
            "ics",
            "--source",
            "local",
            "--resource",
            stix_file_ics_latest,
            "--batch-type",
            "group",
            "--output",
            str(output_layers_dir),
        ]
    )
    assert output_layers_dir.is_dir()


@pytest.mark.skip("layerGenerator_cli does not support ICS domain yet")
def test_generate_batch_software(tmp_path: Path, stix_file_ics_latest: str):
    """Test CLI software batch generation."""
    output_layers_dir = tmp_path / "test_batch_software"
    LGC_main(
        [
            "--domain",
            "ics",
            "--source",
            "local",
            "--resource",
            stix_file_ics_latest,
            "--batch-type",
            "software",
            "--output",
            str(output_layers_dir),
        ]
    )
    assert output_layers_dir.is_dir()


@pytest.mark.slow
@pytest.mark.slow
def test_generate_batch_mitigation(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI mitigation batch generation."""
    output_layers_dir = tmp_path / "test_batch_mitigation"
    LGC_main(
        [
            "--domain",
            "enterprise",
            "--source",
            "local",
            "--resource",
            stix_file_enterprise_latest,
            "--batch-type",
            "mitigation",
            "--output",
            str(output_layers_dir),
        ]
    )
    assert output_layers_dir.is_dir()


@pytest.mark.slow
def test_generate_batch_datasource(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI datasource batch generation."""
    output_layers_dir = tmp_path / "test_batch_datasource"
    LGC_main(
        [
            "--domain",
            "enterprise",
            "--source",
            "local",
            "--resource",
            stix_file_enterprise_latest,
            "--batch-type",
            "datasource",
            "--output",
            str(output_layers_dir),
        ]
    )
    assert output_layers_dir.is_dir()
