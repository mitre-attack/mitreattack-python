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
from click import unstyle
from typer.testing import CliRunner

from mitreattack.attackToExcel import attackToExcel
from mitreattack.navlayers import Layer, layerExporter_cli
from mitreattack.navlayers.layerExporter_cli import main as LEC_main
from mitreattack.navlayers.layerGenerator_cli import main as LGC_main


@pytest.fixture
def attack_to_excel_runner():
    """Return a CLI runner for the attack-to-excel Typer app."""
    return CliRunner()


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


def test_attack_to_excel_cli_from_stix_exports(monkeypatch, tmp_path: Path, attack_to_excel_runner: CliRunner):
    """from-stix should call export with parsed single-domain options."""
    calls = {}

    def fake_export(**kwargs):
        calls["export"] = kwargs

    monkeypatch.setattr(attackToExcel, "export", fake_export)

    result = attack_to_excel_runner.invoke(
        attackToExcel.app, ["from-stix", "--domain", "mobile-attack", "--version", "v19.0", "--output", str(tmp_path)]
    )

    assert result.exit_code == 0
    assert calls["export"] == {
        "domain": "mobile-attack",
        "version": "v19.0",
        "output_dir": str(tmp_path),
        "remote": None,
        "stix_file": None,
    }


def test_attack_to_excel_cli_from_stix_rejects_multiple_sources(attack_to_excel_runner: CliRunner):
    """from-stix should reject ambiguous STIX source options."""
    result = attack_to_excel_runner.invoke(
        attackToExcel.app,
        ["from-stix", "--remote", "http://localhost:3000", "--stix-file", "enterprise-attack.json"],
    )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_attack_to_excel_cli_from_release_all_domains(monkeypatch, tmp_path: Path, attack_to_excel_runner: CliRunner):
    """from-release should support release batch export options."""
    calls = {}

    def fake_export_release(**kwargs):
        calls["export_release"] = kwargs

    monkeypatch.setattr(attackToExcel, "export_release", fake_export_release)

    result = attack_to_excel_runner.invoke(
        attackToExcel.app,
        [
            "from-release",
            "--version",
            "v19.0",
            "--stix-version",
            "2.0",
            "--output",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0
    assert calls["export_release"] == {
        "version": "v19.0",
        "stix_version": "2.0",
        "output_dir": str(tmp_path),
        "stix_base_dir": None,
        "domains": None,
        "versioned_output_dir": False,
    }


def test_attack_to_excel_cli_from_release_selected_domains(
    monkeypatch, tmp_path: Path, attack_to_excel_runner: CliRunner
):
    """from-release should pass selected release domains to release export."""
    calls = {}

    def fake_export_release(**kwargs):
        calls["export_release"] = kwargs

    monkeypatch.setattr(attackToExcel, "export_release", fake_export_release)

    result = attack_to_excel_runner.invoke(
        attackToExcel.app,
        [
            "from-release",
            "--domains",
            "mobile-attack",
            "--domains",
            "ics-attack",
            "--output",
            str(tmp_path),
            "--versioned-output-dir",
        ],
    )

    assert result.exit_code == 0
    assert calls["export_release"]["domains"] == ["mobile-attack", "ics-attack"]
    assert calls["export_release"]["versioned_output_dir"] is True


def test_attack_to_excel_cli_from_release_defaults_output_to_output_dir(monkeypatch, attack_to_excel_runner: CliRunner):
    """from-release should use the release export default output directory."""
    calls = {}

    def fake_export_release(**kwargs):
        calls["export_release"] = kwargs

    monkeypatch.setattr(attackToExcel, "export_release", fake_export_release)

    result = attack_to_excel_runner.invoke(attackToExcel.app, ["from-release"])

    assert result.exit_code == 0
    assert calls["export_release"]["output_dir"] == "output"


def test_attack_to_excel_cli_rejects_root_legacy_all_domains(attack_to_excel_runner: CliRunner):
    """Root-level legacy batch options should no longer dispatch exports."""
    result = attack_to_excel_runner.invoke(attackToExcel.app, ["--all-domains"])

    assert result.exit_code != 0
    assert "No such option" in result.output


def test_attack_to_excel_cli_rejects_root_legacy_domain(attack_to_excel_runner: CliRunner):
    """Root-level legacy single-domain options should no longer dispatch exports."""
    result = attack_to_excel_runner.invoke(attackToExcel.app, ["--domain", "mobile-attack"])

    assert result.exit_code != 0
    assert "No such option" in result.output


def test_attack_to_excel_cli_help_lists_subcommands(attack_to_excel_runner: CliRunner):
    """attack-to-excel help should expose the from-stix and from-release subcommands."""
    result = attack_to_excel_runner.invoke(attackToExcel.app, ["--help"])
    root_help = unstyle(result.output)

    assert result.exit_code == 0
    assert "from-stix" in root_help
    assert "from-release" in root_help

    from_stix_help = attack_to_excel_runner.invoke(attackToExcel.app, ["from-stix", "--help"])
    from_stix_output = unstyle(from_stix_help.output)
    assert from_stix_help.exit_code == 0
    assert "--domain" in from_stix_output
    assert "--remote" in from_stix_output
    assert "--stix-file" in from_stix_output

    from_release_help = attack_to_excel_runner.invoke(attackToExcel.app, ["from-release", "--help"])
    from_release_output = unstyle(from_release_help.output)
    assert from_release_help.exit_code == 0
    assert "--domains" in from_release_output
    assert "--stix-version" in from_release_output
    assert "--stix-base-dir" in from_release_output


def test_attack_to_excel_cli_no_args_shows_help(attack_to_excel_runner: CliRunner):
    """attack-to-excel without a subcommand should show help instead of exporting."""
    result = attack_to_excel_runner.invoke(attackToExcel.app, [])

    assert result.exit_code == 0
    assert "from-stix" in result.output
    assert "from-release" in result.output


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
