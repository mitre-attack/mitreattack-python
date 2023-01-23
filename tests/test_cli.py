from pathlib import Path

import pytest

from mitreattack.navlayers import Layer
from mitreattack.navlayers.layerExporter_cli import main as LEC_main
from mitreattack.navlayers.layerGenerator_cli import main as LGC_main


def test_export_svg(tmp_path: Path, layer_v43: Layer, stix_file_enterprise_latest: str):
    """Test SVG Export capabilities from CLI"""
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


def test_export_excel(tmp_path: Path, layer_v43: Layer, stix_file_enterprise_latest: str):
    """Test excel export capabilities from CLI"""
    demo_file = tmp_path / "demo_file.json"
    test_export_xlsx_file = tmp_path / "test_export_excel.xlsx"

    layer_v43.to_file(str(demo_file))
    LEC_main(
        [
            str(demo_file),
            "-m",
            "excel",
            "--source",
            "local",
            "--resource",
            stix_file_enterprise_latest,
            "--output",
            str(test_export_xlsx_file),
        ]
    )

    assert test_export_xlsx_file.exists()


def test_generate_overview_group(tmp_path: Path, stix_file_mobile_latest: str):
    """Test CLI group overview generation"""
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
    """Test CLI software overview generation"""
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


def test_generate_overview_mitigation(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI mitigation overview generation"""
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


def test_generate_overview_datasource(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI datasource overview generation"""
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


def test_generate_mapped_group(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI group mapped generation (APT1)"""
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


def test_generate_mapped_software(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI software mapped generation (S0202)"""
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
    """Test CLI mitigation mapped generation (M1013)"""
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


def test_generate_mapped_datasource(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI datasource mapped generation"""
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


@pytest.mark.skip("layerGenerator_cli does not support ICS domain yet")
def test_generate_batch_group(tmp_path: Path, stix_file_ics_latest: str):
    """Test CLI group batch generation"""
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
    """Test CLI software batch generation"""
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


def test_generate_batch_mitigation(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI mitigation batch generation"""
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


def test_generate_batch_datasource(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test CLI datasource batch generation"""
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
