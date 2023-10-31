import json
import os
from pathlib import Path

import pytest
from stix2 import MemoryStore

from mitreattack.navlayers import (
    Layer,
    LayerOps,
    Link,
    LinkDiv,
    Metadata,
    MetaDiv,
    Technique,
    ToExcel,
    ToSvg,
)

from .resources import testing_data


def test_depreciated_tactics_export(tmp_path: Path, memstore_enterprise_latest: MemoryStore):
    """Test exporting a layer with depreciated tactics"""
    lay = Layer(testing_data.example_layer_v3_longer)
    xlsx_output = tmp_path / "test.xlsx"
    svg_output = tmp_path / "test.svg"

    t = ToExcel(domain=lay.layer.domain, source="memorystore", resource=memstore_enterprise_latest)
    t2 = ToSvg(domain=lay.layer.domain, source="memorystore", resource=memstore_enterprise_latest)
    t.to_xlsx(layerInit=lay, filepath=str(xlsx_output))
    t2.to_svg(layerInit=lay, filepath=str(svg_output))

    assert xlsx_output.exists()
    assert svg_output.exists()


def test_colormap_export(tmp_path: Path, memstore_enterprise_latest: MemoryStore):
    """Test exporting a layer with a gradiant of scores"""
    lay = Layer()
    dir = os.path.dirname(__file__)
    lay.from_file(os.path.join(dir, "resources", "heatmap_example.json"))
    xlsx_output = tmp_path / "layer.xlsx"
    svg_output = tmp_path / "layer.svg"

    xlsx_exporter = ToExcel(domain=lay.layer.domain, source="memorystore", resource=memstore_enterprise_latest)
    svg_exporter = ToSvg(domain=lay.layer.domain, source="memorystore", resource=memstore_enterprise_latest)
    xlsx_exporter.to_xlsx(layerInit=lay, filepath=str(xlsx_output))
    svg_exporter.to_svg(layerInit=lay, filepath=str(svg_output))

    assert xlsx_output.exists()
    assert svg_output.exists()


@pytest.mark.skip(reason="For some reason there is a Unicode decode error here, possibly with the test data?")
def test_config_load(tmp_path: Path, memstore_enterprise_latest: MemoryStore):
    """Test loading a SVG config"""
    lay = Layer(testing_data.example_layer_v3_all)
    svg_output = tmp_path / "example.svg"

    svg_exporter = ToSvg(domain=lay.layer.domain, source="memorystore", resource=memstore_enterprise_latest)
    svg_exporter.config.load_from_file("resources/demo.json")
    svg_exporter.to_svg(layerInit=lay, filepath=str(svg_output))

    assert Path(svg_output).exists()


def test_aggregate(tmp_path: Path, memstore_enterprise_latest: MemoryStore):
    """Test aggregate layer exports (agg configurations are present in each layer)"""
    listing = [
        testing_data.agg_layer_1,
        testing_data.agg_layer_2,
        testing_data.agg_layer_3,
        testing_data.agg_layer_5,
        testing_data.agg_layer_6,
        testing_data.agg_layer_7,
    ]
    for lay in listing:
        test_layer = Layer()
        test_layer.from_str(lay)
        xlsx_output = tmp_path / f"layer-{test_layer.layer.name}.xlsx"
        svg_output = tmp_path / f"layer-{test_layer.layer.name}.svg"

        xlsx_exporter = ToExcel(
            domain=test_layer.layer.domain, source="memorystore", resource=memstore_enterprise_latest
        )
        svg_exporter = ToSvg(domain=test_layer.layer.domain, source="memorystore", resource=memstore_enterprise_latest)

        xlsx_exporter.to_xlsx(layerInit=test_layer, filepath=str(xlsx_output))
        svg_exporter.to_svg(layerInit=test_layer, filepath=str(svg_output))

        assert xlsx_output.exists()
        assert svg_output.exists()


def test_upgrades():
    """Test layer version auto-upgrade functionality"""
    lay = Layer()
    lay2 = Layer()
    lay3 = Layer()
    lay.from_dict(testing_data.example_layer_v3_dict)
    lay2.from_dict(testing_data.example_layer_v42_dict)
    lay3.from_dict(testing_data.example_layer_v43_dict)

    out1 = lay.to_dict()
    out2 = lay2.to_dict()
    out3 = lay3.to_dict()

    assert all(
        [
            (out3[x] == out1[x], x)
            for x in out3
            if x
            not in [
                "versions",
                "techniques",
                "metadata",
                "gradient",
                "selectSubtechniquesWithParent",
                "layout",
                "selectVisibleTechniques",
            ]
        ]
    )
    assert all([out3[x] == out2[x] for x in out3 if x not in ["versions", "techniques", "metadata", "gradient"]])
    assert all(["4.5" == x["versions"]["layer"] for x in [out1, out2, out3]])


def test_layer_ops():
    """Test layer lambda computation functionality"""

    def get_layers_by_name(test_layers):
        layers_dict["Endgame"] = Layer()
        layers_dict["Endgame"].from_str(test_layers[0])
        layers_dict["Red2"] = Layer()
        layers_dict["Red2"].from_str(test_layers[1])
        return layers_dict

    def build_combined_layer(layers_dict):
        lo = LayerOps(score=lambda x: sum(x) / len(x))
        return lo.process(list(layers_dict.values()))

    layers_dict = {}
    layers_dict = get_layers_by_name([testing_data.example_layer_v3_longer, testing_data.example_layer_v3_all])
    out_layer = build_combined_layer(layers_dict)
    assert isinstance(out_layer, Layer)


def test_direct_meta():
    Layer(init_data={"name": "Layer A", "domain": "enterprise-attack"})
    layer_technique = Technique(tID="T1003")
    layer_technique.metadata = [Metadata(name="Metadata", value="1"), MetaDiv(active=True)]
    layer_technique2 = Technique(tID="T1004")
    layer_technique2.metadata = [dict(name="Metadata", value="1"), dict(name="DIVIDER", value=True)]
    assert layer_technique.metadata[0].get_dict() == layer_technique2.metadata[0].get_dict()
    assert layer_technique.metadata[1].get_dict() == layer_technique2.metadata[1].get_dict()


def test_direct_link():
    layer_technique = Technique(tID="T1003")
    layer_technique.links = [Link(label="test", url="127.0.0.1"), LinkDiv(divider=True)]
    layer_technique2 = Technique(tID="T1004")
    layer_technique2.links = [dict(label="test", url="127.0.0.1"), dict(divider=True)]
    assert layer_technique.links[0].get_dict() == layer_technique2.links[0].get_dict()
    assert layer_technique.links[1].get_dict() == layer_technique2.links[1].get_dict()


def test_compat(tmp_path: Path):
    layer_dict = testing_data.compat
    layer_file = Layer()
    json_output = tmp_path / "output.json"

    layer_file.from_dict(layer_dict)
    layer_file.to_file(str(json_output))

    with open(str(json_output), "r", encoding="utf-16") as fio:
        output = json.load(fio)
    # check both 8-hex color and unicode preservation

    assert output["description"] == layer_dict["description"]
    assert output["gradient"] == layer_dict["gradient"]
