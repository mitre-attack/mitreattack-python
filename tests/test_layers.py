import json
import os
import shutil

from resources import testing_data

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


class TestLayers:
    @staticmethod
    def test_depreciated_tactics_export():
        """Test exporting a layer with depreciated tactics"""
        if os.path.isfile("test.xlsx"):
            os.remove("test.xlsx")
        if os.path.isfile("test.svg"):
            os.remove("test.svg")

        lay = Layer(testing_data.example_layer_v3_longer)
        t = ToExcel(domain=lay.layer.domain)
        t2 = ToSvg(domain=lay.layer.domain)
        t.to_xlsx(lay, "test.xlsx")
        t2.to_svg(lay, "test.svg")
        assert os.path.isfile("test.xlsx")
        assert os.path.isfile("test.svg")
        os.remove("test.xlsx")
        os.remove("test.svg")

    @staticmethod
    def test_colormap_export():
        """Test exporting a layer with a gradiant of scores"""
        if os.path.isfile("layer.xlsx"):
            os.remove("layer.xlsx")
        if os.path.isfile("layer.svg"):
            os.remove("layer.svg")

        lay = Layer()
        lay.from_file("resources/heatmap_example.json")
        xlsx_exporter = ToExcel(domain=lay.layer.domain)
        xlsx_exporter.to_xlsx(lay, filepath="layer.xlsx")
        svg_exporter = ToSvg(domain=lay.layer.domain)
        svg_exporter.to_svg(lay, filepath="layer.svg")
        assert os.path.isfile("layer.xlsx")
        assert os.path.isfile("layer.svg")
        os.remove("layer.xlsx")
        os.remove("layer.svg")

    @staticmethod
    def test_config_load():
        """Test loading a svg config"""
        lay = Layer(testing_data.example_layer_v3_all)
        exp = ToSvg(domain=lay.layer.domain)
        exp.config.load_from_file("resources/demo.json")
        print(exp.config)
        exp.to_svg(lay)
        os.remove("example.svg")

    @staticmethod
    def test_aggregate():
        """Test aggregate layer exports (agg configurations are present in each layer)"""
        if os.path.isdir("agg_tests"):
            shutil.rmtree("agg_tests")

        os.mkdir("agg_tests")
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

            exporter = ToExcel(domain=test_layer.layer.domain, source="taxii", resource=None)
            exporter.to_xlsx(layerInit=test_layer, filepath=f"agg_tests/layer-{test_layer.layer.name}.xlsx")

            exp = ToSvg(domain=test_layer.layer.domain, source="taxii", resource=None)
            exp.to_svg(test_layer, filepath=f"agg_tests/layer-{test_layer.layer.name}.svg")

            assert os.path.isfile(f"agg_tests/layer-{test_layer.layer.name}.xlsx")
            assert os.path.isfile(f"agg_tests/layer-{test_layer.layer.name}.svg")

        shutil.rmtree("agg_tests")

    @staticmethod
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
                not in ["versions", "techniques", "metadata", "gradient", "selectSubtechniquesWithParent", "layout"]
            ]
        )
        assert all([out3[x] == out2[x] for x in out3 if x not in ["versions", "techniques", "metadata", "gradient"]])
        assert all(["4.3" == x["versions"]["layer"] for x in [out1, out2, out3]])

    @staticmethod
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

    @staticmethod
    def test_direct_meta():
        Layer(init_data={"name": "Layer A", "domain": "enterprise-attack"})
        layer_technique = Technique(tID="T1003")
        layer_technique.metadata = [Metadata(name="Metadata", value="1"), MetaDiv(active=True)]
        layer_technique2 = Technique(tID="T1004")
        layer_technique2.metadata = [dict(name="Metadata", value="1"), dict(name="DIVIDER", value=True)]
        assert layer_technique.metadata[0].get_dict() == layer_technique2.metadata[0].get_dict()
        assert layer_technique.metadata[1].get_dict() == layer_technique2.metadata[1].get_dict()

    @staticmethod
    def test_direct_link():
        layer_technique = Technique(tID="T1003")
        layer_technique.links = [Link(label="test", url="127.0.0.1"), LinkDiv(divider=True)]
        layer_technique2 = Technique(tID="T1004")
        layer_technique2.links = [dict(label="test", url="127.0.0.1"), dict(divider=True)]
        assert layer_technique.links[0].get_dict() == layer_technique2.links[0].get_dict()
        assert layer_technique.links[1].get_dict() == layer_technique2.links[1].get_dict()

    @staticmethod
    def test_compat():
        layer_dict = testing_data.compat
        layer_file = Layer()
        layer_file.from_dict(layer_dict)
        layer_file.to_file("output.json")
        with open("output.json", "r", encoding="utf-16") as fio:
            output = json.load(fio)
        # check both 8-hex color and unicode preservation
        assert output["description"] == layer_dict["description"]
        assert output["gradient"] == layer_dict["gradient"]
        os.remove("output.json")
