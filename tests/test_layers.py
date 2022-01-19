from resources import testing_data
from mitreattack.navlayers import Layer, ToExcel, ToSvg, LayerOps
import os
import shutil


class TestLayers:
    @staticmethod
    def test_depreciated_tactics_export():
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
        if os.path.isfile("layer.xlsx"):
            os.remove("layer.xlsx")
        if os.path.isfile("layer.svg"):
            os.remove("layer.svg")

        lay = Layer()
        lay.from_file('resources/heatmap_example.json')
        xlsx_exporter = ToExcel(domain=lay.layer.domain)
        xlsx_exporter.to_xlsx(lay, filepath="layer.xlsx")
        svg_exporter = ToSvg(domain=lay.layer.domain)
        svg_exporter.to_svg(lay, filepath="layer.svg")
        assert os.path.isfile("layer.xlsx")
        assert os.path.isfile("layer.svg")
        os.remove('layer.xlsx')
        os.remove('layer.svg')

    @staticmethod
    def test_config_load():
        lay = Layer(testing_data.example_layer_v3_all)
        exp = ToSvg(domain=lay.layer.domain)
        exp.config.load_from_file("resources/demo.json")
        exp.config.__str__()
        exp.to_svg(lay)

    @staticmethod
    def test_aggregate():
        if os.path.isdir("agg_tests"):
            shutil.rmtree("agg_tests")

        os.mkdir("agg_tests")
        listing = [testing_data.agg_layer_1, testing_data.agg_layer_2, testing_data.agg_layer_3,
                   testing_data.agg_layer_5, testing_data.agg_layer_6, testing_data.agg_layer_7]
        for lay in listing:
            test_layer = Layer()
            test_layer.from_str(lay)

            exporter = ToExcel(domain=test_layer.layer.domain, source='taxii', resource=None)
            exporter.to_xlsx(layerInit=test_layer, filepath=f"agg_tests/layer-{test_layer.layer.name}.xlsx")

            exp = ToSvg(domain=test_layer.layer.domain, source='taxii', resource=None)
            exp.to_svg(test_layer, filepath=f"agg_tests/layer-{test_layer.layer.name}.svg")

            assert os.path.isfile(f"agg_tests/layer-{test_layer.layer.name}.xlsx")
            assert os.path.isfile(f"agg_tests/layer-{test_layer.layer.name}.svg")

        shutil.rmtree("agg_tests")

    @staticmethod
    def test_upgrades():
        lay = Layer()
        lay2 = Layer()
        lay3 = Layer()
        lay.from_dict(testing_data.example_layer_v3_dict)
        lay2.from_dict(testing_data.example_layer_v42_dict)
        lay3.from_dict(testing_data.example_layer_v43_dict)

        out1 = lay.to_dict()
        out2 = lay2.to_dict()
        out3 = lay3.to_dict()

        assert all([(out3[x] == out1[x], x) for x in out3 if x not in ['versions', 'techniques', 'metadata',
                                                                       'gradient', 'selectSubtechniquesWithParent',
                                                                       'layout']])
        assert all([out3[x] == out2[x] for x in out3 if x not in ['versions', 'techniques', 'metadata']])
        assert all(['4.3' == x['versions']['layer'] for x in [out1, out2, out3]])


    @staticmethod
    def test_layer_ops():
        def get_layers_by_name(test_layers):
            layers_dict['Endgame'] = Layer()
            layers_dict['Endgame'].from_str(test_layers[0])
            layers_dict['Red2'] = Layer()
            layers_dict['Red2'].from_str(test_layers[1])
            return layers_dict

        def build_combined_layer(layers_dict):
            lo = LayerOps(score=lambda x: sum(x) / len(x))
            return lo.process(list(layers_dict.values()))

        layers_dict = {}
        layers_dict = get_layers_by_name([testing_data.example_layer_v3_longer, testing_data.example_layer_v3_all])
        out_layer = build_combined_layer(layers_dict)
        assert isinstance(out_layer, Layer)
