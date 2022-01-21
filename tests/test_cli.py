from mitreattack.navlayers.layerExporter_cli import main as LEC_main
from mitreattack.navlayers.layerGenerator_cli import main as LGC_main
from mitreattack.navlayers import Layer
from tests.resources.testing_data import example_layer_v43_dict as layer_template
import os
import shutil


class TestCLI:
    @staticmethod
    def test_export_svg():
        """Test SVG Export capabilities from CLI"""
        if os.path.isfile('test_export_svg.svg'):
            os.remove('test_export_svg.svg')
        if os.path.isfile('demo_file.json'):
            os.remove('demo_file.json')

        layer = Layer()
        layer.from_dict(layer_template)
        layer.to_file('demo_file.json')
        LEC_main(['demo_file.json', '-m', 'svg', '--output', 'test_export_svg.svg'])
        os.remove('demo_file.json')
        assert os.path.isfile('test_export_svg.svg')
        os.remove('test_export_svg.svg')

    @staticmethod
    def test_export_excel():
        """Test excel export capabilities from CLI"""
        if os.path.isfile('test_export_excel.xlsx'):
            os.remove('test_export_excel.xlsx')
        if os.path.isfile('demo_file.json'):
            os.remove('demo_file.json')

        layer = Layer()
        layer.from_dict(layer_template)
        layer.to_file('demo_file.json')
        LEC_main(['demo_file.json', '-m', 'excel', '--output', 'test_export_excel.xlsx'])
        os.remove('demo_file.json')
        assert os.path.isfile('test_export_excel.xlsx')
        os.remove('test_export_excel.xlsx')

    @staticmethod
    def test_generate_overview_group():
        """Test CLI group overview generation"""
        if os.path.isfile('test_overview_group'):
            os.remove('test_overview_group')

        LGC_main(["--domain", "mobile", "--source", "taxii", "--overview-type", "group", "--output",
                  "test_overview_group"])
        assert os.path.isfile("test_overview_group")
        os.remove('test_overview_group')

    @staticmethod
    def test_generate_overview_software():
        """Test CLI software overview generation"""
        if os.path.isfile('test_overview_software'):
            os.remove('test_overview_software')

        LGC_main(["--domain", "mobile", "--source", "taxii", "--overview-type", "software", "--output",
                  "test_overview_software"])
        assert os.path.isfile("test_overview_software")
        os.remove('test_overview_software')

    @staticmethod
    def test_generate_overview_mitigation():
        """Test CLI mitigation overview generation"""
        if os.path.isfile('test_overview_mitigation'):
            os.remove('test_overview_mitigation')

        LGC_main(["--domain", "enterprise", "--source", "taxii", "--overview-type", "mitigation", "--output",
                  "test_overview_mitigation"])
        assert os.path.isfile("test_overview_mitigation")
        os.remove('test_overview_mitigation')

    @staticmethod
    def test_generate_overview_datasource():
        """Test CLI datasource overview generation"""
        if os.path.isfile('test_overview_datasource'):
            os.remove('test_overview_datasource')

        LGC_main(["--domain", "enterprise", "--source", "taxii", "--overview-type", "datasource", "--output",
                  "test_overview_datasource"])
        assert os.path.isfile("test_overview_datasource")
        os.remove('test_overview_datasource')

    @staticmethod
    def test_generate_mapped_group():
        """Test CLI group mapped generation (APT1)"""
        if os.path.isfile('test_mapped_group'):
            os.remove('test_mapped_group')

        LGC_main(["--domain", "enterprise", "--source", "taxii", "--mapped-to", "APT1", "--output",
                  "test_mapped_group"])
        assert os.path.isfile("test_mapped_group")
        os.remove('test_mapped_group')

    @staticmethod
    def test_generate_mapped_software():
        """Test CLI software mapped generation (S0202)"""
        if os.path.isfile('test_mapped_software'):
            os.remove('test_mapped_software')

        LGC_main(["--domain", "enterprise", "--source", "taxii", "--mapped-to", "S0202", "--output",
                  "test_mapped_software"])
        assert os.path.isfile("test_mapped_software")
        os.remove('test_mapped_software')

    @staticmethod
    def test_generate_mapped_mitigation():
        """Test CLI mitigation mapped generation (M1013)"""
        if os.path.isfile('test_mapped_mitigation'):
            os.remove('test_mapped_mitigation')

        LGC_main(["--domain", "mobile", "--source", "taxii", "--mapped-to", "M1013", "--output",
                  "test_mapped_mitigation"])
        assert os.path.isfile("test_mapped_mitigation")
        os.remove('test_mapped_mitigation')

    @staticmethod
    def test_generate_mapped_datasource():
        """Test CLI datasource mapped generation"""
        if os.path.isfile('test_mapped_datasource'):
            os.remove('test_mapped_datasource')

        LGC_main(["--domain", "enterprise", "--source", "taxii", "--mapped-to",
                  "x-mitre-data-component--0f72bf50-35b3-419d-ab95-70f9b6a818dd", "--output", "test_mapped_datasource"])
        assert os.path.isfile("test_mapped_datasource")
        os.remove('test_mapped_datasource')

    @staticmethod
    def test_generate_batch_group():
        """Test CLI group batch generation"""
        if os.path.isdir('test_batch_group'):
            os.remove('test_batch_group')

        LGC_main(["--domain", "ics", "--source", "taxii", "--batch-type", "group", "--output",
                  "test_batch_group"])
        assert os.path.isdir("test_batch_group")
        shutil.rmtree('test_batch_group')

    @staticmethod
    def test_generate_batch_software():
        """Test CLI software batch generation"""
        if os.path.isdir('test_batch_software'):
            os.remove('test_batch_software')

        LGC_main(["--domain", "ics", "--source", "taxii", "--batch-type", "software", "--output",
                  "test_batch_software"])
        assert os.path.isdir("test_batch_software")
        shutil.rmtree('test_batch_software')

    @staticmethod
    def test_generate_batch_mitigation():
        """Test CLI mitigation batch generation"""
        if os.path.isdir('test_batch_mitigation'):
            os.remove('test_batch_mitigation')

        LGC_main(["--domain", "enterprise", "--source", "taxii", "--batch-type", "mitigation", "--output",
                  "test_batch_mitigation"])
        assert os.path.isdir("test_batch_mitigation")
        shutil.rmtree('test_batch_mitigation')

    @staticmethod
    def test_generate_batch_datasource():
        """Test CLI datasource batch generation"""
        if os.path.isdir('test_batch_datasource'):
            os.remove('test_batch_datasource')

        LGC_main(["--domain", "enterprise", "--source", "taxii", "--batch-type", "datasource", "--output",
                  "test_batch_datasource"])
        assert os.path.isdir("test_batch_datasource")
        shutil.rmtree('test_batch_datasource')
