import os
import shutil

from resources.testing_data import example_layer_v3_all as data_layer

from mitreattack.navlayers import Layer, SVGConfig, ToExcel, ToSvg

source = "taxii"
resource = None

l1 = Layer()
l1.from_str(data_layer)


class TestMass:
    def test_dimensions(self):
        """Test SVG export: dimensions"""
        if os.path.isdir("mass"):
            shutil.rmtree("mass")

        index = 0
        os.mkdir("mass")
        os.mkdir("mass/output")
        for width in [8.5, 11]:
            for height in [8.5, 11]:
                for headerHeight in [1, 2]:
                    for unit in ["in", "cm"]:
                        c = SVGConfig(width=width, height=height, headerHeight=headerHeight, unit=unit)
                        l1.layer.description = f"{width}x{height}{unit}; header={headerHeight}"
                        t = ToSvg(domain=l1.layer.domain, source=source, resource=resource, config=c)
                        t.to_svg(l1, filepath=f"mass/output/{index}.svg")
                        e = ToExcel(domain=l1.layer.domain, source=source, resource=resource)
                        e.to_xlsx(l1, filepath=f"mass/output/{index}.xlsx")
                        assert os.path.exists(f"mass/output/{index}.xlsx")
                        assert os.path.exists(f"mass/output/{index}.svg")
                        index += 1
        shutil.rmtree("mass")

    def test_showSubtechniques(self):
        """Test SVG export: Displaying Subtechniques"""
        if os.path.isdir("mass"):
            shutil.rmtree("mass")

        index = 0
        os.mkdir("mass")
        os.mkdir("mass/output")
        for showSubtechniques in ["all", "expanded", "none"]:
            for showHeader in [True, False]:
                c = SVGConfig(showSubtechniques=showSubtechniques, showHeader=showHeader)
                l1.layer.description = f"subs={showSubtechniques},showHeader={showHeader}"
                t = ToSvg(domain=l1.layer.domain, source=source, resource=resource, config=c)
                t.to_svg(l1, filepath=f"mass/output/{index}.svg")
                e = ToExcel(domain=l1.layer.domain, source=source, resource=resource)
                e.to_xlsx(l1, filepath=f"mass/output/{index}.xlsx")
                assert os.path.exists(f"mass/output/{index}.xlsx")
                assert os.path.exists(f"mass/output/{index}.svg")
                index += 1
        shutil.rmtree("mass")

    def test_legendWidth(self):
        """Test SVG export: legend width variations"""
        if os.path.isdir("mass"):
            shutil.rmtree("mass")

        index = 0
        os.mkdir("mass")
        os.mkdir("mass/output")
        for legendWidth in [3, 6]:
            for legendHeight in [1, 2]:
                for legendX in [2, 4]:
                    for legendY in [2, 4]:
                        c = SVGConfig(
                            legendDocked=False,
                            legendWidth=legendWidth,
                            legendHeight=legendHeight,
                            legendX=legendX,
                            legendY=legendY,
                        )
                        l1.layer.description = f"undocked legend, {legendWidth}x{legendHeight} at {legendX}x{legendY}"
                        t = ToSvg(domain=l1.layer.domain, source=source, resource=resource, config=c)
                        t.to_svg(l1, filepath=f"mass/output/{index}.svg")
                        e = ToExcel(domain=l1.layer.domain, source=source, resource=resource)
                        e.to_xlsx(l1, filepath=f"mass/output/{index}.xlsx")
                        assert os.path.exists(f"mass/output/{index}.xlsx")
                        assert os.path.exists(f"mass/output/{index}.svg")
                        index += 1
        shutil.rmtree("mass")

    def test_showFilters(self):
        """Test SVG export: customization options"""
        if os.path.isdir("mass"):
            shutil.rmtree("mass")

        index = 0
        os.mkdir("mass")
        os.mkdir("mass/output")
        for showFilters in [True, False]:
            for showAbout in [True, False]:
                for showLegend in [True, False]:
                    for showDomain in [True, False]:
                        c = SVGConfig(
                            showFilters=showFilters, showAbout=showAbout, showLegend=showLegend, showDomain=showDomain
                        )
                        l1.layer.description = f"legend={showLegend}, filters={showFilters}, about={showAbout}"
                        t = ToSvg(domain=l1.layer.domain, source=source, resource=resource, config=c)
                        t.to_svg(l1, filepath=f"mass/output/{index}.svg")
                        e = ToExcel(domain=l1.layer.domain, source=source, resource=resource)
                        e.to_xlsx(l1, filepath=f"mass/output/{index}.xlsx")
                        assert os.path.exists(f"mass/output/{index}.xlsx")
                        assert os.path.exists(f"mass/output/{index}.svg")
                        index += 1
        shutil.rmtree("mass")

    def test_borders(self):
        """Test SVG export: borders"""
        if os.path.isdir("mass"):
            shutil.rmtree("mass")

        index = 0
        os.mkdir("mass")
        os.mkdir("mass/output")
        for border in [0.1, 0.3]:
            for tableBorderColor in ["#ddd", "#ffaaaa"]:
                c = SVGConfig(border=border, tableBorderColor=tableBorderColor)
                l1.layer.description = f"border={border}, tableBorderColor={tableBorderColor}"
                t = ToSvg(domain=l1.layer.domain, source=source, resource=resource, config=c)
                t.to_svg(l1, filepath=f"mass/output/{index}.svg")
                e = ToExcel(domain=l1.layer.domain, source=source, resource=resource)
                e.to_xlsx(l1, filepath=f"mass/output/{index}.xlsx")
                assert os.path.exists(f"mass/output/{index}.xlsx")
                assert os.path.exists(f"mass/output/{index}.svg")
                index += 1
        shutil.rmtree("mass")

    def test_counts(self):
        """Test SVG export: scores/aggregation"""
        if os.path.isdir("mass"):
            shutil.rmtree("mass")

        index = 0
        os.mkdir("mass")
        os.mkdir("mass/output")
        for countUnscored in [True, False]:
            for aggregateFunction in ["average", "min", "max", "sum"]:
                l1.layer.layout.countUnscored = countUnscored
                l1.layer.layout.aggregateFunction = aggregateFunction
                l1.layer.description = f"countUnscored={countUnscored}, aggregateFunction={aggregateFunction}"
                print(l1.layer.description)
                t = ToSvg(domain=l1.layer.domain, source=source, resource=resource)
                t.to_svg(l1, filepath=f"mass/output/{index}.svg")
                e = ToExcel(domain=l1.layer.domain, source=source, resource=resource)
                e.to_xlsx(l1, filepath=f"mass/output/{index}.xlsx")
                assert os.path.exists(f"mass/output/{index}.xlsx")
                assert os.path.exists(f"mass/output/{index}.svg")
                index += 1
        shutil.rmtree("mass")
