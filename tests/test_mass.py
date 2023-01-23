from pathlib import Path

from loguru import logger
from stix2 import MemoryStore

from mitreattack.navlayers import Layer, SVGConfig, ToExcel, ToSvg


def check_svg_generation(layer: Layer, path: Path, resource: MemoryStore, index: int, config: SVGConfig = None):
    t = ToSvg(domain=layer.layer.domain, source="memorystore", resource=resource, config=config)
    svg_output = path / f"{index}.svg"
    t.to_svg(layerInit=layer, filepath=str(svg_output))
    assert svg_output.exists()


def check_xlsx_generation(layer: Layer, path: Path, resource: MemoryStore, index: int):
    e = ToExcel(domain=layer.layer.domain, source="memorystore", resource=resource)
    xlsx_output = path / f"{index}.xlsx"
    e.to_xlsx(layerInit=layer, filepath=str(xlsx_output))
    assert xlsx_output.exists()


def test_showSubtechniques(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: Displaying Subtechniques"""
    logger.debug(f"{tmp_path=}")
    index = 0
    for showSubtechniques in ["all", "expanded", "none"]:
        for showHeader in [True, False]:
            c = SVGConfig(showSubtechniques=showSubtechniques, showHeader=showHeader)
            layer_v3_all.layer.description = f"subs={showSubtechniques},showHeader={showHeader}"

            check_svg_generation(
                layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index, config=c
            )
            check_xlsx_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index)
            index += 1


def test_dimensions(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: dimensions"""
    logger.debug(f"{tmp_path=}")
    index = 0
    for width in [8.5, 11]:
        for height in [8.5, 11]:
            for headerHeight in [1, 2]:
                for unit in ["in", "cm"]:
                    c = SVGConfig(width=width, height=height, headerHeight=headerHeight, unit=unit)
                    layer_v3_all.layer.description = f"{width}x{height}{unit}; header={headerHeight}"

                    check_svg_generation(
                        layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index, config=c
                    )
                    check_xlsx_generation(
                        layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index
                    )
                    index += 1


def test_legendWidth(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: legend width variations"""
    logger.debug(f"{tmp_path=}")
    index = 0
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
                    layer_v3_all.layer.description = (
                        f"undocked legend, {legendWidth}x{legendHeight} at {legendX}x{legendY}"
                    )

                    check_svg_generation(
                        layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index, config=c
                    )
                    check_xlsx_generation(
                        layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index
                    )
                    index += 1


def test_showFilters(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: customization options"""
    logger.debug(f"{tmp_path=}")
    index = 0
    for showFilters in [True, False]:
        for showAbout in [True, False]:
            for showLegend in [True, False]:
                for showDomain in [True, False]:
                    c = SVGConfig(
                        showFilters=showFilters, showAbout=showAbout, showLegend=showLegend, showDomain=showDomain
                    )
                    layer_v3_all.layer.description = f"legend={showLegend}, filters={showFilters}, about={showAbout}"

                    check_svg_generation(
                        layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index, config=c
                    )
                    check_xlsx_generation(
                        layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index
                    )
                    index += 1


def test_borders(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: borders"""
    logger.debug(f"{tmp_path=}")
    index = 0
    for border in [0.1, 0.3]:
        for tableBorderColor in ["#ddd", "#ffaaaa"]:
            c = SVGConfig(border=border, tableBorderColor=tableBorderColor)
            layer_v3_all.layer.description = f"border={border}, tableBorderColor={tableBorderColor}"

            check_svg_generation(
                layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index, config=c
            )
            check_xlsx_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index)
            index += 1


def test_counts(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: scores/aggregation"""
    logger.debug(f"{tmp_path=}")
    index = 0
    for countUnscored in [True, False]:
        for aggregateFunction in ["average", "min", "max", "sum"]:
            layer_v3_all.layer.layout.countUnscored = countUnscored
            layer_v3_all.layer.layout.aggregateFunction = aggregateFunction
            layer_v3_all.layer.description = f"countUnscored={countUnscored}, aggregateFunction={aggregateFunction}"
            print(layer_v3_all.layer.description)

            check_svg_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index)
            check_xlsx_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, index=index)
            index += 1
