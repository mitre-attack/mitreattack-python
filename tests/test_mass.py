import uuid
from pathlib import Path

from loguru import logger
from stix2 import MemoryStore

from mitreattack.navlayers import Layer, SVGConfig, ToExcel, ToSvg


def check_svg_generation(layer: Layer, path: Path, resource: MemoryStore, config: SVGConfig = None):
    t = ToSvg(domain=layer.layer.domain, source="memorystore", resource=resource, config=config)
    svg_output = path / f"{uuid.uuid4()}.svg"
    t.to_svg(layerInit=layer, filepath=str(svg_output))
    assert svg_output.exists()


def check_xlsx_generation(layer: Layer, path: Path, resource: MemoryStore):
    e = ToExcel(domain=layer.layer.domain, source="memorystore", resource=resource)
    xlsx_output = path / f"{uuid.uuid4()}.xlsx"
    e.to_xlsx(layerInit=layer, filepath=str(xlsx_output))
    assert xlsx_output.exists()


def test_showSubtechniques(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: Displaying Subtechniques"""
    logger.debug(f"{tmp_path=}")
    showSubtechniques = "all"
    showHeader = True

    c = SVGConfig(showSubtechniques=showSubtechniques, showHeader=showHeader)
    layer_v3_all.layer.description = f"subs={showSubtechniques},showHeader={showHeader}"

    check_svg_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, config=c)
    check_xlsx_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest)


def test_dimensions(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: dimensions"""
    logger.debug(f"{tmp_path=}")
    width = 8.5
    height = 11
    headerHeight = 2
    unit = "in"

    c = SVGConfig(width=width, height=height, headerHeight=headerHeight, unit=unit)
    layer_v3_all.layer.description = f"{width}x{height}{unit}; header={headerHeight}"

    check_svg_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, config=c)
    check_xlsx_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest)


def test_legendWidth(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: legend width variations"""
    logger.debug(f"{tmp_path=}")
    legendWidth = 3
    legendHeight = 1
    legendX = 2
    legendY = 4

    c = SVGConfig(
        legendDocked=False,
        legendWidth=3,
        legendHeight=1,
        legendX=2,
        legendY=2,
    )
    layer_v3_all.layer.description = f"undocked legend, {legendWidth}x{legendHeight} at {legendX}x{legendY}"

    check_svg_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, config=c)
    check_xlsx_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest)


def test_showFilters(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: customization options"""
    logger.debug(f"{tmp_path=}")
    showFilters = True
    showAbout = True
    showLegend = True
    showDomain = True

    c = SVGConfig(showFilters=showFilters, showAbout=showAbout, showLegend=showLegend, showDomain=showDomain)
    layer_v3_all.layer.description = f"legend={showLegend}, filters={showFilters}, about={showAbout}"

    check_svg_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, config=c)
    check_xlsx_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest)


def test_borders(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: borders"""
    logger.debug(f"{tmp_path=}")
    border = 0.2
    tableBorderColor = "#ddd"
    c = SVGConfig(border=border, tableBorderColor=tableBorderColor)
    layer_v3_all.layer.description = f"border={border}, tableBorderColor={tableBorderColor}"

    check_svg_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest, config=c)
    check_xlsx_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest)


def test_counts(tmp_path: Path, layer_v3_all: Layer, memstore_enterprise_latest: MemoryStore):
    """Test SVG export: scores/aggregation"""
    logger.debug(f"{tmp_path=}")
    countUnscored = True
    aggregateFunction = "average"

    layer_v3_all.layer.layout.countUnscored = countUnscored
    layer_v3_all.layer.layout.aggregateFunction = aggregateFunction
    layer_v3_all.layer.description = f"countUnscored={countUnscored}, aggregateFunction={aggregateFunction}"
    logger.info(layer_v3_all.layer.description)

    check_svg_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest)
    check_xlsx_generation(layer=layer_v3_all, path=tmp_path, resource=memstore_enterprise_latest)
