"""Contains SVGConfig and ToSvg classes."""

import json
from copy import deepcopy

from mitreattack.navlayers.core import Layer
from mitreattack.navlayers.exporters.svg_templates import SvgTemplates


class NoLayer(Exception):
    """Custom exception used when no layer is found."""

    pass


class SVGConfig:
    """A SVGConfig object."""

    d_width = 8.5
    d_height = 11
    d_headerHeight = 1
    d_unit = "in"
    d_showSubtechniques = "expanded"
    d_font = "sans-serif"
    d_tableBorderColor = "#6B7279"
    d_showHeader = True
    d_legendDocked = True
    d_legendX = 0
    d_legendY = 0
    d_legendWidth = 2
    d_legendHeight = 1
    d_showLegend = True
    d_showFilters = True
    d_showAbout = True
    d_showDomain = True
    d_border = 0.104

    def __init__(
        self,
        width=d_width,
        height=d_height,
        headerHeight=d_headerHeight,
        unit=d_unit,
        showSubtechniques=d_showSubtechniques,
        font=d_font,
        tableBorderColor=d_tableBorderColor,
        showHeader=d_showHeader,
        legendDocked=d_legendDocked,
        legendX=d_legendX,
        legendY=d_legendY,
        legendWidth=d_legendWidth,
        legendHeight=d_legendHeight,
        showLegend=d_showLegend,
        showFilters=d_showFilters,
        showAbout=d_showAbout,
        showDomain=d_showDomain,
        border=d_border,
    ):
        """Define parameters to configure SVG export.

        :param width: Desired SVG width
        :param height: Desired SVG height
        :param headerHeight: Desired Header Block height
        :param unit: SVG measurement units (qualifies width, height, etc.) - "in", "cm", "px", "em", or "pt"
        :param showSubtechniques: Display form for subtechniques - "all", "expanded" (decided by layer), or "none"
        :param font: What font style to use - "serif", "sans-serif", or "monospace"
        :param tableBorderColor: Hex color to use for the technique borders
        :param showHeader: Whether or not to show Header Blocks
        :param legendDocked: Whether or not the legend should be docked
        :param legendX: Where to place the legend on the x axis if not docked
        :param legendY: Where to place the legend on the y axis if not docked
        :param legendWidth: Width of the legend if not docked
        :param legendHeight: Height of the legend if not docked
        :param showLegend: Whether or not to show the legend
        :param showFilters: Whether or not to show the Filter Header Block
        :param showAbout: Whether or not to show the About Header Block
        :param showDomain: Whether or not to show the Domain Version Header Block
        :param border: What default border width to use
        """
        # force defaults in case bad values are provided so we don't crash later
        self.width = self.d_width
        self.height = self.d_height
        self.headerHeight = self.d_headerHeight
        self.unit = self.d_unit
        self.showSubtechniques = self.d_showSubtechniques
        self.font = self.d_font
        self.tableBorderColor = self.d_tableBorderColor
        self.showHeader = self.d_showHeader
        self.legendDocked = self.d_legendDocked
        self.legendX = self.d_legendX
        self.legendY = self.d_legendY
        self.legendWidth = self.d_legendWidth
        self.legendHeight = self.d_legendHeight
        self.showDomain = self.d_showDomain
        self.showLegend = self.d_showLegend
        self.showFilters = self.d_showFilters
        self.showAbout = self.d_showAbout
        self.border = self.d_border

        self.width = width
        self.height = height
        self.headerHeight = headerHeight
        self.unit = unit
        self.showSubtechniques = showSubtechniques
        self.font = font
        self.tableBorderColor = tableBorderColor
        self.showHeader = showHeader
        self.legendDocked = legendDocked
        self.legendX = legendX
        self.legendY = legendY
        self.legendWidth = legendWidth
        self.legendHeight = legendHeight
        self.showDomain = showDomain
        self.showLegend = showLegend
        self.showFilters = showFilters
        self.showAbout = showAbout
        self.border = border

    def load_from_file(self, filename=""):
        """Load config from a json file.

        :param filename: The file to read from
        """
        with open(filename, "r") as fio:
            raw = fio.read()
        self._data = json.loads(raw)
        for entry in self._data:
            patched = entry
            if not patched.startswith("_SVGConfig__"):
                patched = "_SVGConfig__" + patched
            if patched in vars(self).keys():
                setattr(self, entry, self._data[entry])
            else:
                print(f"WARNING - Unidentified Config Field in {filename}: {entry}")

        self.__str__()

    def save_to_file(self, filename=""):
        """Store config to json file.

        :param filename: The file to write to
        """
        out = dict(
            width=self.width,
            height=self.height,
            headerHeight=self.headerHeight,
            unit=self.unit,
            showSubtechniques=self.showSubtechniques,
            font=self.font,
            tableBorderColor=self.tableBorderColor,
            showHeader=self.showHeader,
            legendDocked=self.legendDocked,
            legendX=self.legendX,
            legendY=self.legendY,
            legendWidth=self.legendWidth,
            legendHeight=self.legendHeight,
            showLegend=self.showLegend,
            showFilters=self.showFilters,
            showAbout=self.showAbout,
            border=self.border,
        )
        with open(filename, "w", encoding="utf-16") as file:
            json.dump(out, file, ensure_ascii=False)

    def __str__(self):
        """Display current configuration."""
        print("SVGConfig current settings: ")
        print(f"width - {self.width}")
        print(f"height - {self.height}")
        print(f"headerHeight - {self.headerHeight}")
        print(f"unit - {self.unit}")
        print(f"showSubtechniques - {self.showSubtechniques}")
        print(f"font - {self.font}")
        print(f"tableBorderColor - {self.tableBorderColor}")
        print(f"showHeader - {self.showHeader}")
        print(f"legendDocked - {self.legendDocked}")
        print(f"legendX - {self.legendX}")
        print(f"legendY - {self.legendY}")
        print(f"legendWidth - {self.legendWidth}")
        print(f"legendHeight - {self.legendHeight}")
        print(f"showLegend - {self.showLegend}")
        print(f"showFilters - {self.showFilters}")
        print(f"showAbout - {self.showAbout}")
        print(f"border - {self.border}")

    @property
    def width(self):
        """Width getter."""
        if self.__width is not None:
            return self.__width

    @width.setter
    def width(self, width):
        """Width setter."""
        if isinstance(width, int) or isinstance(width, float):
            self.__width = width
        else:
            print(f"[Warning] - Unable to set width to {width}: not a float or int")

    @property
    def height(self):
        """Height getter."""
        if self.__height is not None:
            return self.__height

    @height.setter
    def height(self, height):
        """Height setter."""
        if isinstance(height, int) or isinstance(height, float):
            self.__height = height
        else:
            print(f"[Warning] - Unable to set height to {height}: not a float or int")

    @property
    def headerHeight(self):
        """Header Height getter."""
        if self.__headerHeight is not None:
            return self.__headerHeight

    @headerHeight.setter
    def headerHeight(self, headerHeight):
        """Header Height setter."""
        if isinstance(headerHeight, int) or isinstance(headerHeight, float):
            self.__headerHeight = headerHeight
        else:
            print(f"[Warning] - Unable to set headerHeight to {headerHeight}: not a float or int")

    @property
    def unit(self):
        """Getter for Unit."""
        if self.__unit is not None:
            return self.__unit

    @unit.setter
    def unit(self, unit):
        """Setter for Unit."""
        if unit in ["in", "cm", "px", "em", "pt"]:
            self.__unit = unit
        else:
            print(f'[Warning] - Unable to set unit to {unit}: not one of ["in", "cm", "px", "em", "pt"]')

    @property
    def showSubtechniques(self):
        """Show Subtechniques getter."""
        if self.__showSubtechniques is not None:
            return self.__showSubtechniques

    @showSubtechniques.setter
    def showSubtechniques(self, showSubtechniques):
        """Show Subtechniques setter."""
        if showSubtechniques in ["expanded", "all", "none"]:
            self.__showSubtechniques = showSubtechniques
        else:
            print(
                '[Warning] - Unable to set showSubtechniques to {}: not one of ["expanded", "all", "none"]'.format(
                    showSubtechniques
                )
            )

    @property
    def font(self):
        """Font getter."""
        if self.__font is not None:
            return self.__font

    @font.setter
    def font(self, font):
        """Font setter."""
        if font in ["serif", "sans-serif", "monospace"]:
            self.__font = font
        else:
            print(f'[Warning] - Unable to set font to {font}: not one of ["serif", "sans-serif", "monospace"]')

    @property
    def tableBorderColor(self):
        """Table Border Color getter."""
        if self.__tableBorderColor is not None:
            return self.__tableBorderColor

    @tableBorderColor.setter
    def tableBorderColor(self, tableBorderColor):
        """Table Border Color setter."""
        if isinstance(tableBorderColor, str) and tableBorderColor.startswith("#") and len(tableBorderColor) == 7:
            self.__tableBorderColor = tableBorderColor
        else:
            reason = ""
            if not isinstance(tableBorderColor, str):
                reason = "not a string"
            elif not tableBorderColor.startswith("#"):
                reason = "not a valid code (does not start with #)"
            elif len(tableBorderColor) != 7:
                reason = "not a valid code (#ZZZZZZ)"
            print(f"[Warning] - Unable to set tableBorderColor to {tableBorderColor}: " + reason)

    @property
    def showHeader(self):
        """Show Header getter."""
        if self.__showHeader is not None:
            return self.__showHeader

    @showHeader.setter
    def showHeader(self, showHeader):
        """Show Header setter."""
        if isinstance(showHeader, bool):
            self.__showHeader = showHeader
        else:
            print(f"[Warning] - Unable to set showHeader to {showHeader}: not a bool")

    @property
    def legendDocked(self):
        """Legend Docked getter."""
        if self.__legendDocked is not None:
            return self.__legendDocked

    @legendDocked.setter
    def legendDocked(self, legendDocked):
        """Legend Docked setter."""
        if isinstance(legendDocked, bool):
            self.__legendDocked = legendDocked
        else:
            print(f"[Warning] - Unable to set legendDocked to {legendDocked}: not a bool")

    @property
    def legendX(self):
        """Legend X getter."""
        if self.__legendX is not None:
            return self.__legendX

    @legendX.setter
    def legendX(self, legendX):
        """Legend X setter."""
        if isinstance(legendX, int) or isinstance(legendX, float):
            self.__legendX = legendX
        else:
            print(f"[Warning] - Unable to set legendX to {legendX}: not a float or int")

    @property
    def legendY(self):
        """Legend Y getter."""
        if self.__legendY is not None:
            return self.__legendY

    @legendY.setter
    def legendY(self, legendY):
        """Legend Y setter."""
        if isinstance(legendY, int) or isinstance(legendY, float):
            self.__legendY = legendY
        else:
            print(f"[Warning] - Unable to set legendY to {legendY}: not a float or int")

    @property
    def legendWidth(self):
        """Legend Width getter."""
        if self.__legendWidth is not None:
            return self.__legendWidth

    @legendWidth.setter
    def legendWidth(self, legendWidth):
        """Legend Width setter."""
        if isinstance(legendWidth, int) or isinstance(legendWidth, float):
            self.__legendWidth = legendWidth
        else:
            print(f"[Warning] - Unable to set legendWidth to {legendWidth}: not a float or int")

    @property
    def legendHeight(self):
        """Legend Height getter."""
        if self.__legendHeight is not None:
            return self.__legendHeight

    @legendHeight.setter
    def legendHeight(self, legendHeight):
        """Legend Height setter."""
        if isinstance(legendHeight, int) or isinstance(legendHeight, float):
            self.__legendHeight = legendHeight
        else:
            print(f"[Warning] - Unable to set legendHeight to {legendHeight}: not a float or int")

    @property
    def showLegend(self):
        """Show Legend getter."""
        if self.__showLegend is not None:
            return self.__showLegend

    @showLegend.setter
    def showLegend(self, showLegend):
        """Show Legend setter."""
        if isinstance(showLegend, bool):
            self.__showLegend = showLegend
        else:
            print(f"[Warning] - Unable to set showLegend to {showLegend}: not a bool")

    @property
    def showFilters(self):
        """Show Filters getter."""
        if self.__showFilters is not None:
            return self.__showFilters

    @showFilters.setter
    def showFilters(self, showFilters):
        """Show Filters setter."""
        if isinstance(showFilters, bool):
            self.__showFilters = showFilters
        else:
            print(f"[Warning] - Unable to set showFilters to {showFilters}: not a bool")

    @property
    def showAbout(self):
        """Show About getter."""
        if self.__showAbout is not None:
            return self.__showAbout

    @showAbout.setter
    def showAbout(self, showAbout):
        """Show About setter."""
        if isinstance(showAbout, bool):
            self.__showAbout = showAbout
        else:
            print(f"[Warning] - Unable to set showAbout to {showAbout}: not a bool")

    @property
    def showDomain(self):
        """Show Domain getter."""
        if self.__showDomain is not None:
            return self.__showDomain

    @showDomain.setter
    def showDomain(self, showDomain):
        """Show Domain setter."""
        if isinstance(showDomain, bool):
            self.__showDomain = showDomain
        else:
            print(f"[Warning] - Unable to set showAbout to {showDomain}: not a bool")

    @property
    def border(self):
        """Border getter."""
        if self.__border is not None:
            return self.__border

    @border.setter
    def border(self, border):
        """Border setter."""
        if isinstance(border, float):
            self.__border = border
        else:
            print(f"[Warning] - Unable to set border to {border}: not a float")


class ToSvg:
    """A ToSvg object."""

    def __init__(self, domain="enterprise", source="taxii", resource=None, config=None):
        """Set up exporting system, builds underlying matrix.

        :param domain: Which domain to utilize for the underlying matrix layout
        :param source: Use the taxii server, local data, or a remote ATT&CK Workbench instance
        :param resource: string path to local cache of stix data (local) or url of workbench to reach out
                            to (remote)
        :param config: Optional pre-existing SVGConfig object
        """
        self.raw_handle = SvgTemplates(domain=domain, source=source, resource=resource)
        if config is not None and isinstance(config, SVGConfig):
            self.config = config
        else:
            self.config = SVGConfig()

    def to_svg(self, layerInit, filepath="example.svg"):
        """Generate a svg file based on the input layer.

        :param layerInit: Input attack layer object to transform
        :param filepath: Desired output svg location
        :return: (meta) svg file at the targeted output location
        """
        if layerInit is not None:
            if not isinstance(layerInit, Layer):
                raise TypeError

        if layerInit is None:
            raise NoLayer

        layer = deepcopy(layerInit)

        included_subs = []
        if layer.layer.techniques:
            for entry in layer.layer.techniques:
                if self.config.showSubtechniques == "expanded":
                    if entry.showSubtechniques:
                        if not entry.enabled:
                            continue
                        if entry.tactic:
                            included_subs.append((entry.techniqueID, entry.tactic))
                        else:
                            included_subs.append((entry.techniqueID, False))
                elif self.config.showSubtechniques == "all":
                    if not entry.enabled:
                        continue
                    if entry.tactic:
                        included_subs.append((entry.techniqueID, entry.tactic))
                    else:
                        included_subs.append((entry.techniqueID, False))
                else:  # none displayed
                    pass

        excluded = []
        if layer.layer.hideDisabled:
            for entry in layer.layer.techniques:
                if entry.enabled is False:
                    if entry.tactic:
                        excluded.append((entry.techniqueID, entry.tactic))
                    else:
                        excluded.append((entry.techniqueID, False))
        scores = []
        colors = []
        if layer.layer.techniques:
            for entry in layer.layer.techniques:
                tscore = entry.score
                if tscore is not None:
                    if entry.tactic:
                        scores.append((entry.techniqueID, entry.tactic, tscore))
                    else:
                        scores.append((entry.techniqueID, False, tscore))
                elif entry.color:
                    if entry.tactic:
                        colors.append((entry.techniqueID, entry.tactic, entry.color))
                    else:
                        colors.append((entry.techniqueID, False, entry.color))
        sName = True
        sID = False
        sort = 0
        if layer.layer.layout:
            sName = layer.layer.layout.showName
            sID = layer.layer.layout.showID
        if layer.layer.sorting:
            sort = layer.layer.sorting
        if layer.layer.legendItems:
            legend = layer.layer.legendItems
        d = self.raw_handle.export(
            showName=sName,
            showID=sID,
            sort=sort,
            scores=scores,
            subtechs=included_subs,
            colors=colors,
            exclude=excluded,
            layer=layer.layer,
            legend=legend,
            config=self.config,
        )
        d.saveSvg(filepath)
