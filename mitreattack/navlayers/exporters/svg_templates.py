"""Contains SvgTemplates class."""

import drawsvg

from mitreattack.navlayers.exporters.matrix_gen import MatrixGen
from mitreattack.navlayers.exporters.svg_objects import (
    G,
    SVG_HeaderBlock,
    SVG_Technique,
    Text,
    convertToPx,
    _optimalFontSize,
)
from mitreattack.navlayers.core.gradient import Gradient
from mitreattack.navlayers.core.filter import Filter


class BadTemplateException(Exception):
    """Custom exception used when bad templates are found."""

    pass


class SvgTemplates:
    """An SvgTemplates object."""

    def __init__(self, source="local", domain="enterprise", resource=None):
        """Initialize - Creates a SvgTemplate object.

        :param domain: Which domain to utilize for the underlying matrix layout
        :param source: Use local data
        :param resource: string path to local cache of stix data (local) or url of workbench to reach out
                            to (remote)
        """
        muse = domain
        if muse.startswith("mitre-"):
            muse = domain[6:]
        if muse.endswith("-attack"):
            muse = domain[:-7]
        if muse in ["enterprise", "mobile", "ics"]:
            self.mode = muse
            self.h = MatrixGen(source=source, resource=resource, domain=domain)
            self.lhandle = None
        else:
            raise BadTemplateException

    def _build_headers(
        self, name, config, domain="Enterprise", version="8", desc=None, filters=None, gradient=None, legend=[]
    ):
        """Build the header blocks for the svg.

        :param name: The name of the layer being exported
        :param config: SVG Config object
        :param domain: The layer's domain
        :param version: The layer's version
        :param desc: Description of the layer being exported
        :param filters: Any filters applied to the layer being exported
        :param gradient: Gradient information included with the layer
        :param legend: List of legend items
        :return: Instantiated SVG header
        """
        max_x = convertToPx(config.width, config.unit)
        max_y = convertToPx(config.height, config.unit)
        header_height = convertToPx(config.headerHeight, config.unit)
        ff = config.font
        d = drawsvg.Drawing(max_x, max_y, origin=(0, 0), displayInline=False)
        psych = 0

        if config.showHeader:
            border = convertToPx(config.border, config.unit)
            root = G(tx=border, ty=border, style=f"font-family: {ff}")

            header = G()
            root.append(header)
            b1 = G()
            header.append(b1)

            header_count = 0
            showAgg = False
            if config.showAbout:
                header_count += 1
            if config.showFilters:
                header_count += 1
            if config.showDomain:
                header_count += 1
            if config.showLegend and config.legendDocked and (gradient is not False or legend):
                header_count += 1
            if self.lhandle.layout:
                if self.lhandle.layout.showAggregateScores:
                    showAgg = True
                    header_count += 1

            operation_x = (max_x - border) - (1.5 * border * (header_count - 1)) - border
            if header_count > 0:
                header_width = operation_x / header_count
                if config.showAbout:
                    if desc is not None:
                        g = SVG_HeaderBlock().build(
                            height=header_height,
                            width=header_width,
                            label="about",
                            t1text=name,
                            t2text=desc,
                            config=config,
                        )
                    else:
                        g = SVG_HeaderBlock().build(
                            height=header_height, width=header_width, label="about", t1text=name, config=config
                        )
                    b1.append(g)
                    psych += 1
                if config.showDomain:
                    if domain.startswith("mitre-"):
                        domain = domain[6:].capitalize()
                    if domain.endswith("-attack"):
                        domain = domain[:-7].capitalize()
                    tag = domain + " ATT&CK v" + version
                    if config.showFilters and showAgg:
                        fi = filters
                        if fi is None:
                            fi = Filter()
                            fi.platforms = ["Windows", "Linux", "macOS"]
                        gD = SVG_HeaderBlock().build(
                            height=header_height,
                            width=header_width,
                            label="domain & platforms",
                            t1text=tag,
                            t2text=", ".join(fi.platforms),
                            config=config,
                        )
                    else:
                        gD = SVG_HeaderBlock().build(
                            height=header_height, width=header_width, label="domain", t1text=tag, config=config
                        )
                    bD = G(tx=operation_x / header_count * psych + 1.5 * border * psych)
                    header.append(bD)
                    bD.append(gD)
                    psych += 1
                if config.showFilters and not showAgg:
                    fi = filters
                    if fi is None:
                        fi = Filter()
                        fi.platforms = ["Windows", "Linux", "macOS"]
                    g2 = SVG_HeaderBlock().build(
                        height=header_height,
                        width=header_width,
                        label="filters",
                        t1text=", ".join(fi.platforms),
                        config=config,
                    )
                    b2 = G(tx=operation_x / header_count * psych + 1.5 * border * psych)
                    header.append(b2)
                    b2.append(g2)
                    psych += 1
                if showAgg:
                    t1 = (
                        f"showing aggregate scores using the {self.lhandle.layout.aggregateFunction} "
                        f"aggregate function"
                    )
                    stub = "does not include"
                    if self.lhandle.layout.countUnscored:
                        stub = "includes"
                    t2 = f"{stub} unscored techniques as having a score of 0"
                    gA = SVG_HeaderBlock().build(
                        height=header_height, width=header_width, label="aggregate", t1text=t1, t2text=t2, config=config
                    )
                    bA = G(tx=operation_x / header_count * psych + 1.5 * border * psych)
                    header.append(bA)
                    bA.append(gA)
                    psych += 1

                # build gradient/legend
                if config.showLegend and config.legendDocked:
                    b3 = G(tx=operation_x / header_count * psych + 1.5 * border * psych)
                    g3 = self._build_legend(gradient, legend, header_height, header_width, config)
                    header.append(b3)
                    b3.append(g3)
                    psych += 1
            d.append(root)

        # undocked legend
        overlay = None
        if config.showLegend and not config.legendDocked:
            adjusted_height = convertToPx(config.legendHeight, config.unit)
            adjusted_width = convertToPx(config.legendWidth, config.unit)

            g3 = self._build_legend(gradient, legend, adjusted_height, adjusted_width, config)

            lx = convertToPx(config.legendX, config.unit)
            if not lx:
                lx = max_x - adjusted_width - convertToPx(config.border, config.unit)
            ly = convertToPx(config.legendY, config.unit)
            if not ly:
                ly = max_y - adjusted_height - convertToPx(config.border, config.unit)
            overlay = G(tx=lx, ty=ly)
            if (ly + adjusted_height) > max_y or (lx + adjusted_width) > max_x:
                print("[WARNING] - Floating legend will render partly out of view...")
            overlay.append(g3)

        return d, psych, overlay

    def _build_legend(self, gradient, legend, height, width, config):
        """Build the legend block for the SVG.

        :param gradient: Gradient information included with the layer
        :param legend: List of legend items
        :param height: Height of the legend block
        :param width: Width of the legend block
        :param config: SVGConfig object
        :return: The SVG legend block
        """
        # get all gradient colors
        gradient_colors = []
        if gradient is not False:
            gr = gradient
            if gr is None:
                gr = Gradient(colors=["#ff6666", "#ffe766", "#8ec843"], minValue=1, maxValue=100)
            div = round((gr.maxValue - gr.minValue) / (len(gr.colors) * 2 - 1))
            for i in range(0, len(gr.colors) * 2 - 1):
                gradient_colors.append((gr.compute_color(int(gr.minValue + div * i)), gr.minValue + div * i))
            gradient_colors.append((gr.compute_color(gr.maxValue), gr.maxValue))

        # get all legend colors
        legend_colors = []
        if legend:
            for legend_item in legend:
                legend_colors.append((legend_item.color, legend_item.label))

        legend_block = SVG_HeaderBlock().build(
            height=height,
            width=width,
            label="legend",
            variant="graphic",
            gradient_colors=gradient_colors,
            legend_colors=legend_colors,
            config=config,
        )
        return legend_block

    def get_tactic(
        self, tactic, height, width, config, colors=[], scores=[], subtechs=[], exclude=[], mode=(True, False)
    ):
        """Build a 'tactic column' svg object.

        :param tactic: The corresponding tactic for this column
        :param height: A technique block's allocated height
        :param width: A technique blocks' allocated width
        :param config: A SVG Config object
        :param colors: Default color data in case of no score
        :param scores: Score values for the dataset
        :param subtechs: List of visible subtechniques
        :param exclude: List of excluded techniques
        :param mode: Tuple describing text for techniques (Show Name, Show ID)
        :return: Instantiated tactic column (or none if no techniques were found)
        """
        # create tactic column
        column = G(ty=2)
        tactic_name = tactic.tactic.name
        excluded_ids = [str(t[0]) + str(t[1]) for t in exclude]
        subtech_ids = [str(s[0]) + str(s[1]) for s in subtechs]

        # copy scores to SVG
        offset = 0
        for id in tactic.subtechniques:
            self._copy_scores(tactic.subtechniques[id], scores, tactic_name, exclude)

        for technique in tactic.techniques:
            if (str(technique.id) + str(self.h.convert(tactic_name))) in excluded_ids:
                continue
            self._copy_scores([technique], scores, tactic_name, exclude)
            if (str(technique.id) + str(self.h.convert(tactic_name))) in subtech_ids:
                technique_svg, offset = self.get_tech(
                    offset,
                    mode,
                    technique,
                    tactic=self.h.convert(tactic_name),
                    subtechniques=tactic.subtechniques.get(technique.id, []),
                    exclude=exclude,
                    colors=colors,
                    config=config,
                    height=height,
                    width=width,
                    subscores=tactic.subtechniques.get(technique.id, []),
                )
            else:
                technique_svg, offset = self.get_tech(
                    offset,
                    mode,
                    technique,
                    tactic=self.h.convert(tactic_name),
                    subtechniques=[],
                    exclude=exclude,
                    colors=colors,
                    config=config,
                    height=height,
                    width=width,
                    subscores=tactic.subtechniques.get(technique.id, []),
                )
            column.append(technique_svg)
        if len(column.children) == 0:
            return None
        return column

    def get_tech(
        self,
        offset,
        mode,
        technique,
        tactic,
        config,
        height,
        width,
        subtechniques=[],
        exclude=[],
        colors=[],
        subscores=[],
    ):
        """Retrieve a svg object for a single technique.

        :param offset: The offset in the column based on previous work
        :param mode: Tuple describing display format (Show Name, Show ID)
        :param technique: The technique to build a block for
        :param tactic: The corresponding tactic
        :param config: An SVG Config object
        :param height: The allocated height of a technique block
        :param width: The allocated width of a technique block
        :param subtechniques: A list of all visible subtechniques, some of which may apply to this one
        :param exclude: List of excluded techniques
        :param colors: A list of all color overrides in the event of no score, which may apply
        :param subscores: List of all subtechniques for the (visible or not) [includes scores]
        :return: Tuple (SVG block, new offset)
        """
        # Handle aggregate scoring (v4.2)
        if self.lhandle.layout:
            mod = self.lhandle.layout.compute_aggregate(technique, subscores)
            if mod is not None:
                technique.aggregateScore = mod
        a, b = SVG_Technique(self.lhandle.gradient).build(
            offset,
            technique,
            height,
            width,
            config,
            subtechniques=subtechniques,
            exclude=exclude,
            mode=mode,
            tactic=tactic,
            colors=colors,
            tBC=config.tableBorderColor,
        )
        return a, b

    def export(self, showName, showID, layer, config, sort=0, scores=[], colors=[], subtechs=[], exclude=[], legend=[]):
        """Export a layer object to an SVG object.

        :param showName: Boolean of whether or not to show names
        :param showID:  Boolean of whether or not to show IDs
        :param layer: The layer object being exported
        :param config: A SVG Config object
        :param sort: The sort mode
        :param scores: List of tactic scores
        :param colors: List of tactic default colors
        :param subtechs: List of visible subtechniques
        :param exclude: List of excluded techniques
        :param legend: List of legend items
        :return:
        """
        # get the matrix list of tactics
        self.matrix = self.h.get_matrix(self.mode, filters=layer.filters)

        # check for a gradient
        gradient = False
        if len(scores):
            gradient = layer.gradient
        self.lhandle = layer

        # build SVG headers
        drawing, presence, overlay = self._build_headers(
            layer.name, config, layer.domain, layer.versions.attack, layer.description, layer.filters, gradient, legend
        )

        # sort matrix by the given sort mode
        self.matrix = self.h._adjust_ordering(self.matrix, sort, scores)

        # count number of included techniques for each tactic
        lengths = []
        for tactic in self.matrix:
            num_techniques = len(tactic.techniques)

            tactic_technique_ids = [technique.id for technique in tactic.techniques]
            for technique_id, shortname in exclude:
                if technique_id in tactic_technique_ids:
                    if self.h.convert(shortname) == tactic.tactic.name or shortname is False:
                        num_techniques -= 1

            subtech_ids = [subtechnique[0] for subtechnique in subtechs]
            for subtechnique in tactic.subtechniques:
                if subtechnique in subtech_ids:
                    num_techniques += len(tactic.subtechniques[subtechnique])

            lengths.append(num_techniques)

        # calculate border
        border = convertToPx(config.border, config.unit)

        # calculate technique width
        technique_width = (convertToPx(config.width, config.unit) - 2.2 * border) / sum([1 for x in lengths if x > 0])
        technique_width -= border

        # calculate header offset
        header_offset = convertToPx(config.headerHeight, config.unit)
        if presence == 0:
            header_offset = 0
        header_offset += 2.5 * border

        # calculate technique height
        technique_height = convertToPx(config.height, config.unit) - header_offset - border
        technique_height /= max(lengths) + 1

        # create SVG object
        svg_glob = G(tx=border)

        # build SVG
        index = 0
        incre = technique_width + 1.1 * border
        for tactic in self.matrix:
            # get tactic display string
            displayStr = ""
            if showName and showID:
                displayStr = tactic.tactic.id + ": " + tactic.tactic.name
            elif showName:
                displayStr = tactic.tactic.name
            elif showID:
                displayStr = tactic.tactic.id

            # create header text
            header_glob = G(tx=index, ty=header_offset)
            text_glob = G(tx=technique_width / 2, ty=technique_height / 2)
            font_size, _ = _optimalFontSize(displayStr, technique_width, technique_height, config.fontSize)
            text = Text(ctype="TacticName", font_size=font_size, text=displayStr, position="middle")
            text_glob.append(text)
            header_glob.append(text_glob)

            # get tactic column
            tactic_col_svg = self.get_tactic(
                tactic,
                technique_height,
                technique_width,
                colors=colors,
                subtechs=subtechs,
                exclude=exclude,
                mode=(showName, showID),
                scores=scores,
                config=config,
            )

            # build tactic column svg
            tactic_col_glob = G(ty=technique_height)
            tactic_col_glob.append(tactic_col_svg)
            header_glob.append(tactic_col_glob)

            if tactic_col_svg:
                svg_glob.append(header_glob)
                index += incre

        drawing.append(svg_glob)

        # add overlay, if applicable
        if overlay:
            drawing.append(overlay)

        return drawing

    def _copy_scores(self, listing, scores, tactic_name, exclude):
        """Move scores over from the input object (scores) to the one used to build the svg (listing).

        :param listing: List of objects to apply scores to
        :param scores: List of scores for this tactic
        :param exclude: List of excluded techniques
        :return: None - operates on the raw object itself
        """
        excluded_ids = [str(t[0]) + str(t[1]) for t in exclude]
        for b in listing:
            if (str(b.id) + str(tactic_name)) in excluded_ids:
                b.score = None
                continue
            found = False
            for y in scores:
                if b.id == y[0] and (y[1] == self.h.convert(tactic_name) or not y[1]):
                    b.score = y[2]
                    found = True
                    continue
            if not found:
                b.score = None
