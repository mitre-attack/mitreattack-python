"""Helper classes and functions for working with SVG objects."""

import drawsvg
import colorsys
import numpy as np
import os
from PIL import ImageFont

from mitreattack.navlayers.core.gradient import Gradient


def convertToPx(quantity, unit):
    """Convert values to pixels.

    :param quantity: value
    :param unit: unit for that value
    :return: quantity in pixels
    """
    if unit == "in":
        return quantity * 96
    if unit == "cm":
        return quantity * 37.79375
    if unit == "px":
        return quantity
    if unit == "em":
        return quantity * 16
    if unit == "pt":
        return quantity * 1.33
    return -1


def _getstringwidth(string, font, size):
    """Calculate the width of a string (in pixels).

    :param string: string to evaluate
    :param font: font to use
    :param size: font size
    :return: pixel length of string
    """
    font = ImageFont.truetype(f"{os.path.sep.join(__file__.split(os.path.sep)[:-1])}/fonts/{font}.ttf", int(size))
    length, _ = font.getbbox(string)[2:4]
    return length


def _getstringheight(string, font, size):
    """Calculate the width of a string (in pixels).

    :param string: string to evaluate
    :param font: font to use
    :param size: font size
    :return: pixel height of string
    """
    font = ImageFont.truetype(f"{os.path.sep.join(__file__.split(os.path.sep)[:-1])}/fonts/{font}.ttf", int(size))
    _, height = font.getbbox(string)[2:4]
    return height


def _findSpace(words, width, height, maxFontSize):
    """Find space locations for a string to keep it within width x height.

    :param words: string to evaluate
    :param width: width of the box
    :param height: height of the box
    :param maxFontSize: maximum font size
    :return:
    """
    padding = 4
    breakDistance = min(height, (maxFontSize + 3) * len(words))

    breakTextHeight = breakDistance / len(words)
    fitTextHeight = min(breakTextHeight, height) * 0.8

    longestWordLength = -9999
    fitTextWidth = 9999
    for w in range(0, len(words)):
        word = words[w]
        longestWordLength = max(longestWordLength, len(word))
    try:
        fitTextWidth = (width - (2 * padding)) / longestWordLength * 1.45
    except ZeroDivisionError:
        pass
    size = min(maxFontSize, fitTextHeight, fitTextWidth)
    return size


def _find_breaks(num_spaces, num_breaks=3):
    """Generate break mapping.

    :param num_spaces: number of spaces in string
    :param num_breaks: number of breaks to insert
    :return: list of possible break mappings
    """
    breaks = set()

    def recurse(breakset_inherit, depth, break_count):
        """Recursive combinatorics.

        breakset is binary array of break locations
        depth is the depth of recursion,
        break_count is how many breaks should be added
        """
        for i in range(len(breakset_inherit)):  # for each possible break
            # insert a break here
            breakset = np.copy(breakset_inherit)
            breakset[i] = 1
            breaks.add("".join(str(x) for x in breakset))
            # try inserting another depth of break
            if depth < break_count - 1:
                recurse(breakset, depth + 1, break_count)

    initial_breaks = [0] * num_spaces
    breaks.add("".join(str(x) for x in initial_breaks))
    recurse(initial_breaks, 0, num_breaks)

    return breaks


def _optimalFontSize(st, width, height, maxFontSize=12):
    """Calculate the optimal fontsize and word layout for a box of width x height.

    :param st: string to fit
    :param width: box width
    :param height: box height
    :param maxFontSize: maximum allowable font size
    :return: size in pixels for font, array of strings split by where new lines should go
    """
    words = st.split(" ")
    bestSize = -9999
    bestWordArrangement = []

    num_spaces = len(words)
    num_breaks = 1
    if num_spaces < 20:
        num_breaks = 2
    elif num_spaces < 50:
        num_breaks = 3

    if _findSpace([st], width, height, maxFontSize) == maxFontSize:
        return maxFontSize, [st]
    breaks = _find_breaks(num_spaces, num_breaks)
    for binaryString in breaks:
        wordSet = []

        for k in range(0, len(binaryString)):
            if binaryString[k] == "0":
                if len(wordSet) == 0:
                    wordSet.append(words[k])
                else:
                    wordSet[len(wordSet) - 1] = wordSet[len(wordSet) - 1] + " " + words[k]
            else:
                wordSet.append(words[k])

        size = _findSpace(wordSet, width, height, maxFontSize)
        if size > bestSize:
            bestSize = size
            bestWordArrangement = wordSet

    return bestSize, bestWordArrangement


class Cell(drawsvg.DrawingParentElement):
    """Cell class."""

    TAG_NAME = "rect"

    def __init__(self, height, width, fill, tBC, ctype=None):
        # tBC = tableBorderColor, ctype='class' field on resulting svg object, fill=[R,G,B]
        super().__init__(height=height, width=width, style=f"fill: rgb({fill[0]}, {fill[1]}, {fill[2]})", stroke=tBC)
        if ctype:
            self.args["class"] = ctype


class HeaderRect(drawsvg.DrawingParentElement):
    """HeaderRect class."""

    TAG_NAME = "rect"

    def __init__(self, width, height, ctype, x=None, y=None, outline=True):
        # ctype='class' field on resulting svg object, x=x coord, y=y coord
        super().__init__(width=width, height=height, fill="white", rx="5")
        self.args["class"] = ctype
        if x:
            self.args["x"] = x
        if y:
            self.args["y"] = y
        if outline:
            self.args["stroke"] = "black"


class G(drawsvg.DrawingParentElement):
    """G class."""

    TAG_NAME = "g"

    def __init__(self, tx=None, ty=None, style=None, ctype=None):
        # tx=translate x, ty=translate y, ctype='class' field on resulting svg object
        super().__init__()
        if tx is None:
            tx = 0
        if ty is None:
            ty = 0
        self.args["transform"] = "translate(" + str(tx) + "," + str(ty) + ")"
        if style:
            self.args["style"] = style
        if ctype:
            self.args["class"] = ctype


class Line(drawsvg.DrawingParentElement):
    """Line class."""

    TAG_NAME = "line"

    def __init__(self, x1, x2, y1, y2, stroke):
        # x1=start x, x2=stop x, y1=start y, y2=stop y, stroke='stroke' field on resulting svg object
        super().__init__(x1=x1, x2=x2, y1=y1, y2=y2, stroke=stroke)


class Text(drawsvg.Text):
    """Text class."""

    def __init__(self, text, font_size, ctype, position=None, tx=None, ty=None, x=None, y=None, fill=None):
        # ctype='class' object on resulting svg, position='text-anchor' field, tx/ty=translate x/y, x/y=x/y coord
        if x is None:
            x = 0
        if y is None:
            y = 0
        super().__init__(text=text, font_size=font_size, x=x, y=y)
        self.args["class"] = ctype
        if tx is None:
            tx = 0
        if ty is None:
            ty = 0
        if tx != 0 or ty != 0:
            self.args["transform"] = "translate(" + str(tx) + "," + str(ty) + ")"
        if position:
            self.args["style"] = f"text-anchor: {position}"
        if fill:
            self.args["fill"] = fill


class Swatch(drawsvg.DrawingParentElement):
    """Swatch class."""

    TAG_NAME = "rect"

    def __init__(self, height, width, fill):
        # fill= [R,G,B]
        super().__init__(height=height, width=width, style=f"fill: rgb({fill[0]}, {fill[1]}, {fill[2]})")


class SVG_HeaderBlock:
    """SVG_HeaderBlock class."""

    @staticmethod
    def build(
        height, width, label, config, variant="text", t1text=None, t2text=None, gradient_colors=[], legend_colors=[]
    ):
        """Build a single SVG Header Block object.

        :param height: Height of the block
        :param width: Width of the block
        :param label: Label for the block
        :param config: SVG configuration object
        :param variant: text or graphic - the type of header block to build
        :param t1text: upper text
        :param t2text: lower text
        :param gradient_colors: array of tuple (color, score value) for the gradient graphic
        :param legend_colors: array of tuple (color, label) for the legend item graphic
        :return:
        """
        g = G(ty=5)
        rect = HeaderRect(width, height, "header-box")
        g.append(rect)
        rect2 = HeaderRect(
            _getstringwidth(label, config.font, 12),
            _getstringheight(label, config.font, 12),
            "label-cover",
            x=7,
            y=-5,
            outline=False,
        )
        g.append(rect2)
        text = Text(label, 12, "header-box-label", x=8, y=3)
        g.append(text)
        internal = G(tx=5, ctype="header-box-content")
        g.append(internal)
        if variant == "text":
            upper = G(tx=0, ty=2.1)
            internal.append(upper)
            if t1text is not None:
                bu = t2text is not None and t2text != ""
                theight = height - 8
                if bu:
                    theight = theight / 2
                fs, patch_text = _optimalFontSize(t1text, width, theight, maxFontSize=28)
                lines = len(patch_text)
                y = theight / 2 + 2.1
                if lines > 1:
                    y = y - (theight / 5 * (lines - 1) - (fs * 6 / 16))
                if float(fs) < (convertToPx(config.border, config.unit) + 2.1):
                    y = theight / 2 + 2.1 - (theight / 5)
                t1 = Text("\n".join(patch_text), fs, "", x=4, y=y)
                upper.append(t1)
                if bu:
                    upper.append(Line(0, width - 10, theight, theight, stroke="#dddddd"))
                    upper_fs = fs
                    lower_offset = theight + 2.1
                    lower = G(tx=0, ty=lower_offset)
                    fs, patch_text = _optimalFontSize(t2text, width, (height - (height / 3 + upper_fs)), maxFontSize=28)
                    y = theight / 2 + 5.1
                    lines = len(patch_text)
                    adju = "\n".join(patch_text)
                    if lines > 1:
                        y = y - ((theight / 5) * (lines - 1))
                    if float(fs) > lower_offset:
                        y = y + 2 * (float(fs) - lower_offset)
                    t2 = Text(adju, fs, "", x=4, y=y)
                    lower.append(t2)
                    internal.append(lower)
        elif variant == "graphic":
            usable = width - 10
            sub1 = G(ty=5)
            internal.append(sub1)

            if len(gradient_colors):
                sub2 = G(ty=5)
                sub1.append(sub2)
                gradient_cells = G(ctype="legendCells")
                sub2.append(gradient_cells)
                offset = 0
                block_width = usable / len(gradient_colors)
                for entry in gradient_colors:
                    cell = G(ctype="cell", tx=offset)
                    conv = entry[0]
                    if conv.startswith("#"):
                        conv = conv[1:]
                    block = Swatch(15, block_width, tuple(int(conv[i : i + 2], 16) for i in (0, 2, 4)))
                    offset += block_width
                    cell.append(block)
                    gradient_cells.append(cell)
                    tblob = str(entry[1])
                    off = (block_width - (5 * (1 + len(tblob)))) / 2
                    if off < 0:
                        off = 0
                    fs, _ = _optimalFontSize("0", width / len(gradient_colors), height)
                    label = Text(tblob, fs, ctype="label", ty=25, tx=off)
                    cell.append(label)
            if len(legend_colors):
                sub3 = None
                if len(gradient_colors):
                    sub3 = G(ty=35)
                else:
                    sub3 = G(ty=5)
                sub1.append(sub3)
                legend_cells = G(ctype="legendCells")
                sub3.append(legend_cells)
                offset = 0
                block_width = usable / len(legend_colors)
                for entry in legend_colors:
                    cell = G(ctype="cell", tx=offset)
                    color = entry[0]
                    if color.startswith("#"):
                        color = color[1:]
                    block = Swatch(15, block_width, tuple(int(color[i : i + 2], 16) for i in (0, 2, 4)))
                    offset += block_width
                    cell.append(block)
                    legend_cells.append(cell)
                    legendLabel = str(entry[1])
                    off = (block_width - (5 * (1 + len(legendLabel)))) / 2
                    if off < 0:
                        off = 0
                    fs, _ = _optimalFontSize("0", width / len(legend_colors), height)
                    textLabel = Text(legendLabel, fs, ctype="label", ty=25, tx=off)
                    cell.append(textLabel)
        return g


class SVG_Technique:
    """SVG_Technique class."""

    def __init__(self, gradient):
        self.grade = gradient
        if self.grade is None:
            self.grade = Gradient(colors=["#ff6666", "#ffe766", "#8ec843"], minValue=1, maxValue=100)

    def build(
        self,
        offset,
        technique,
        height,
        width,
        config,
        tBC,
        subtechniques=[],
        exclude=[],
        mode=(True, False),
        tactic=None,
        colors=[],
    ):
        """Build a SVG Technique block.

        :param offset: Current offset to build the block at (so it fits in the column)
        :param technique: The technique to build a block for
        :param height: The height of the technique block
        :param width: The width of the technique block
        :param config: SVG configuration object
        :param tBC: The hex code of the technique block's border
        :param subtechniques: List of any visible subtechniques for this technique
        :param exclude: List of excluded techniques
        :param mode: Display mode (Show Name, Show ID)
        :param tactic: The corresponding tactic
        :param colors: List of all default color values if no score can be found
        :return: The newly created SVG technique block
        """
        g = G(ty=offset)
        c = self._com_color(technique, tactic, colors)
        t = dict(
            name=self._disp(technique.name, technique.id, mode),
            id=technique.id,
            color=tuple(int(c[i : i + 2], 16) for i in (0, 2, 4)),
        )
        tech, text = self._block(t, height, width, config, tBC=tBC)
        g.append(tech)
        g.append(text)
        new_offset = height
        excluded_ids = [str(t[0]) + str(t[1]) for t in exclude]
        count = 0
        for entry in subtechniques:
            if (str(entry.id) + str(tactic)) in excluded_ids:
                continue
            count += 1
            gp = G(tx=width / 5, ty=new_offset)
            g.append(gp)
            c = self._com_color(entry, tactic, colors)
            st = dict(
                name=self._disp(entry.name, entry.id, mode),
                id=entry.id,
                color=tuple(int(c[i : i + 2], 16) for i in (0, 2, 4)),
            )
            subtech, subtext = self._block(st, height, width - width / 5, config, tBC=tBC)
            gp.append(subtech)
            gp.append(subtext)
            new_offset = new_offset + height
        y_offset = height * (count + 2)
        if count > 0:
            g.append(
                drawsvg.Lines(
                    width / 16,
                    -height,
                    width / 8,
                    -height * 2,
                    width / 8,
                    -height * (count + 1),
                    width / 5,
                    -height * (count + 1),
                    width / 5,
                    -height,
                    close=True,
                    fill=tBC,
                    stroke=tBC,
                    transform=f'translate(0,{y_offset})'
                )
            )
        return g, offset + new_offset

    @staticmethod
    def _block(technique, height, width, config, tBC):
        """Build a technique block element.

        :param technique: Technique data dictionary
        :param height: Block height
        :param width: Block width
        :param config: SVG configuration object
        :param tBC: Block border color
        :return: Block object, fit text object
        """
        tech = Cell(height, width, technique["color"], ctype=technique["id"], tBC=tBC)

        fs, patch_text = _optimalFontSize(technique["name"], width, height, config.fontSize)
        adjusted = "\n".join(patch_text)

        lines = adjusted.count("\n")

        y = height / 2
        if lines > 0:
            y = (height - (lines * fs)) / 2 + height / 10  # padding
        else:
            y = y + fs / 4

        hls = colorsys.rgb_to_hls(technique["color"][0], technique["color"][1], technique["color"][2])
        fill = None
        if hls[1] < 127.5:
            fill = "white"

        text = Text(adjusted.encode("utf-8").decode("ascii", "backslashreplace"), fs, "", x=4, y=y, fill=fill)
        return tech, text

    def _com_color(self, technique, tactic, colors=[]):
        """Retrieve hex color for a block.

        :param technique: Technique object
        :param tactic: What tactic the technique falls under
        :param colors: Default technique color data
        :return: Hex color code
        """
        c = "FFFFFF"
        tscore = None
        if technique.score is not None:
            tscore = technique.score
        if hasattr(technique, "aggregateScore"):
            tscore = technique.aggregateScore
        if tscore is not None:
            c = self.grade.compute_color(tscore)[1:]
        else:
            for x in colors:
                if x[0] == technique.id and (x[1] == tactic or not x[1]):
                    c = x[2][1:]
        return c

    @staticmethod
    def _disp(name, id, mode):
        """Generate technique display form.

        :param name: The name of the technique
        :param id: The ID of the technique
        :param mode: Which mode to use
        :return: Target display string for the technique
        """
        p1 = name
        p2 = id
        if not mode[0]:
            p1 = ""
        if not mode[1]:
            p2 = ""
        out = ": ".join([p2, p1])
        if out.startswith(": "):
            return p1
        return out
