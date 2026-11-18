"""Contains Gradient class."""

import colour

from mitreattack.navlayers.core.exceptions import typeChecker, typeCheckerArray


class Gradient:
    """A Gradient object."""

    def __init__(self, colors, minValue, maxValue):
        """Initialize - Creates a gradient object.

        :param colors: The array of color codes for this gradient
        :param minValue: The minValue for this gradient
        :param maxValue: The maxValue for this gradient
        """
        self.__minValue = None
        self.__maxValue = None
        self.__alpha = []
        self.colors = colors
        self.minValue = minValue
        self.maxValue = maxValue

    @property
    def colors(self):
        """Getter for colors."""
        return self.__colors

    @colors.setter
    def colors(self, colors):
        typeCheckerArray(type(self).__name__, colors, str, "colors")
        self.__colors = []
        self.__alpha = []
        for entry in colors:
            try:
                colour.Color(entry)
            except AttributeError:
                self.__alpha.append(entry[-2:])
                if entry.startswith("#"):
                    entry = entry[:7]
                else:
                    entry = entry[:6]
            self.__colors.append(entry)

    @property
    def minValue(self):
        """Getter for minValue."""
        return self.__minValue

    @minValue.setter
    def minValue(self, minValue):
        typeChecker(type(self).__name__, minValue, int, "minValue")
        self.__minValue = minValue

    @property
    def maxValue(self):
        """Getter for maxValue."""
        return self.__maxValue

    @maxValue.setter
    def maxValue(self, maxValue):
        typeChecker(type(self).__name__, maxValue, int, "maxValue")
        self.__maxValue = maxValue

    def compute_color(self, score):
        """Compute a specific color based on the score value provided.

        Colors are interpolated linearly in RGB between evenly spaced gradient stops, as in the ATT&CK Navigator.

        :returns: A hexadecimal color representation of the score on the gradient
        """
        stops = [colour.Color(color) for color in self.colors]
        if score <= self.minValue or len(stops) == 1:
            return stops[0].hex_l
        if score >= self.maxValue:
            return stops[-1].hex_l

        position = (score - self.minValue) / (self.maxValue - self.minValue) * (len(stops) - 1)
        index = min(int(position), len(stops) - 2)
        fraction = position - index
        start, end = stops[index].rgb, stops[index + 1].rgb
        return colour.Color(rgb=tuple(s + (e - s) * fraction for s, e in zip(start, end, strict=True))).hex_l

    def get_dict(self):
        """Convert the currently loaded gradient file into a dict.

        :returns: A dict representation of the current gradient object
        """
        if len(self.__alpha) == len(self.__colors):
            color_out = [f"{self.__colors[i]}{self.__alpha[i]}" for i in range(0, len(self.__alpha))]
        else:
            color_out = self.__colors
        return dict(colors=color_out, minValue=self.__minValue, maxValue=self.maxValue)
