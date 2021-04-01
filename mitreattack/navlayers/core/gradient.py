import colour
import math
try:
    from ..core.exceptions import typeChecker, typeCheckerArray
except ImportError:
    from core.exceptions import typeChecker, typeCheckerArray


class Gradient:
    def __init__(self, colors, minValue, maxValue):
        """
            Initialization - Creates a gradient object

            :param colors: The array of color codes for this gradient
            :param minValue: The minValue for this gradient
            :param maxValue: The maxValue for this gradient
        """
        self.__minValue = None
        self.__maxValue = None
        self.colors = colors
        self.minValue = minValue
        self.maxValue = maxValue

    @property
    def colors(self):
        return self.__colors

    @colors.setter
    def colors(self, colors):
        typeCheckerArray(type(self).__name__, colors, str, "colors")
        self.__colors = []
        for entry in colors:
            self.__colors.append(entry)
        self._compute_curve()

    @property
    def minValue(self):
        return self.__minValue

    @minValue.setter
    def minValue(self, minValue):
        typeChecker(type(self).__name__, minValue, int, "minValue")
        self.__minValue = minValue
        self._compute_curve()

    @property
    def maxValue(self):
        return self.__maxValue

    @maxValue.setter
    def maxValue(self, maxValue):
        typeChecker(type(self).__name__, maxValue, int, "maxValue")
        self.__maxValue = maxValue
        self._compute_curve()

    def _compute_curve(self):
        """
            Computes the gradient color curve
        """
        if self.maxValue is not None and self.minValue is not None and self.colors is not None:
            chunksize = int(math.floor((self.maxValue - self.minValue)/(len(self.colors) - 1)))
            fchunksize = int(math.ceil((self.maxValue - self.minValue)/(len(self.colors) - 1)))
            self.curve = []
            index = 1
            while index < len(self.colors):
                s_c = colour.Color(self.colors[index-1])
                e_c = colour.Color(self.colors[index])
                if index == len(self.colors):
                    curve_2 = list(s_c.range_to(e_c, fchunksize))
                else:
                    curve_2 = list(s_c.range_to(e_c, chunksize))
                index += 1
                self.curve.extend(curve_2)
            self.curve.append(colour.Color(self.colors[-1]))

    def compute_color(self, score):
        """
            Computes a specific color based on the score value provided
            :returns: A hexadecimal color representation of the score on
                the gradient
        """
        if score <= self.minValue:
            return self.curve[0].hex_l
        if score >= self.maxValue:
            return self.curve[-1].hex_l

        target = self.curve[score - self.minValue]
        return target.hex_l


    def get_dict(self):
        """
            Converts the currently loaded gradient file into a dict
            :returns: A dict representation of the current gradient object
        """
        return dict(colors=self.__colors, minValue=self.__minValue,
                    maxValue=self.maxValue)
