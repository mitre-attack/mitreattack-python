"""Contains LegendItem class."""

from mitreattack.navlayers.core.exceptions import typeChecker


class LegendItem:
    """A LegendItem object."""

    def __init__(self, label, color):
        """Initialize - Creates a legendItem object.

        :param label: The label described by this object
        :param color: The color associated with the label
        """
        self.label = label
        self.color = color

    @property
    def color(self):
        """Getter for color."""
        return self.__color

    @color.setter
    def color(self, color):
        typeChecker(type(self).__name__, color, str, "color")
        self.__color = color

    @property
    def label(self):
        """Getter for label."""
        return self.__label

    @label.setter
    def label(self, label):
        typeChecker(type(self).__name__, label, str, "label")
        self.__label = label

    def get_dict(self):
        """Convert the currently loaded data into a dict.

        :returns: A dict representation of the local legendItem object
        """
        return dict(label=self.__label, color=self.__color)
