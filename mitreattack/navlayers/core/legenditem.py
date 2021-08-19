from mitreattack.navlayers.core.exceptions import typeChecker


class LegendItem:
    def __init__(self, label, color):
        """
            Initialization - Creates a legendItem object

            :param label: The label described by this object
            :param color: The color associated with the label
        """
        self.label = label
        self.color = color

    @property
    def color(self):
        return self.__color

    @color.setter
    def color(self, color):
        typeChecker(type(self).__name__, color, str, "color")
        self.__color = color

    @property
    def label(self):
        return self.__label

    @label.setter
    def label(self, label):
        typeChecker(type(self).__name__, label, str, "label")
        self.__label = label

    def get_dict(self):
        """
            Converts the currently loaded data into a dict
            :returns: A dict representation of the local legendItem object
        """
        return dict(label=self.__label, color=self.__color)
