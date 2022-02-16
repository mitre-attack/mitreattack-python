from mitreattack.navlayers.core.exceptions import typeChecker


class Metadata:
    def __init__(self, name, value):
        """
            Initialization - Creates a metadata object

            :param name: the name for this metadata entry
            :param value: the corresponding value for this metadata entry
        """
        self.name = name
        self.value = value

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, name):
        typeChecker(type(self).__name__, name, str, "name")
        self.__name = name

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, value):
        if isinstance(value, bool):
            value = str(value)
        typeChecker(type(self).__name__, value, str, "value")
        self.__value = value

    def get_dict(self):
        """
            Converts the currently loaded data into a dict
            :returns: A dict representation of the local metadata object
        """
        return dict(name=self.__name, value=self.__value)


class MetaDiv:
    def __init__(self, active):
        """
            Initialization - Creates a metadata object divider
        """
        self.__name = "DIVIDER"
        self.__value = active

    @property
    def name(self):
        return self.__name

    @property
    def state(self):
        return self.__value

    @state.setter
    def state(self, state):
        typeChecker(type(self).__name__, state, bool, "state")
        self.__value = state

    def get_dict(self):
        """
            Converts the currently loaded data into a dict
            :returns: A dict representation of the local metadata object
        """
        return dict(name=self.__name, value=self.__value)
