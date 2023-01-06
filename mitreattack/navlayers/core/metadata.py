"""Contains Metadata and MetaDiv classes."""

from mitreattack.navlayers.core.exceptions import typeChecker


class Metadata:
    """A Metadata object."""

    def __init__(self, name, value):
        """Initialize - Creates a metadata object.

        :param name: the name for this metadata entry
        :param value: the corresponding value for this metadata entry
        """
        self.name = name
        self.value = value

    @property
    def name(self):
        """Getter for name."""
        return self.__name

    @name.setter
    def name(self, name):
        typeChecker(type(self).__name__, name, str, "name")
        self.__name = name

    @property
    def value(self):
        """Getter for value."""
        return self.__value

    @value.setter
    def value(self, value):
        if isinstance(value, bool):
            value = str(value)
        typeChecker(type(self).__name__, value, str, "value")
        self.__value = value

    def get_dict(self):
        """Convert the currently loaded data into a dict.

        :returns: A dict representation of the local metadata object
        """
        return dict(name=self.__name, value=self.__value)


class MetaDiv:
    """A MetaDiv object."""

    def __init__(self, active):
        """Initialize - Creates a metadata object divider."""
        self.__name = "DIVIDER"
        self.__value = active

    @property
    def name(self):
        """Getter for name."""
        return self.__name

    @property
    def state(self):
        """Getter for state."""
        return self.__value

    @state.setter
    def state(self, state):
        """Getter for state."""
        typeChecker(type(self).__name__, state, bool, "state")
        self.__value = state

    def get_dict(self):
        """Convert the currently loaded data into a dict.

        :returns: A dict representation of the local metadata object
        """
        return dict(name=self.__name, value=self.__value)
