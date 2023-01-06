"""Contains Link and LinkDiv classes."""

from mitreattack.navlayers.core.exceptions import typeChecker


class Link:
    """A Link object."""

    def __init__(self, label, url):
        """Initialize - Creates a link object.

        :param label: the label for this link entry
        :param url: the corresponding url for this link entry
        """
        self.label = label
        self.url = url

    @property
    def label(self):
        """Getter for label."""
        return self.__label

    @label.setter
    def label(self, label):
        """Setter for label."""
        typeChecker(type(self).__name__, label, str, "label")
        self.__label = label

    @property
    def url(self):
        """Getter for url."""
        return self.__url

    @url.setter
    def url(self, url):
        """Setter for url."""
        typeChecker(type(self).__name__, url, str, "url")
        self.__url = url

    def get_dict(self):
        """Convert the currently loaded data into a dict.

        :returns: A dict representation of the local metadata object
        """
        return dict(label=self.__label, url=self.__url)


class LinkDiv:
    """A LinkDiv object."""

    def __init__(self, divider):
        """Initialize - Creates a Link object divider."""
        self.__divider = divider

    @property
    def state(self):
        """Getter for state."""
        return self.__divider

    @state.setter
    def state(self, state):
        """Setter for state."""
        typeChecker(type(self).__name__, state, bool, "state")
        self.__divider = state

    def get_dict(self):
        """Convert the currently loaded data into a dict.

        :returns: A dict representation of the local metadata object
        """
        return dict(divider=self.__divider)
