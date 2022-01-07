from mitreattack.navlayers.core.exceptions import typeChecker


class Link:
    def __init__(self, label, url):
        """
            Initialization - Creates a link object

            :param label: the label for this link entry
            :param url: the corresponding url for this link entry
        """
        self.label = label
        self.url = url

    @property
    def label(self):
        return self.__label

    @label.setter
    def label(self, label):
        typeChecker(type(self).__name__, label, str, "label")
        self.__label = label

    @property
    def url(self):
        return self.__url

    @url.setter
    def url(self, url):
        typeChecker(type(self).__name__, url, str, "url")
        self.__url = url

    def get_dict(self):
        """
            Converts the currently loaded data into a dict
            :returns: A dict representation of the local metadata object
        """
        return dict(label=self.__label, url=self.__url)


class LinkDiv:
    def __init__(self, active):
        """
            Initialization - Creates a Link object divider
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
