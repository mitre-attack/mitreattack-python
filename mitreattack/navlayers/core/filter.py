"""Contains Filter and Filterv3 classes."""

from mitreattack.navlayers.core.exceptions import typeCheckerArray, categoryChecker, UNSETVALUE


class Filter:
    """A Filter object."""

    def __init__(self, domain="enterprise-attack"):
        """Initialize - Creates a filter object, with an optional domain input.

        :param domain: The domain used for this layer (mitre-enterprise
            or mitre-mobile)
        """
        self.domain = domain
        self.__platforms = UNSETVALUE

    @property
    def platforms(self):
        """Getter for platforms."""
        if self.__platforms != UNSETVALUE:
            return self.__platforms

    @platforms.setter
    def platforms(self, platforms):
        """Setter for platforms."""
        typeCheckerArray(type(self).__name__, platforms, str, "platforms")
        self.__platforms = []
        for entry in platforms:
            self.__platforms.append(entry)

    def get_dict(self):
        """Convert the currently loaded data into a dict.

        :returns: A dict representation of the local filter object
        """
        temp = dict()
        listing = vars(self)
        for entry in listing:
            if entry == "domain":
                continue
            if listing[entry] != UNSETVALUE:
                subname = entry.split("__")[-1]
                if subname != "stages":
                    temp[subname] = listing[entry]
        if len(temp) > 0:
            return temp


class Filterv3(Filter):
    """A Filterv3 object."""

    def __init__(self, domain="mitre-enterprise"):
        self.__stages = UNSETVALUE
        super().__init__(domain)

    @property
    def stages(self):
        """Getter for stages."""
        if self.__stages != UNSETVALUE:
            return self.__stages

    @stages.setter
    def stages(self, stage):
        """Setter for stages."""
        typeCheckerArray(type(self).__name__, stage, str, "stage")
        categoryChecker(type(self).__name__, stage[0], ["act", "prepare"], "stages")
        self.__stages = stage
