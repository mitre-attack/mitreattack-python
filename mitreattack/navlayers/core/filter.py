from mitreattack.navlayers.core.exceptions import typeCheckerArray, categoryChecker, UNSETVALUE


class Filter:
    def __init__(self, domain="enterprise-attack"):
        """
            Initialization - Creates a filter object, with an optional
                domain input

            :param domain: The domain used for this layer (mitre-enterprise
                or mitre-mobile)
        """
        self.domain = domain
        self.__platforms = UNSETVALUE

    @property
    def platforms(self):
        if self.__platforms != UNSETVALUE:
            return self.__platforms

    @platforms.setter
    def platforms(self, platforms):
        typeCheckerArray(type(self).__name__, platforms, str, "platforms")
        self.__platforms = []
        for entry in platforms:
            self.__platforms.append(entry)

    def get_dict(self):
        """
            Converts the currently loaded data into a dict
            :returns: A dict representation of the local filter object
        """
        temp = dict()
        listing = vars(self)
        for entry in listing:
            if entry == 'domain':
                continue
            if listing[entry] != UNSETVALUE:
                subname = entry.split('__')[-1]
                if subname != 'stages':
                    temp[subname] = listing[entry]
        if len(temp) > 0:
            return temp


class Filterv3(Filter):
    def __init__(self, domain="mitre-enterprise"):
        self.__stages = UNSETVALUE
        super().__init__(domain)

    @property
    def stages(self):
        if self.__stages != UNSETVALUE:
            return self.__stages

    @stages.setter
    def stages(self, stage):
        typeCheckerArray(type(self).__name__, stage, str, "stage")
        categoryChecker(type(self).__name__, stage[0], ["act", "prepare"],
                        "stages")
        self.__stages = stage
