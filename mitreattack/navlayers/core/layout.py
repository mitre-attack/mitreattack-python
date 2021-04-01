try:
    from ..core.exceptions import typeChecker, categoryChecker, UNSETVALUE
except ImportError:
    from core.exceptions import typeChecker, categoryChecker, UNSETVALUE


class Layout:
    def __init__(self):
        """
            Initialization - Creates a layout object
        """
        self.__layout = UNSETVALUE
        self.__showID = UNSETVALUE
        self.__showName = UNSETVALUE

    @property
    def layout(self):
        if self.__layout != UNSETVALUE:
            return self.__layout

    @layout.setter
    def layout(self, layout):
        typeChecker(type(self).__name__, layout, str, "layout")
        categoryChecker(type(self).__name__, layout, ["side", "flat", "mini"],
                        "layout")
        self.__layout = layout

    @property
    def showID(self):
        if self.__showID != UNSETVALUE:
            return self.__showID

    @showID.setter
    def showID(self, showID):
        typeChecker(type(self).__name__, showID, bool, "showID")
        self.__showID = showID

    @property
    def showName(self):
        if self.__showName != UNSETVALUE:
            return self.__showName

    @showName.setter
    def showName(self, showName):
        typeChecker(type(self).__name__, showName, bool, "showName")
        self.__showName = showName

    def get_dict(self):
        """
            Converts the currently loaded data into a dict
            :returns: A dict representation of the local layout object
        """
        listing = vars(self)
        temp = dict()
        for entry in listing:
            if listing[entry] != UNSETVALUE:
                temp[entry.split(type(self).__name__ + '__')[-1]]\
                    = listing[entry]
        if len(temp) > 0:
            return temp
