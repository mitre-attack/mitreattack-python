try:
    from ..core.exceptions import typeChecker, categoryChecker, UNSETVALUE
except ValueError:
    from core.exceptions import typeChecker, categoryChecker, UNSETVALUE


class Versions:
    def __init__(self, layer="4.1", attack=UNSETVALUE, navigator="4.1"):
        """
            Initialization - Creates a v4 Versions object

            :param layer: The layer version
            :param attack: The attack version
            :param navigator: The navigator version
        """
        self.layer = layer
        self.__attack = attack
        self.navigator = navigator

    @property
    def attack(self):
        if self.__attack != UNSETVALUE:
            return self.__attack
        else:
            return '4.x'

    @attack.setter
    def attack(self, attack):
        typeChecker(type(self).__name__, attack, str, "attack")
        self.__attack = attack

    @property
    def navigator(self):
        return self.__navigator

    @navigator.setter
    def navigator(self, navigator):
        typeChecker(type(self).__name__, navigator, str, "navigator")
        categoryChecker(type(self).__name__, navigator, ["4.0", "4.1"], "navigator version")
        self.__navigator = navigator

    @property
    def layer(self):
        return self.__layer

    @layer.setter
    def layer(self, layer):
        typeChecker(type(self).__name__, layer, str, "layer")
        categoryChecker(type(self).__name__, layer, ["3.0", "4.0", "4.1"], "layer version")
        if layer == '3.0':
            print('[NOTICE] - Forcibly upgrading version from {} to 4.1.'.format(layer))
            layer = "4.1"
        self.__layer = layer

    def get_dict(self):
        """
            Converts the currently loaded data into a dict
            :returns: A dict representation of the local Versions object
        """
        temp = dict()
        listing = vars(self)
        for entry in listing:
            if listing[entry] != UNSETVALUE:
                subname = entry.split('__')[-1]
                temp[subname] = listing[entry]
        return temp
