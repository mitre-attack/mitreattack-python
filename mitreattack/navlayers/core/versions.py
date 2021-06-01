try:
    from core.exceptions import typeChecker, categoryChecker, UNSETVALUE, BadInput
except ImportError:
    from mitreattack_python.navlayers.core.exceptions import typeChecker, categoryChecker, UNSETVALUE, BadInput


class Versions:
    def __init__(self, layer="4.2", attack=UNSETVALUE, navigator="4.2"):
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
        try:
            categoryChecker(type(self).__name__, navigator, ["4.0", "4.1", "4.2"], "navigator version")
        except BadInput:
            print(f'[WARNING] - unrecognized navigator version {navigator}. Defaulting to the 4.2 schema, '
                  f'this may result in unexpected behavior.')
        self.__navigator = navigator

    @property
    def layer(self):
        return self.__layer

    @layer.setter
    def layer(self, layer):
        typeChecker(type(self).__name__, layer, str, "layer")
        try:
            categoryChecker(type(self).__name__, layer, ["3.0", "4.0", "4.1", "4.2"], "layer version")
        except BadInput:
            print(f'[WARNING] - unrecognized layer version {layer}. Defaulting to the 4.2 schema, this may result in '
                  f'unexpected behavior.')
        if layer in ["3.0", "4.0", "4.1"]:
            print(f'[NOTICE] - Forcibly upgrading version from {layer} to 4.2.')
            layer = "4.2"
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
