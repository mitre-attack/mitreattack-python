"""Contains Versions class."""

from mitreattack.navlayers.core.exceptions import typeChecker, categoryChecker, UNSETVALUE, BadInput

defaults = dict(layer="4.5", navigator="5.0.0")


class Versions:
    """A Versions object."""

    def __init__(self, layer=defaults["layer"], attack=UNSETVALUE, navigator=defaults["navigator"]):
        """Initialize - Creates a v4 Versions object.

        :param layer: The layer version
        :param attack: The attack version
        :param navigator: The navigator version
        """
        self.layer = layer
        self.__attack = attack
        self.navigator = navigator

    @property
    def attack(self):
        """Getter for attack."""
        if self.__attack != UNSETVALUE:
            return self.__attack
        else:
            return "4.x"

    @attack.setter
    def attack(self, attack):
        """Setter for attack."""
        typeChecker(type(self).__name__, attack, str, "attack")
        self.__attack = attack

    @property
    def navigator(self):
        """Getter for navigator."""
        return self.__navigator

    @navigator.setter
    def navigator(self, navigator):
        """Setter for navigator."""
        typeChecker(type(self).__name__, navigator, str, "navigator")
        if not navigator.startswith("5."):
            print(
                f"[WARNING] - unrecognized navigator version {navigator}. Defaulting to the 5.X.X schema, "
                f"this may result in unexpected behavior."
            )
            navigator = defaults["navigator"]
        self.__navigator = navigator

    @property
    def layer(self):
        """Getter for layer."""
        return self.__layer

    @layer.setter
    def layer(self, layer):
        """Setter for layer."""
        typeChecker(type(self).__name__, layer, str, "layer")
        try:
            categoryChecker(type(self).__name__, layer, ["3.0", "4.0", "4.1", "4.2", "4.3", "4.4", "4.5"], "layer version")
        except BadInput:
            print(
                f"[WARNING] - unrecognized layer version {layer}. Defaulting to the 4.5 schema, this may result in "
                f"unexpected behavior."
            )
        if layer in ["3.0", "4.0", "4.1", "4.2", "4.3", "4.4"]:
            print(f"[NOTICE] - Forcibly upgrading version from {layer} to 4.5.")
            layer = "4.5"
        self.__layer = layer

    def get_dict(self):
        """Convert the currently loaded data into a dict.

        :returns: A dict representation of the local Versions object
        """
        temp = dict()
        listing = vars(self)
        for entry in listing:
            if listing[entry] != UNSETVALUE:
                subname = entry.split("__")[-1]
                temp[subname] = listing[entry]
        return temp
