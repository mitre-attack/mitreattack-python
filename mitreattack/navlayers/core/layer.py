"""Contains Layer class."""

import json
import traceback

from mitreattack.navlayers.core.exceptions import UninitializedLayer, BadType, BadInput, handler
from mitreattack.navlayers.core.layerobj import _LayerObj


class Layer:
    """A Layer object."""

    def __init__(self, init_data={}, name=None, domain=None, strict=True):
        """Initialize - create a new Layer object.

        :param init_data: Optionally provide base Layer json or string data on initialization
        """
        self.__layer = None
        self.strict = strict
        if isinstance(name, str) and isinstance(domain, str):
            self.__data = dict(name=name, domain=domain)
            self._build()
        elif isinstance(init_data, str):
            self.from_str(init_data)
        else:
            self.from_dict(init_data)

    @property
    def layer(self):
        """Getter for layer."""
        if self.__layer is not None:
            return self.__layer
        return "No Layer Loaded Yet!"

    @layer.setter
    def layer(self, layer):
        """Setter for layer."""
        if isinstance(layer, _LayerObj):
            self.__layer = layer

    def from_str(self, init_str):
        """Load a raw layer string into the object.

        :param init_str: the string representing the layer data to be loaded
        """
        self.__data = json.loads(init_str)
        self._build()

    def from_dict(self, init_dict):
        """Load a raw layer string into the object.

        :param init_dict: the dictionary representing the layer data to be loaded
        """
        self.__data = init_dict
        if self.__data != {}:
            self._build()

    def from_file(self, filename):
        """Load input from a layer file specified by filename.

        :param filename: the target filename to load from
        """
        fallback = False
        with open(filename, "r", encoding="utf-16") as fio:
            try:
                raw = fio.read()
            except UnicodeError or UnicodeDecodeError:
                fallback = True
        if fallback:
            with open(filename, "r") as fio:
                raw = fio.read()
        self.__data = json.loads(raw)
        self._build()

    def to_file(self, filename):
        """Save the current state of the layer to a layer file specified by filename.

        :param filename: the target filename to save as
        """
        if self.__layer is not None:
            with open(filename, "w", encoding="utf-16") as fio:
                json.dump(self.__layer.get_dict(), fio, ensure_ascii=False)
        else:
            raise UninitializedLayer

    def _build(self):
        """Load the data stored in self.data into a LayerObj (self.layer)."""
        try:
            self.__layer = _LayerObj(self.__data["name"], self.__data["domain"])
        except BadType or BadInput as e:
            handler(type(self).__name__, f"Layer is malformed: {e}. Unable to load.")
            self.__layer = None
            return
        except KeyError as e:
            handler(type(self).__name__, f"Layer is missing parameters: {e}. Unable to load.")
            self.__layer = None
            return

        for key in self.__data:
            if key not in ["name", "domain"]:
                try:
                    self.__layer._linker(key, self.__data[key])
                except Exception as e:
                    if self.strict:
                        handler(
                            type(self).__name__,
                            f"{str(e.__class__.__name__)} encountered [{e}]. Unable to load.",
                        )
                        handler(type(self).__name__, f"Full Traceback - {traceback.format_exc()}")
                        self.__layer = None
                        return

    def to_dict(self):
        """Convert the currently loaded layer file into a dict.

        :returns: A dict representation of the current layer object
        """
        if self.__layer is not None:
            return self.__layer.get_dict()

    def to_str(self):
        """Convert the currently loaded layer file into a string representation of a dictionary.

        :returns: A string representation of the current layer object
        """
        if self.__layer is not None:
            return json.dumps(self.to_dict())
