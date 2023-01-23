"""Contains Technique class."""

from mitreattack.navlayers.core.exceptions import (
    BadInput,
    handler,
    typeChecker,
    loadChecker,
    UNSETVALUE,
    UnknownTechniqueProperty,
    BadType,
    MissingParameters,
)
from mitreattack.navlayers.core.metadata import Metadata, MetaDiv
from mitreattack.navlayers.core.objlink import Link, LinkDiv
from mitreattack.navlayers.core.helpers import handle_object_placement


class Technique:
    """A Technique object."""

    def __init__(self, tID):
        """Initialize - Creates a technique object.

        :param tID: The techniqueID associated with this technique object
        """
        self.techniqueID = tID
        self.__tactic = UNSETVALUE
        self.__comment = UNSETVALUE
        self.__enabled = UNSETVALUE
        self.__score = UNSETVALUE
        self.__color = UNSETVALUE
        self.__metadata = UNSETVALUE
        self.__showSubtechniques = UNSETVALUE
        self.__aggregateScore = UNSETVALUE
        self.__links = UNSETVALUE

    @property
    def techniqueID(self):
        """Getter for techniqueID."""
        return self.__techniqueID

    @techniqueID.setter
    def techniqueID(self, techniqueID):
        """Setter for techniqueID."""
        typeChecker(type(self).__name__, techniqueID, str, "techniqueID")
        if not techniqueID.startswith("T"):
            handler(type(self).__name__, f"{techniqueID} not a valid value for techniqueID")
            raise BadInput
        else:
            self.__techniqueID = techniqueID

    @property
    def tactic(self):
        """Getter for tactic."""
        if self.__tactic != UNSETVALUE:
            return self.__tactic

    @tactic.setter
    def tactic(self, tactic):
        """Setter for tactic."""
        typeChecker(type(self).__name__, tactic, str, "tactic")
        self.__tactic = tactic

    @property
    def comment(self):
        """Getter for comment."""
        if self.__comment != UNSETVALUE:
            return self.__comment

    @comment.setter
    def comment(self, comment):
        """Setter for comment."""
        typeChecker(type(self).__name__, comment, str, "comment")
        self.__comment = comment

    @property
    def enabled(self):
        """Getter for enabled."""
        if self.__enabled != UNSETVALUE:
            return self.__enabled

    @enabled.setter
    def enabled(self, enabled):
        """Setter for enabled."""
        typeChecker(type(self).__name__, enabled, bool, "enabled")
        self.__enabled = enabled

    @property
    def score(self):
        """Getter for score."""
        if self.__score != UNSETVALUE:
            return self.__score

    @score.setter
    def score(self, score):
        """Setter for score."""
        try:
            typeChecker(type(self).__name__, score, int, "score")
            self.__score = score
        except BadType:
            typeChecker(type(self).__name__, score, float, "score")
            self.__score = int(score)

    @property
    def color(self):
        """Getter for color."""
        if self.__color != UNSETVALUE:
            return self.__color

    @color.setter
    def color(self, color):
        """Setter for color."""
        typeChecker(type(self).__name__, color, str, "color")
        self.__color = color

    @property
    def metadata(self):
        """Getter for metadata."""
        if self.__metadata != UNSETVALUE:
            return self.__metadata

    @metadata.setter
    def metadata(self, metadata):
        """Setter for metadata."""
        typeChecker(type(self).__name__, metadata, list, "metadata")
        self.__metadata = []

        try:
            for entry in metadata:
                try:
                    if isinstance(entry, Metadata) or isinstance(entry, MetaDiv):
                        loadChecker(type(self).__name__, entry.get_dict(), ["name", "value"], "metadata")
                        self.__metadata.append(entry)
                    elif isinstance(entry, dict):
                        loadChecker(type(self).__name__, entry, ["name", "value"], "metadata")
                        if entry["name"] == "DIVIDER":
                            self.__metadata.append(MetaDiv(active=entry["value"]))
                        else:
                            self.__metadata.append(Metadata(name=entry["name"], value=entry["value"]))
                    else:
                        pass  # Object in the list was not of Metadata or MetaDiv classes
                except MissingParameters as e:
                    handler(type(self).__name__, f"Metadata {entry} is missing parameters: {e}. Skipping.")
        except KeyError as e:
            handler(type(self).__name__, f"Metadata {entry} is missing parameters: {e}. Unable to load.")

    @property
    def showSubtechniques(self):
        """Getter for showSubtechniques."""
        if self.__showSubtechniques != UNSETVALUE:
            return self.__showSubtechniques

    @showSubtechniques.setter
    def showSubtechniques(self, showSubtechniques):
        """Setter for showSubtechniques."""
        typeChecker(type(self).__name__, showSubtechniques, bool, "showSubtechniques")
        self.__showSubtechniques = showSubtechniques

    @property
    def aggregateScore(self):
        """Getter for aggregateScore."""
        if self.__aggregateScore != UNSETVALUE:
            return self.__aggregateScore

    @aggregateScore.setter
    def aggregateScore(self, aggregateScore):
        """Setter for aggregateScore."""
        typeChecker(type(self).__name__, aggregateScore, int, "aggregate")
        self.__aggregateScore = aggregateScore

    @property
    def links(self):
        """Getter for links."""
        if self.__links != UNSETVALUE:
            return self.__links

    @links.setter
    def links(self, links):
        """Setter for links."""
        typeChecker(type(self).__name__, links, list, "links")
        if not handle_object_placement(self.__links, links, Link):
            self.__links = []
        entry = ""
        try:
            for entry in links:
                if isinstance(entry, Link):
                    loadChecker(type(self).__name__, entry.get_dict(), ["label", "url"], "link")
                    self.__links.append(entry)
                elif isinstance(entry, LinkDiv):
                    loadChecker(type(self).__name__, entry.get_dict(), ["divider"], "linkdiv")
                    self.__links.append(entry)
                elif isinstance(entry, dict):
                    if "divider" in entry and entry["divider"]:
                        loadChecker(type(self).__name__, entry, ["divider"], "linkdiv")
                        self.__links.append(LinkDiv(divider=entry["divider"]))
                    else:
                        loadChecker(type(self).__name__, entry, ["label", "url"], "link")
                        self.__links.append(Link(label=entry["label"], url=entry["url"]))
                else:
                    pass
        except KeyError as e:
            handler(type(self).__name__, f"Link {entry} is missing parameters: {e}. Unable to load.")

    def _loader(self, data):
        """Middleman for loading values into the technique object from a dict representation.

        :param data: A dict describing the technique
        :raises UnknownTechniqueProperty: An error indicating that an
            unexpected property was found on the technique
        """
        for entry in data.keys():
            if entry == "techniqueID":
                pass
            elif entry == "tactic":
                self.tactic = data[entry]
            elif entry == "comment":
                self.comment = data[entry]
            elif entry == "enabled":
                self.enabled = data[entry]
            elif entry == "score":
                self.score = data[entry]
            elif entry == "color":
                self.color = data[entry]
            elif entry == "metadata":
                self.metadata = data[entry]
            elif entry == "showSubtechniques":
                self.showSubtechniques = data[entry]
            elif entry == "links":
                self.links = data[entry]
            elif entry == "aggregateScore":
                self.aggregateScore = data[entry]
            else:
                handler(type(self).__name__, f"Unknown technique property: {entry}")
                raise UnknownTechniqueProperty

    def get_dict(self):
        """Convert the currently loaded data into a dict.

        :returns: A dict representation of the local technique object
        """
        dset = vars(self)
        temp = {}
        for key in dset:
            entry = key.split(type(self).__name__ + "__")[-1]
            if dset[key] != UNSETVALUE:
                if entry != "metadata" and entry != "links":
                    temp[entry] = dset[key]
                else:
                    temp[entry] = [x.get_dict() for x in dset[key]]
        return temp
