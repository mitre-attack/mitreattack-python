from mitreattack.navlayers.core.exceptions import BadInput, handler, typeChecker, loadChecker, UNSETVALUE, \
    UnknownTechniqueProperty, BadType, MissingParameters
from mitreattack.navlayers.core.metadata import Metadata, MetaDiv
from mitreattack.navlayers.core.objlink import Link, LinkDiv
from mitreattack.navlayers.core.helpers import handle_object_placement


class Technique:
    def __init__(self, tID):
        """
            Initialization - Creates a technique object

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
        return self.__techniqueID

    @techniqueID.setter
    def techniqueID(self, techniqueID):
        typeChecker(type(self).__name__, techniqueID, str, "techniqueID")
        if not techniqueID.startswith('T'):
            handler(type(self).__name__, '{} not a valid value for techniqueID'
                    .format(techniqueID))
            raise BadInput
        else:
            self.__techniqueID = techniqueID

    @property
    def tactic(self):
        if self.__tactic != UNSETVALUE:
            return self.__tactic

    @tactic.setter
    def tactic(self, tactic):
        typeChecker(type(self).__name__, tactic, str, "tactic")
        self.__tactic = tactic

    @property
    def comment(self):
        if self.__comment != UNSETVALUE:
            return self.__comment

    @comment.setter
    def comment(self, comment):
        typeChecker(type(self).__name__, comment, str, "comment")
        self.__comment = comment

    @property
    def enabled(self):
        if self.__enabled != UNSETVALUE:
            return self.__enabled

    @enabled.setter
    def enabled(self, enabled):
        typeChecker(type(self).__name__, enabled, bool, "enabled")
        self.__enabled = enabled

    @property
    def score(self):
        if self.__score != UNSETVALUE:
            return self.__score

    @score.setter
    def score(self, score):
        try:
            typeChecker(type(self).__name__, score, int, "score")
            self.__score = score
        except BadType:
            typeChecker(type(self).__name__, score, float, "score")
            self.__score = int(score)

    @property
    def color(self):
        if self.__color != UNSETVALUE:
            return self.__color

    @color.setter
    def color(self, color):
        typeChecker(type(self).__name__, color, str, "color")
        self.__color = color

    @property
    def metadata(self):
        if self.__metadata != UNSETVALUE:
            return self.__metadata

    @metadata.setter
    def metadata(self, metadata):
        typeChecker(type(self).__name__, metadata, list, "metadata")
        self.__metadata = []

        try:
            for entry in metadata:
                try:
                    if isinstance(entry, Metadata) or isinstance(entry, MetaDiv):
                        loadChecker(type(self).__name__, entry.get_dict(), ['name', 'value'], "metadata")
                        self.__metadata.append(entry)
                    elif isinstance(entry, dict):
                        loadChecker(type(self).__name__, entry, ['name', 'value'], "metadata")
                        if entry['name'] == "DIVIDER":
                            self.__metadata.append(MetaDiv(active=entry['value']))
                        else:
                            self.__metadata.append(Metadata(name=entry['name'], value=entry['value']))
                    else:
                        pass  # Object in the list was not of Metadata or MetaDiv classes
                except MissingParameters as e:
                    handler(
                        type(self).__name__,
                        'Metadata {} is missing parameters: {}. Skipping.'.format(entry, e)
                    )
        except KeyError as e:
            handler(type(self).__name__, 'Metadata {} is missing parameters: '
                                         '{}. Unable to load.'
                    .format(entry, e))

    @property
    def showSubtechniques(self):
        if self.__showSubtechniques != UNSETVALUE:
            return self.__showSubtechniques

    @showSubtechniques.setter
    def showSubtechniques(self, showSubtechniques):
        typeChecker(type(self).__name__, showSubtechniques, bool,
                    "showSubtechniques")
        self.__showSubtechniques = showSubtechniques

    @property
    def aggregateScore(self):
        if self.__aggregateScore != UNSETVALUE:
            return self.__aggregateScore

    @aggregateScore.setter
    def aggregateScore(self, aggregateScore):
        typeChecker(type(self).__name__, aggregateScore, int, "aggregate")
        self.__aggregateScore = aggregateScore

    @property
    def links(self):
        if self.__links != UNSETVALUE:
            return self.__links

    @links.setter
    def links(self, links):
        typeChecker(type(self).__name__, links, list, "links")
        if not handle_object_placement(self.__links, links, Link):
            self.__links = []
        entry = ""
        try:
            for entry in links:
                if isinstance(entry, Link):
                    loadChecker(type(self).__name__, entry.get_dict(), ['label', 'url'], "link")
                    self.__links.append(entry)
                elif isinstance(entry, LinkDiv):
                    loadChecker(type(self).__name__, entry.get_dict(), ['name', 'value'], "linkdiv")
                    self.__links.append(entry)
                elif isinstance(entry, dict):
                    if 'name' in entry and entry['name'] == "DIVIDER":
                        loadChecker(type(self).__name__, entry, ['name', 'value'], "linkdiv")
                        self.__links.append(LinkDiv(active=entry['value']))
                    else:
                        loadChecker(type(self).__name__, entry, ['label', 'url'], "link")
                        self.__links.append(Link(label=entry['label'], url=entry['url']))
                else:
                    pass
        except KeyError as e:
            handler(type(self).__name__, 'Link {} is missing parameters: '
                                         '{}. Unable to load.'
                    .format(entry, e))

    def _loader(self, data):
        """
            INTERNAL: Acts a middleman for loading values into the technique
                object from a dict representation
            :param data: A dict describing the technique
            :raises UnknownTechniqueProperty: An error indicating that an
                unexpected property was found on the technique
        """
        for entry in data.keys():
            if entry == 'techniqueID':
                pass
            elif entry == 'tactic':
                self.tactic = data[entry]
            elif entry == 'comment':
                self.comment = data[entry]
            elif entry == 'enabled':
                self.enabled = data[entry]
            elif entry == 'score':
                self.score = data[entry]
            elif entry == 'color':
                self.color = data[entry]
            elif entry == 'metadata':
                self.metadata = data[entry]
            elif entry == 'showSubtechniques':
                self.showSubtechniques = data[entry]
            elif entry == 'links':
                self.links = data[entry]
            elif entry == 'aggregateScore':
                self.aggregateScore = data[entry]
            else:
                handler(type(self).__name__, "Unknown technique property: {}"
                        .format(entry))
                raise UnknownTechniqueProperty

    def get_dict(self):
        """
            Converts the currently loaded data into a dict
            :returns: A dict representation of the local technique object
        """
        dset = vars(self)
        temp = {}
        for key in dset:
            entry = key.split(type(self).__name__ + '__')[-1]
            if dset[key] != UNSETVALUE:
                if entry != 'metadata' and entry != 'links':
                    temp[entry] = dset[key]
                else:
                    temp[entry] = [x.get_dict() for x in dset[key]]
        return temp
