from mitreattack.navlayers.core.filter import Filter
from mitreattack.navlayers.core.layout import Layout
from mitreattack.navlayers.core.technique import Technique
from mitreattack.navlayers.core.gradient import Gradient
from mitreattack.navlayers.core.legenditem import LegendItem
from mitreattack.navlayers.core.metadata import Metadata, MetaDiv
from mitreattack.navlayers.core.objlink import Link, LinkDiv
from mitreattack.navlayers.core.versions import Versions
from mitreattack.navlayers.core.exceptions import UNSETVALUE, typeChecker, handler, categoryChecker, \
     UnknownLayerProperty, loadChecker, MissingParameters
from mitreattack.navlayers.core.helpers import handle_object_placement


class _LayerObj:
    def __init__(self, name, domain):
        """
            Initialization - Creates a layer object

            :param name: The name for this layer
            :param domain: The domain for this layer (enterprise-attack
                or mobile-attack)
        """
        self.__versions = UNSETVALUE
        self.name = name
        self.__description = UNSETVALUE
        self.domain = domain
        self.__filters = UNSETVALUE
        self.__sorting = UNSETVALUE
        self.__layout = UNSETVALUE
        self.__hideDisabled = UNSETVALUE
        self.__techniques = UNSETVALUE
        self.__gradient = UNSETVALUE
        self.__legendItems = UNSETVALUE
        self.__showTacticRowBackground = UNSETVALUE
        self.__tacticRowBackground = UNSETVALUE
        self.__selectTechniquesAcrossTactics = UNSETVALUE
        self.__selectSubtechniquesWithParent = UNSETVALUE
        self.__metadata = UNSETVALUE
        self.__links = UNSETVALUE

    @property
    def version(self):
        if self.__versions != UNSETVALUE:
            return self.__versions.layer

    @version.setter
    def version(self, version):
        typeChecker(type(self).__name__, version, str, "version")
        categoryChecker(type(self).__name__, version, ["3.0", "4.0", "4.1", "4.2", "4.3"], "version")
        if self.__versions is UNSETVALUE:
            self.__versions = Versions()
        self.__versions.layer = version

    @property
    def versions(self):
        if self.__versions != UNSETVALUE:
            return self.__versions

    @versions.setter
    def versions(self, versions):
        ret = handle_object_placement(self.__versions, versions, Versions)
        if ret:
            self.__versions = ret
        else:
            typeChecker(type(self).__name__, versions, dict, "version")
            attack = UNSETVALUE
            if 'attack' in versions:
                attack = versions['attack']
            try:
                loadChecker(type(self).__name__, versions, ['layer', 'navigator'], "versions")
                self.__versions = Versions(versions['layer'], attack, versions['navigator'])
            except MissingParameters as e:
                handler(type(self).__name__, 'versions {} is missing parameters: '
                                             '{}. Skipping.'
                        .format(versions, e))

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, name):
        typeChecker(type(self).__name__, name, str, "name")
        self.__name = name

    @property
    def domain(self):
        return self.__domain

    @domain.setter
    def domain(self, domain):
        typeChecker(type(self).__name__, domain, str, "domain")
        dom = domain
        if dom.startswith('mitre'):
            dom = dom.split('-')[-1] + '-attack'
        categoryChecker(type(self).__name__, dom, ["enterprise-attack",
                                                   "mobile-attack",
                                                   "ics-attack"],
                        "domain")
        self.__domain = domain

    @property
    def description(self):
        if self.__description != UNSETVALUE:
            return self.__description

    @description.setter
    def description(self, description):
        typeChecker(type(self).__name__, description, str, "description")
        self.__description = description

    @property
    def filters(self):
        if self.__filters != UNSETVALUE:
            return self.__filters

    @filters.setter
    def filters(self, filters):
        ret = handle_object_placement(self.__filters, filters, Filter)
        if ret:
            self.__filters = ret
        else:
            temp = Filter(self.domain)
            try:
                loadChecker(type(self).__name__, filters, ['platforms'], "filters")
                # force upgrade to v4
                if 'stages' in filters:
                    print('[Filters] - V3 Field "stages" detected. Upgrading Filters object to V4.')
                temp.platforms = filters['platforms']
                self.__filters = temp
            except MissingParameters as e:
                handler(type(self).__name__, 'Filters {} is missing parameters: '
                                             '{}. Skipping.'
                        .format(filters, e))

    @property
    def sorting(self):
        if self.__sorting != UNSETVALUE:
            return self.__sorting

    @sorting.setter
    def sorting(self, sorting):
        typeChecker(type(self).__name__, sorting, int, "sorting")
        categoryChecker(type(self).__name__, sorting, [0, 1, 2, 3], "sorting")
        self.__sorting = sorting

    @property
    def layout(self):
        if self.__layout != UNSETVALUE:
            return self.__layout

    @layout.setter
    def layout(self, layout):
        ret = handle_object_placement(self.__layout, layout, Layout)
        if ret:
            self.__layout = ret
        else:
            temp = Layout()
            if "layout" in layout:
                temp.layout = layout['layout']
            if "showName" in layout:
                temp.showName = layout['showName']
            if "showID" in layout:
                temp.showID = layout['showID']
            if "showAggregateScores" in layout:
                temp.showAggregateScores = layout['showAggregateScores']
            if "countUnscored" in layout:
                temp.countUnscored = layout['countUnscored']
            if 'aggregateFunction' in layout:
                temp.aggregateFunction = layout['aggregateFunction']
            self.__layout = temp

    @property
    def hideDisabled(self):
        if self.__hideDisabled != UNSETVALUE:
            return self.__hideDisabled

    @hideDisabled.setter
    def hideDisabled(self, hideDisabled):
        typeChecker(type(self).__name__, hideDisabled, bool, "hideDisabled")
        self.__hideDisabled = hideDisabled

    @property
    def techniques(self):
        if self.__techniques != UNSETVALUE:
            return self.__techniques

    @techniques.setter
    def techniques(self, techniques):
        typeChecker(type(self).__name__, techniques, list, "techniques")
        self.__techniques = []

        for entry in techniques:
            ret = handle_object_placement(self.__techniques, entry, Technique, list=True)
            if ret:
                self.__techniques = ret
            else:
                try:
                    loadChecker(type(self).__name__, entry, ['techniqueID'], "technique")
                    temp = Technique(entry['techniqueID'])
                    temp._loader(entry)
                    self.__techniques.append(temp)
                except MissingParameters as e:
                    handler(type(self).__name__, 'Technique {} is missing parameters: '
                                                 '{}. Skipping.'
                            .format(entry, e))

    @property
    def gradient(self):
        if self.__gradient != UNSETVALUE:
            return self.__gradient

    @gradient.setter
    def gradient(self, gradient):
        ret = handle_object_placement(self.__gradient, gradient, Gradient)
        if ret:
            self.__gradient = ret
        else:
            try:
                loadChecker(type(self).__name__, gradient, ['colors', 'minValue', 'maxValue'], "gradient")
                self.__gradient = Gradient(gradient['colors'], gradient['minValue'], gradient['maxValue'])
            except MissingParameters as e:
                handler(type(self).__name__, 'Gradient {} is missing parameters: '
                                             '{}. Skipping.'
                        .format(gradient, e))

    @property
    def legendItems(self):
        if self.__legendItems != UNSETVALUE:
            return self.__legendItems

    @legendItems.setter
    def legendItems(self, legendItems):
        typeChecker(type(self).__name__, legendItems, list, "legendItems")
        self.__legendItems = []
        for entry in legendItems:
            ret = handle_object_placement(self.__legendItems, entry, LegendItem, list=True)
            if ret:
                self.__legendItems = ret
            else:
                try:
                    loadChecker(type(self).__name__, entry, ['label', 'color'], "legendItem")
                    temp = LegendItem(entry['label'], entry['color'])
                    self.__legendItems.append(temp)
                except MissingParameters as e:
                    handler(type(self).__name__, 'Legend Item {} is missing parameters: '
                                                 '{}. Skipping.'
                            .format(entry, e))

    @property
    def showTacticRowBackground(self):
        if self.__showTacticRowBackground != UNSETVALUE:
            return self.__showTacticRowBackground

    @showTacticRowBackground.setter
    def showTacticRowBackground(self, showTacticRowBackground):
        typeChecker(type(self).__name__, showTacticRowBackground, bool,
                    "showTacticRowBackground")
        self.__showTacticRowBackground = showTacticRowBackground

    @property
    def tacticRowBackground(self):
        if self.__tacticRowBackground != UNSETVALUE:
            return self.__tacticRowBackground

    @tacticRowBackground.setter
    def tacticRowBackground(self, tacticRowBackground):
        typeChecker(type(self).__name__, tacticRowBackground, str,
                    "tacticRowBackground")
        self.__tacticRowBackground = tacticRowBackground

    @property
    def selectTechniquesAcrossTactics(self):
        if self.__selectTechniquesAcrossTactics != UNSETVALUE:
            return self.__selectTechniquesAcrossTactics

    @selectTechniquesAcrossTactics.setter
    def selectTechniquesAcrossTactics(self, selectTechniquesAcrossTactics):
        typeChecker(type(self).__name__, selectTechniquesAcrossTactics, bool,
                    "selectTechniqueAcrossTactics")
        self.__selectTechniquesAcrossTactics = selectTechniquesAcrossTactics

    @property
    def selectSubtechniquesWithParent(self):
        if self.__selectSubtechniquesWithParent != UNSETVALUE:
            return self.__selectSubtechniquesWithParent

    @selectSubtechniquesWithParent.setter
    def selectSubtechniquesWithParent(self, selectSubtechniquesWithParent):
        typeChecker(type(self).__name__, selectSubtechniquesWithParent, bool,
                    "selectSubtechniquesWithParent")
        self.__selectSubtechniquesWithParent = selectSubtechniquesWithParent

    @property
    def metadata(self):
        if self.__metadata != UNSETVALUE:
            return self.__metadata

    @metadata.setter
    def metadata(self, metadata):
        typeChecker(type(self).__name__, metadata, list, "metadata")
        self.__metadata = []

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
                    pass  # Object in the list was not of Metadata or MetaDiv type
            except MissingParameters as e:
                handler(
                    type(self).__name__,
                    'Metadata {} is missing parameters: {}. Skipping.'.format(entry, e)
                )

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

    def _enumerate(self):
        """
            INTERNAL: Identifies which fields have been set for this Layer
                object
            :returns: a list of all set fields within this Layer object
        """
        temp = ['name', 'versions', 'domain']
        if self.description:
            temp.append('description')
        if self.filters:
            temp.append('filters')
        if self.sorting:
            temp.append('sorting')
        if self.layout:
            temp.append('layout')
        if self.hideDisabled:
            temp.append('hideDisabled')
        if self.techniques:
            temp.append('techniques')
        if self.gradient:
            temp.append('gradient')
        if self.legendItems:
            temp.append('legendItems')
        if self.showTacticRowBackground:
            temp.append('showTacticRowBackground')
        if self.tacticRowBackground:
            temp.append('tacticRowBackground')
        if self.selectTechniquesAcrossTactics:
            temp.append('selectTechniquesAcrossTactics')
        if self.selectSubtechniquesWithParent:
            temp.append('selectSubtechniquesWithParent')
        if self.metadata:
            temp.append('metadata')
        return temp

    def get_dict(self):
        """
            Converts the currently loaded layer into a dict
            :returns: A dict representation of the current layer object
        """
        temp = dict(name=self.name, domain=self.domain)

        if self.description:
            temp['description'] = self.description
        if self.versions:
            temp['versions'] = self.versions.get_dict()
        if self.filters:
            temp['filters'] = self.filters.get_dict()
        if self.sorting:
            temp['sorting'] = self.sorting
        if self.layout:
            temp['layout'] = self.layout.get_dict()
        if self.hideDisabled is not None:
            temp['hideDisabled'] = self.hideDisabled
        if self.techniques:
            temp['techniques'] = [x.get_dict() for x in self.techniques]
        if self.gradient:
            temp['gradient'] = self.gradient.get_dict()
        if self.legendItems:
            temp['legendItems'] = [x.get_dict() for x in self.legendItems]
        if self.showTacticRowBackground is not None:
            temp['showTacticRowBackground'] = self.showTacticRowBackground
        if self.tacticRowBackground:
            temp['tacticRowBackground'] = self.tacticRowBackground
        if self.selectTechniquesAcrossTactics is not None:
            temp['selectTechniquesAcrossTactics'] = \
                self.selectTechniquesAcrossTactics
        if self.selectSubtechniquesWithParent is not None:
            temp['selectSubtechniquesWithParent'] = \
                self.selectSubtechniquesWithParent
        if self.metadata:
            temp['metadata'] = [x.get_dict() for x in self.metadata]
        return temp

    def _linker(self, field, data):
        """
            INTERNAL: Acts as a middleman routing the settings of values
                within the layer
            :param field: The value field being set
            :param data: The corresponding data to set that field to
            :raises UnknownLayerProperty: An error indicating that an
                unexpected property was identified
        """
        if field == 'description':
            self.description = data
        elif field.startswith('version'):
            if not field.endswith('s'):
                # force upgrade
                print('[Version] - V3 version field detected. Upgrading to V4 Versions object.')
                ver_obj = dict(layer="4.0", navigator="4.0")
                self.versions = ver_obj
            else:
                self.versions = data
        elif field == 'filters':
            self.filters = data
        elif field == 'sorting':
            self.sorting = data
        elif field == 'layout':
            self.layout = data
        elif field == 'hideDisabled':
            self.hideDisabled = data
        elif field == 'techniques':
            self.techniques = data
        elif field == 'gradient':
            self.gradient = data
        elif field == 'legendItems':
            self.legendItems = data
        elif field == 'showTacticRowBackground':
            self.showTacticRowBackground = data
        elif field == 'tacticRowBackground':
            self.tacticRowBackground = data
        elif field == 'selectTechniquesAcrossTactics':
            self.selectTechniquesAcrossTactics = data
        elif field == 'selectSubtechniquesWithParent':
            self.selectSubtechniquesWithParent = data
        elif field == 'metadata':
            self.metadata = data
        elif field == 'links':
            self.links = data
        else:
            handler(type(self).__name__, "Unknown layer property: {}"
                    .format(field))
            raise UnknownLayerProperty
