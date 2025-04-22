"""Contains MatrixEntry, Tactic, and MatrixGen classes."""

import json

import requests
from loguru import logger
from stix2 import Filter, MemoryStore
from stix2.datastore.memory import _add

from mitreattack.constants import MITRE_ATTACK_ID_SOURCE_NAMES


class DomainNotLoadedError(Exception):
    """Custom exception used when an ATT&CK domain is not loaded properly."""

    pass


class MatrixEntry:
    """A Matrix Entry object."""

    def __init__(self, id=None, name=None, platforms=[]):
        if id is not None:
            self.id = id
        if name is not None:
            self.name = name
        self.__platforms = []
        self.platforms = platforms
        self.score = None

    @property
    def id(self):
        """Id getter."""
        if self.__id is not None:
            return self.__id

    @id.setter
    def id(self, new_id):
        """Id setter."""
        self.__id = new_id

    @property
    def name(self):
        """Name getter."""
        if self.__name is not None:
            return self.__name

    @name.setter
    def name(self, name):
        """Name setter."""
        self.__name = name

    @property
    def platforms(self):
        """Platforms getter."""
        if self.__platforms is not None:
            return self.__platforms

    @platforms.setter
    def platforms(self, platforms):
        """Platforms setter."""
        if isinstance(platforms, list):
            self.__platforms.extend(platforms)
        else:
            self.__platforms.append(platforms)

    @property
    def score(self):
        """Score getter."""
        if self.__score is not None:
            return self.__score

    @score.setter
    def score(self, score):
        """Score setter."""
        self.__score = score


class Tactic:
    """A Tactic object."""

    def __init__(self, tactic=None, techniques=None, subtechniques=None):
        if tactic is not None:
            self.tactic = tactic
        if techniques is not None:
            self.techniques = techniques
        if subtechniques is not None:
            self.subtechniques = subtechniques

    @property
    def tactic(self):
        """Tactic getter."""
        if self.__tactic is not None:
            return self.__tactic

    @tactic.setter
    def tactic(self, tactic):
        """Tactic setter."""
        self.__tactic = tactic

    @property
    def techniques(self):
        """Techniques getter."""
        if self.__techniques is not None:
            return self.__techniques

    @techniques.setter
    def techniques(self, techniques):
        """Techniques setter."""
        self.__techniques = techniques

    @property
    def subtechniques(self):
        """Subtechniques getter."""
        if self.__subtechniques is not None:
            return self.__subtechniques

    @subtechniques.setter
    def subtechniques(self, subtechniques):
        """Subtechniques setter."""
        self.__subtechniques = subtechniques


class MatrixGen:
    """A MatrixGen object."""

    def __init__(self, source="local", resource=None, domain="enterprise"):
        """Initialize - Creates a matrix generator object.

        :param source: Source to utilize (remote or local)
        :param resource: string path to local cache of stix data (local) or url of an ATT&CK Workbench (remote)
        """
        self.convert_data = {}
        self.collections = dict()
        if source.lower() not in ["local", "remote", "memorystore"]:
            logger.error(
                f"Unable to generate matrix, source {source} is not one of [remote | local | memorystore]"
            )
            raise ValueError

        if source.lower() == "local":
            if resource is not None:
                hd = MemoryStore()
                hd.load_from_file(resource)
                if "mobile" in resource.lower():
                    self.collections["mobile"] = hd
                elif "enterprise" in resource.lower():
                    self.collections["enterprise"] = hd
                elif "ics" in resource.lower():
                    self.collections["ics"] = hd
                else:
                    logger.error(f"invalid domain specified ({resource.lower()})")
                    raise ValueError
            else:
                logger.error("source=local specified, but path to local source not provided")
                raise ValueError

        elif source.lower() == "remote":
            if resource is not None:
                if ":" not in resource[6:]:
                    print('[MatrixGen] - "remote" source missing port; assuming ":3000"')
                    resource += ":3000"
                if not resource.startswith("http"):
                    resource = "http://" + resource
                for dataset in ["enterprise", "mobile", "ics"]:
                    hd = MemoryStore()
                    response = requests.get(
                        f"{resource}/api/stix-bundles?domain={dataset}-"
                        f"attack&includeRevoked=true&includeDeprecated=true"
                    )
                    response.raise_for_status()  # ensure we notice bad responses
                    _add(hd, json.loads(response.text), True, None)
                    self.collections[dataset] = hd
            else:
                print(
                    '[MatrixGen] - WARNING: "remote" selected without providing a "resource" url. The use of '
                    '"remote" requires the inclusion of a "resource" url to an ATT&CK Workbench instance. No matrix '
                    "will be generated..."
                )

        elif source.lower() == "memorystore":
            if resource is not None:
                if "mobile" in domain:
                    self.collections["mobile"] = resource
                elif "enterprise" in domain:
                    self.collections["enterprise"] = resource
                elif "ics" in domain:
                    self.collections["ics"] = resource
                else:
                    logger.error(f"invalid domain specified ({resource.lower()})")
                    raise ValueError
            else:
                logger.error("source=memorystore specified, but no data was provided!")
                raise ValueError

        self.matrix = {}
        self._build_matrix(domain=domain)

    @staticmethod
    def _remove_revoked_deprecated(content):
        """Remove any revoked or deprecated objects from queries made to the data source."""
        return list(
            filter(lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False, content)
        )

    def _search(self, domain, query):
        interum = self.collections[domain].query(query)
        return self._remove_revoked_deprecated(interum)

    def _get_tactic_listing(self, domain="enterprise"):
        """Retrieve tactics for the associated domain.

        :param domain: The domain to draw from
        """
        tactics = {}
        t_filt = []
        matrix = self._search(domain, [Filter("type", "=", "x-mitre-matrix")])
        for i in range(len(matrix)):
            tactics[matrix[i]["name"]] = []
            for tactic_id in matrix[i]["tactic_refs"]:
                tactics[matrix[i]["name"]].append(self._search(domain, ([Filter("id", "=", tactic_id)]))[0])
        for entry in tactics[matrix[0]["name"]]:
            self.convert_data[entry["x_mitre_shortname"]] = entry["name"]
            self.convert_data[entry["name"]] = entry["x_mitre_shortname"]
            t_filt.append(MatrixEntry(id=entry["external_references"][0]["external_id"], name=entry["name"]))
        return t_filt

    def _get_technique_listing(self, tactic, domain="enterprise"):
        """Retrieve techniques for a given tactic and domain.

        :param tactic: The tactic to grab techniques from
        :param domain: The domain to draw from
        """
        techniques = []
        subtechs = {}
        techs = self._search(
            domain, [Filter("type", "=", "attack-pattern"), Filter("kill_chain_phases.phase_name", "=", tactic)]
        )
        for entry in techs:
            if entry["kill_chain_phases"][0]["kill_chain_name"] in MITRE_ATTACK_ID_SOURCE_NAMES:
                tid = [t["external_id"] for t in entry["external_references"][:1] if t["source_name"] == "mitre-attack"]
                platform_tags = []
                if "x_mitre_platforms" in entry:
                    platform_tags = entry["x_mitre_platforms"]
                if "." not in tid[0]:
                    techniques.append(MatrixEntry(id=tid[0], name=entry["name"], platforms=platform_tags))
                else:
                    parent = tid[0].split(".")[0]
                    if parent not in subtechs:
                        subtechs[parent] = []
                    subtechs[parent].append(MatrixEntry(id=tid[0], name=entry["name"], platforms=platform_tags))
        return techniques, subtechs

    def _adjust_ordering(self, codex, mode, scores=[]):
        """Adjust ordering of matrix based on sort mode.

        :param codex: The pre-existing matrix data
        :param mode: The sort mode to use
        :param scores: Any relevant scores to use in modes 2, 3
        """
        if mode == 0:
            return codex
        if mode == 1:
            for colm in codex:
                colm.technique.reverse()
                for sub in colm.subtechniques:
                    colm.subtechniques[sub].reverse()
            return codex
        for colm in codex:
            for st in colm.subtechniques:
                for sub in colm.subtechniques[st]:
                    sub.score = 0
                    for entry in scores:
                        if entry[0] == sub.id and (entry[1] is False or entry[1] == self.convert(colm.tactic.name)):
                            sub.score = entry[2]
                            break
            for tech in colm.techniques:
                tech.score = 0
                for entry in scores:
                    if entry[0] == tech.id and (entry[1] is False or entry[1] == self.convert(colm.tactic.name)):
                        tech.score = entry[2]
                        break
        if mode == 2:
            for colm in codex:
                for tsub in colm.subtechniques:
                    colm.subtechniques[tsub].sort(key=lambda x: x.score)
                colm.techniques.sort(key=lambda x: x.score)
        if mode == 3:
            for colm in codex:
                for tsub in colm.subtechniques:
                    colm.subtechniques[tsub].sort(key=lambda x: x.score, reverse=True)
                colm.techniques.sort(key=lambda x: x.score, reverse=True)
        return codex

    def _construct_panop(self, codex, subtechs, excludes):
        """Create a list of lists template for the matrix layout.

        :param codex: A list of lists matrix (output of .get_matrix())
        :param subtechs: A list of subtechniques that will be visible
        :param excludes: A list of techniques that will be excluded
        """
        st = [x[0] for x in subtechs]
        s_tacs = [x[1] for x in subtechs]
        et = [x[0] for x in excludes]
        e_tacs = [x[1] for x in excludes]

        matrix_obj = {}
        column = 0
        cycle = False
        to_add = []
        stechs = []
        joins = []
        for col in codex:
            # each column of the matrix
            column += 1
            if cycle:
                for entry in to_add:
                    sr = entry[0]
                    joins.append([entry[0], column - 1, len(stechs[entry[1]])])
                    for element in stechs[entry[1]]:
                        matrix_obj[(sr, column)] = element.name
                        sr += 1
                cycle = False
                column += 1
            row = 2
            matrix_obj[(1, column)] = col.tactic.name
            c_name = col.tactic.name
            stechs = col.subtechniques
            to_add = []
            for element in col.techniques:
                elname = element.name
                tid = element.id
                skip = False
                for entry in range(0, len(et)):
                    if et[entry] == tid and (e_tacs[entry] is False or self.convert(e_tacs[entry]) == c_name):
                        skip = True
                        break
                if not skip:
                    matrix_obj[(row, column)] = elname
                    sat = False
                    for entry in range(0, len(st)):
                        if st[entry] == tid and (s_tacs[entry] is False or self.convert(s_tacs[entry]) == c_name):
                            # this tech has enabled subtechs
                            to_add.append((row, tid))
                            row += len(stechs[tid])
                            cycle = True
                            sat = True
                            break
                    if not sat:
                        row += 1
        return matrix_obj, joins

    def _get_ID(self, codex, name):
        """Do lookups to retrieve the ID of a technique given it's name.

        :param codex: The list of lists matrix object (output of get_matrix)
        :param name: The name of the technique to retrieve the ID of
        :return: The ID of the technique referenced by name
        """
        for col in codex:
            if col.tactic.name == name:
                return col.tactic.id
            for entry in col.subtechniques:
                for subtech in col.subtechniques[entry]:
                    if subtech.name == name:
                        return subtech.id
            for entry in col.techniques:
                if entry.name == name:
                    return entry.id
        return ""

    def _get_name(self, codex, id):
        """Do lookups to retrieve the name of a technique given it's ID.

        :param codex: The list of lists matrix object (output of get_matrix)
        :param id: The ID of the technique to retrieve the name of
        :return: The name of the technique referenced by id
        """
        for col in codex:
            if col.tactic.id == id:
                return col.tactic.name
            for entry in col.subtechniques:
                for subtech in col.subtechniques[entry]:
                    if subtech.id == id:
                        return subtech.name
            for entry in col.techniques:
                if entry.id == id:
                    return entry.name
        return ""

    def convert(self, input_str):
        """Convert tactic names to and from short names.

        :param input_str: A tactic normal or short name
        :return: The tactic's short or normal name
        """
        if self.convert_data == {}:
            return None
        if input_str in self.convert_data:
            return self.convert_data[input_str]

    def _build_matrix(self, domain="enterprise"):
        """Build a ATT&CK matrix object, as a list of lists containing technique dictionaries.

        :param domain: The domain to build a matrix for
        """
        if domain not in self.collections:
            raise DomainNotLoadedError
        self.matrix[domain] = []
        tacs = self._get_tactic_listing(domain)
        for tac in tacs:
            techs, subtechs = self._get_technique_listing(tac.name.lower().replace(" ", "-"), domain)
            stemp = {}
            # sort subtechniques via id, append to column
            for par in subtechs:
                subtechs[par].sort(key=lambda x: x.name)
                stemp[par] = subtechs[par]
            # sort techniques alphabetically, append to column
            techs.sort(key=lambda x: x.name)
            colm = Tactic(tactic=tac, techniques=techs, subtechniques=stemp)
            self.matrix[domain].append(colm)

    def get_matrix(self, domain="enterprise", filters=None):
        """Retrieve an ATT&CK Domain object.

        :param domain: The domain to build a matrix for
        :param filters: Any platform filters to apply to the matrix
        """
        if domain not in self.matrix:
            self._build_matrix(domain)
        return self._filter_matrix_platforms(self.matrix[domain], filters)

    @staticmethod
    def _filter_matrix_platforms(matrix, filters):
        """Filter a matrix according to its platforms.

        :param matrix: the matrix to refine
        :param filters: a list of platforms to filter
        :return: filtered matrix
        """
        if filters:
            filter_platforms = [x.lower() for x in filters.platforms]
            new_matrix = []
            for tac in matrix:
                ntech_list = []
                nsubtech_list = {}
                for tech in tac.techniques:
                    if any(x.lower() in filter_platforms for x in tech.platforms):
                        ntech_list.append(tech)
                for tech_subs in tac.subtechniques:
                    temp_list = []
                    for subtech in tac.subtechniques[tech_subs]:
                        if any(x.lower() in filter_platforms for x in subtech.platforms):
                            temp_list.append(subtech)
                    if temp_list:
                        nsubtech_list[tech_subs] = temp_list
                if ntech_list:
                    ntac = Tactic(tactic=tac.tactic, techniques=ntech_list, subtechniques=nsubtech_list)
                    new_matrix.append(ntac)
            if new_matrix:
                return new_matrix
            else:
                print(
                    "[WARNING] - Unable to produced filtered matrix... nothing would be left under these platform"
                    " restrictions."
                )
                return matrix
        else:
            return matrix
