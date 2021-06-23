from stix2 import Filter
from itertools import chain
from enum import Enum

try:
    from ..exporters.matrix_gen import MatrixGen
    from ..core.exceptions import BadInput, typeChecker, categoryChecker
    from ..core.layer import Layer
    from ..generators.gen_helpers import remove_revoked, get_attack_id
except ValueError:
    from mitreattack.navlayers.exporters.matrix_gen import MatrixGen
    from mitreattack.navlayers.core.exceptions import BadInput, typeChecker, categoryChecker
    from mitreattack.navlayers.core.layer import Layer
    from mitreattack.navlayers.generators.gen_helpers import remove_revoked, get_attack_id
except ImportError:
    from navlayers.exporters.matrix_gen import MatrixGen
    from navlayers.core.exceptions import BadInput, typeChecker, categoryChecker
    from navlayers.core.layer import Layer
    from navlayers.generators.gen_helpers import remove_revoked, get_attack_id


class UnableToFindStixObject(Exception):
    pass

class StixType(Enum):
    GROUP = 1
    SOFTWARE = 2
    MITIGATION = 3


class UsageGenerator:
    """Generates a Usage file that provides an overview of all techniques utilized by an entity"""
    def __init__(self, source, matrix='enterprise', local=None):
        """
        Initialize the Generator
        :param source: Which source to use for data (local or taxii [server])
        :param matrix: Which matrix to use during generation
        :param local: Optional path to local data
        """
        self.matrix_handle = MatrixGen(source, local)
        self.domain = matrix
        try:
            self.source_handle = self.matrix_handle.collections[matrix]
        except KeyError:
            print(f"[UsageGenerator] - unable to load collection {matrix} (current source = {source}).")
            raise BadInput

    def get_stix_object(self, match):
        """
        Retrieve the stix object for a given string
        :param match: The string to match on - can be a name, alias, or ATT&CK ID
        :return: the corresponding stix object
        """
        filts = [
            [Filter('name', '=', match)],
            [Filter(match, 'in', 'aliases')],
            [Filter(match, 'in', 'x_mitre_aliases')],
            [Filter('external_references.external_id', '=', match)],
        ]
        data = list(chain.from_iterable(self.source_handle.query(f) for f in filts))
        data = remove_revoked(data)
        if len(data) == 1:
            return data[0]
        raise UnableToFindStixObject

    def get_matrix_data(self, match_pattern):
        """
        Retrieve a list of matching attack-pattern (technique) objects for a match_pattern (group, software, mitigation)
        :param match_pattern: the pattern to match
        :return: list of associated attack-pattern objects
        """
        out = []
        obj = self.get_stix_object(match_pattern)
        if obj.type == 'group':
            related = self.source_handle.relationships(obj, 'uses', source_only=True)
            out = self.source_handle.query([Filter('type', '=', 'attack-pattern'),
                                            Filter('id', 'in', [r.target_ref for r in related])])
        elif obj.type == 'software' or obj.type == 'tool':
            software_uses = self.source_handle.query([
                Filter('type', '=', 'relationship'),
                Filter('relationship_type', '=', 'uses'),
                Filter('source_ref', '=', obj.id)
            ])

            # get the techniques themselves from the ids
            out = self.source_handle.query([
                Filter('type', '=', 'attack-pattern'),
                Filter('id', 'in', [r.target_ref for r in software_uses])
            ])
        elif obj.type == "mitigation":
            relations = self.source_handle.relationships(obj.id, 'mitigates', source_only=True)
            out = self.source_handle.query([
                Filter('type', '=', 'attack-pattern'),
                Filter('id', 'in', [r.target_ref for r in relations])
            ])
        return remove_revoked(out), obj

    def generate_technique_data(self, raw_matches):
        """
        Generate technique list of dictionary objects (dictionary form of technique listing for a layer)
        :param raw_matches: matching attack-pattern objects
        :return: list of dictionary objects for every technique: score=0 if not in raw_matches, 1 otherwise,
                    description in comments
        """
        shortlist = []
        for match in raw_matches:
            xid = ''
            xphase = ''
            for ref in match.external_references:
                if ref.source_name == 'mitre-attack':
                    xid = ref.external_id
            for phase in match.kill_chain_phases:
                if phase.kill_chain_name == 'mitre-attack':
                    xphase = phase.phase_name
            shortlist.append((xid, xphase, match.description))
        full_matrix_listing = self.matrix_handle.get_matrix(self.domain)
        construct = list()
        for tactic in full_matrix_listing:
            for tech in tactic.techniques:
                construct.append(dict(techniqueID=tech.id, score=0,
                                      tactic=self.matrix_handle.convert(tactic.tactic.name)))
            for tech_key in tactic.subtechniques:
                for subtech in tactic.subtechniques[tech_key]:
                    construct.append(dict(techniqueID=subtech.id, score=0,
                                          tactic=self.matrix_handle.convert(tactic.tactic.name)))
        for entry in shortlist:
            for tac in construct:
                if entry[0] == tac['techniqueID'] and (entry[1] == '' or entry[1] == tac['tactic']):
                    tac['score'] = 1
                    tac['comment'] = entry[2]
        return construct

    def generate_layer(self, match):
        """
        Generate a layer
        :param match: the pattern to match
        :return: layer object with annotated techniques
        """
        typeChecker(type(self).__name__, match, str, "match")
        raw_data, matched_obj = self.get_matrix_data(match)
        a_id = get_attack_id(matched_obj)
        processed_listing = self.generate_technique_data(raw_data)
        raw_layer = dict(name=f"{matched_obj.name} ({matched_obj.id})", domain=self.domain + '-attack')
        raw_layer['techniques'] = processed_listing
        output_layer = Layer(raw_layer)
        if self.domain == 'enterprise':
            output_layer.description = f"Enterprise techniques used by {matched_obj.name}, " \
                                       f"ATT&CK {matched_obj.type} {a_id}"
        else:
            f"Mobile techniques used by {matched_obj.name}, ATT&CK {matched_obj.type} {a_id}"
        return output_layer
