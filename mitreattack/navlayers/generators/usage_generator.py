from stix2 import Filter
from itertools import chain
try:
    from navlayers.exporters.matrix_gen import MatrixGen
    from navlayers.core.exceptions import BadInput, typeChecker, categoryChecker
    from navlayers.core.layer import Layer
except ImportError:
    from ..exporters.matrix_gen import MatrixGen
    from ..core.exceptions import BadInput, typeChecker, categoryChecker
    from ..core.layer import Layer


class UnableToFindGroup(Exception):
    pass


class UnableToFindSoftware(Exception):
    pass


class UnableToFindMitigation(Exception):
    pass


class UsageGenerator:

    def __init__(self, source, matrix='enterprise', local=None):
        self.matrix_handle = MatrixGen(source, local)
        self.domain = matrix
        try:
            self.source_handle = self.matrix_handle.collections[matrix]
        except KeyError:
            print(f"[UsageGenerator] - unable to load collection {matrix} (current source = {source}).")
            raise BadInput

    def remove_revoked(self, listing):
        """
        Remove revoked elements from the listing
        :param listing: input element list
        :return: input element list - revoked elements
        """
        removed = []
        for x in listing:
            if 'revoked' in x:
                if x['revoked']:
                    removed.append(x)
        return [a for a in listing if a not in removed]

    def get_group(self, match):
        """
        Retrieve group for a given match
        :param match: matching pattern
        :return: first matching group or UnableToFindGroup exception
        """
        a = []
        if match.startswith('G'):
            filts = [Filter('type', '=', 'intrusion-set')]
            temp = self.source_handle.query(filts)
            for b in temp:
                for c in b['external_references']:
                    if c['source_name'] == "mitre-attack" and c['external_id'] == match:
                        return a
        else:
            filts = [Filter('type', '=', 'intrusion-set'),
                     Filter('aliases', '=', match)]
            a = self.source_handle.query(filts)
        if len(a):
            return a[0]
        else:
            raise UnableToFindGroup

    def get_software(self, match):
        """
        Retrieve software for a given match
        :param match: matching pattern
        :return: first matching software or UnableToFindSoftware exception
        """
        filts = [
            [Filter('type', '=', 'malware')],
            [Filter('type', '=', 'tool')]
        ]
        all_software = list(chain.from_iterable(self.source_handle.query(f) for f in filts))
        for x in all_software:
            for y in x['external_references']:
                if y['source_name'] == 'mitre-attack' and y['external_id'] == match:
                    return x
            if match == x['name']:
                return x
            if 'aliases' in x:
                if match in x['aliases']:
                    return x
        raise UnableToFindSoftware

    def get_mitigation(self, match):
        """
        Retrieve mitigation for a given match
        :param match: matching pattern
        :return: first matching mitigation or UnableToFindMitigation exception
        """
        mitigation_list = self.source_handle.query([Filter('type', '=', 'course-of-action')])
        for x in mitigation_list:
            for y in x['external_references']:
                if y['source_name'] == 'mitre-attack' and y['external_id'] == match:
                    return x
            if match in x['name']:
                return x
        raise UnableToFindMitigation

    def get_matrix_data(self, match_pattern, obj_type):
        """
        Retrieve matching attack-pattern objects for match_pattern
        :param match_pattern: the pattern to match
        :param obj_type: the type of object match_pattern is
        :return: list of associated attack-pattern objects
        """
        out = []
        if obj_type == 'group':
            gr = self.get_group(match_pattern)
            related = self.source_handle.relationships(gr, 'uses', source_only=True)
            out = self.source_handle.query([Filter('type', '=', 'attack-pattern'),
                                            Filter('id', 'in', [r.target_ref for r in related])])
        elif obj_type == 'software':
            sr = self.get_software(match_pattern)
            software_uses = self.source_handle.query([
                Filter('type', '=', 'relationship'),
                Filter('relationship_type', '=', 'uses'),
                Filter('source_ref', '=', sr.id)
            ])

            # get the techniques themselves from the ids
            out = self.source_handle.query([
                Filter('type', '=', 'attack-pattern'),
                Filter('id', 'in', [r.target_ref for r in software_uses])
            ])
        elif obj_type == "mitigation":
            mr = self.get_mitigation(match_pattern)
            relations = self.source_handle.relationships(mr.id, 'mitigates', source_only=True)
            out = self.source_handle.query([
                Filter('type', '=', 'attack-pattern'),
                Filter('id', 'in', [r.target_ref for r in relations])
            ])
        return self.remove_revoked(out)

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

    def generate_layer(self, match, obj_type):
        """
        Generate a layer
        :param match: the pattern to match
        :param obj_type: the type of object match is (group, software, or mitigation)
        :return: layer object with annotated techniques
        """

        typeChecker(type(self).__name__, obj_type, str, "type")
        categoryChecker(type(self).__name__, obj_type, ["group", "software", "mitigation"], "type")
        typeChecker(type(self).__name__, match, str, "match")
        raw_data = self.get_matrix_data(match, obj_type)
        processed_listing = self.generate_technique_data(raw_data)
        raw_layer = dict(name=f"AutoGenerated Layer ({match})", domain='enterprise-attack')
        raw_layer['techniques'] = processed_listing
        output_layer = Layer(raw_layer)
        return output_layer


gamma = UsageGenerator('taxii')
generated = gamma.generate_layer('M1036', 'mitigation')
generated.to_file('gen_test.json')
