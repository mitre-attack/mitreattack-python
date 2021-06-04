from stix2 import Filter
from itertools import chain
try:
    from ..exporters.matrix_gen import MatrixGen
    from ..core.exceptions import BadInput, typeChecker, categoryChecker
    from ..core.layer import Layer
except ValueError:
    from mitreattack.navlayers.exporters.matrix_gen import MatrixGen
    from mitreattack.navlayers.core.exceptions import BadInput, typeChecker, categoryChecker
    from mitreattack.navlayers.core.layer import Layer
except ImportError:
    from navlayers.exporters.matrix_gen import MatrixGen
    from navlayers.core.exceptions import BadInput, typeChecker, categoryChecker
    from navlayers.core.layer import Layer


class UnableToFindTechnique(Exception):
    pass


class OverviewGenerator:

    def __init__(self, source, matrix='enterprise', local=None):
        self.matrix_handle = MatrixGen(source, local)
        self.domain = matrix
        try:
            self.source_handle = self.matrix_handle.collections[matrix]
        except KeyError:
            print(f"[UsageGenerator] - unable to load collection {matrix} (current source = {source}).")
            raise BadInput
        self.tech_listing = self.remove_revoked(self.source_handle.query([Filter('type', '=', 'attack-pattern')]))
        self.group_objects = self.source_handle.query([Filter('type', '=', 'course-of-action')])
        complete_relationships = self.source_handle.query([Filter('type', '=', 'relationship'),
                                                           Filter('relationship_type', '=', 'uses')])
        complete_relationships.extend(self.source_handle.query([Filter('type', '=', 'relationship'),
                                                                Filter('relationship_type', '=', 'mitigates')]))
        self.mitigation_relationships = {}
        self.software_relationships = {}
        self.group_relationships = {}

        for entry in complete_relationships:
            if entry['target_ref'].startswith('attack-pattern--'):
                if entry['source_ref'].startswith('course-of-action--'):
                    if entry['target_ref'] not in self.mitigation_relationships:
                        self.mitigation_relationships[entry['target_ref']] = []
                    self.mitigation_relationships[entry['target_ref']].append(entry)
                elif entry['source_ref'].startswith('tool--') or entry['source_ref'].startswith('malware--'):
                    if entry['target_ref'] not in self.software_relationships:
                        self.software_relationships[entry['target_ref']] = []
                    self.software_relationships[entry['target_ref']].append(entry)
                elif entry['source_ref'].startswith('intrusion-set--'):
                    if entry['target_ref'] not in self.group_relationships:
                        self.group_relationships[entry['target_ref']] = []
                    self.group_relationships[entry['target_ref']].append(entry)


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

    def get_groups(self, relationships):
        list_of_groups = []
        for relationship in relationships:
            if relationship.source_ref.startswith('intrusion-set--'):
                list_of_groups.append(relationship)
        group_objects = self.source_handle.query([Filter('type', '=', 'intrusion-set'),
                                                  Filter('id', 'in', [r.source_ref for r in list_of_groups])])
        names = [x.name for x in group_objects]
        return len(names), names

    def get_softwares(self, relationships):
        list_of_softwares = []
        for relationship in relationships:
            if relationship.source_ref.startswith('malware--') or relationship.source_ref.startswith('tool--'):
                list_of_softwares.append(relationship.source_ref)
        software_listing = self.source_handle.query([Filter('type', '=', 'malware'), Filter('type', '=', 'tool')])
        software_objects = []
        for soft in software_listing:
            if soft.id in list_of_softwares:
                software_objects.append(soft)
        names = [x.name for x in software_objects]
        return len(names), names

    def get_mitigations(self, relationships):
        names = [x.name for x in self.group_objects if x.id in relationships]
        return len(names), names

    def get_matrix_template(self):
        construct = list()
        full_matrix_listing = self.matrix_handle.get_matrix(self.domain)
        for tactic in full_matrix_listing:
            for tech in tactic.techniques:
                construct.append(dict(techniqueID=tech.id, score=0,
                                      tactic=self.matrix_handle.convert(tactic.tactic.name)))
            for tech_key in tactic.subtechniques:
                for subtech in tactic.subtechniques[tech_key]:
                    construct.append(dict(techniqueID=subtech.id, score=0,
                                          tactic=self.matrix_handle.convert(tactic.tactic.name)))
        return construct

    def get_technique_obj(self, techniqueID, tactic=''):
        listing = self.tech_listing
        for match in listing:
            xid = False
            xphase = False
            for ref in match.external_references:
                if ref.source_name == 'mitre-attack' and ref.external_id == techniqueID:
                    xid = True
            for phase in match.kill_chain_phases:
                if phase.kill_chain_name == 'mitre-attack' and phase.phase_name == tactic:
                    xphase = True
            if xid and (xphase or tactic == ''):
                return match
        raise UnableToFindTechnique

    def update_template(self, obj_type, complete_tech_listing):
        temp = complete_tech_listing
        for entry in temp:
            tech = self.get_technique_obj(entry['techniqueID'], entry['tactic'])
            score = 0
            listing = []
            if obj_type == 'group':
                try:
                    related = self.group_relationships[tech.id]
                    score, listing = self.get_groups(related)
                except KeyError:
                    pass
            elif obj_type == 'software':
                try:
                    related = self.software_relationships[tech.id]
                    score, listing = self.get_softwares(related)
                except KeyError:
                    pass
            elif obj_type == "mitigation":
                try:
                    related = self.mitigation_relationships[tech.id]
                    score, listing = self.get_mitigations(related)
                except KeyError:
                    pass # we don't have any matches for this one
            entry['score'] = score
            entry['comment'] = ', '.join(listing)
        return temp

    def generate_layer(self, obj_type):
        """
        Generate a layer
        :param obj_type: the type of object data to compute over (group, software, or mitigation)
        :return: layer object with annotated techniques
        """
        typeChecker(type(self).__name__, obj_type, str, "type")
        categoryChecker(type(self).__name__, obj_type, ["group", "software", "mitigation"], "type")
        initial_list = self.get_matrix_template()
        updated_list = self.update_template(obj_type, initial_list)
        raw_layer = dict(name=f"AutoGenerated Layer ({obj_type})", domain='enterprise-attack')
        raw_layer['techniques'] = updated_list
        output_layer = Layer(raw_layer)
        return output_layer
