"""Contains OverviewLayerGenerator class."""

from stix2 import Filter

from mitreattack.constants import MITRE_ATTACK_DOMAIN_STRINGS
from mitreattack.navlayers.exporters.matrix_gen import MatrixGen
from mitreattack.navlayers.core.exceptions import BadInput, typeChecker, categoryChecker
from mitreattack.navlayers.core.layer import Layer
from mitreattack.navlayers.generators.gen_helpers import (
    remove_revoked_depreciated,
    construct_relationship_mapping,
    build_data_strings,
)


class UnableToFindTechnique(Exception):
    """Custom exception used when unable to find techniques."""

    pass


class OverviewLayerGenerator:
    """Generates a Layer file that provides an overview of entities related to each technique."""

    def __init__(self, source, domain="enterprise", resource=None):
        """Initialize the Generator.

        :param source: Which source to use for data (local file or [remote] ATT&CK Workbench)
        :param domain: Which domain to use during generation
        :param resource: string path to local cache of stix data (local) or url of Workbench to connect to (remote)
        """
        self.matrix_handle = MatrixGen(source=source, resource=resource, domain=domain)
        self.domain = domain
        try:
            self.source_handle = self.matrix_handle.collections[domain]
        except KeyError:
            print(f"[UsageGenerator] - unable to load collection {domain} (current source = {source}).")
            raise BadInput
        tl = remove_revoked_depreciated(self.source_handle.query([Filter("type", "=", "attack-pattern")]))
        self.mitigation_objects = self.source_handle.query([Filter("type", "=", "course-of-action")])
        complete_relationships = self.source_handle.query(
            [Filter("type", "=", "relationship"), Filter("relationship_type", "=", "uses")]
        )
        complete_relationships.extend(
            self.source_handle.query(
                [Filter("type", "=", "relationship"), Filter("relationship_type", "=", "mitigates")]
            )
        )
        complete_relationships.extend(
            self.source_handle.query([Filter("type", "=", "relationship"), Filter("relationship_type", "=", "detects")])
        )

        self.sources = self.source_handle.query([Filter("type", "=", "x-mitre-data-source")])
        self.components = self.source_handle.query([Filter("type", "=", "x-mitre-data-component")])
        self.campaigns = self.source_handle.query([Filter("type", "=", "campaign")])
        self.assets = self.source_handle.query([Filter("type", "=", "x-mitre-asset")])
        self.source_mapping = build_data_strings(self.sources, self.components)
        # Contains relationship mapping [stix id] -> [relationships associated with that stix id for each type]
        self.simplifier = {
            "course-of-action": dict(),
            "tool": dict(),
            "malware": dict(),
            "intrusion-set": dict(),
            "x-mitre-data-component": dict(),
            "campaign": dict(),
            "asset": dict(),
        }

        # Scan through all relationships to identify ones that target attack techniques (attack-pattern). Then, sort
        # these into the mapping dictionary by what kind of stix object they are (tool, course-of-action, etc.)
        for entry in complete_relationships:
            if entry["target_ref"].startswith("attack-pattern--"):
                construct_relationship_mapping(self.simplifier[entry["source_ref"].split("--")[0]], entry)
        self.simplifier["software"] = self.simplifier["malware"]
        self.simplifier["software"].update(self.simplifier["tool"])  # get combination of malware/tool
        self.simplifier["datasource"] = self.simplifier["x-mitre-data-component"]

        self.tech_listing = dict()
        self.tech_no_tactic_listing = dict()
        for entry in tl:
            tacs = [None]
            xid = None
            for ref in entry.external_references:
                if ref.source_name in MITRE_ATTACK_DOMAIN_STRINGS:
                    xid = ref.external_id
                    break
            for phase in entry.kill_chain_phases:
                if phase.kill_chain_name in MITRE_ATTACK_DOMAIN_STRINGS:
                    tacs.append(phase.phase_name)
            for xphase in tacs:
                self.tech_listing[(xid, xphase)] = entry
            self.tech_no_tactic_listing[xid] = entry

    def get_groups(self, relationships):
        """Sort Groups out of relationships.

        :param relationships: List of all related relationships to a given technique
        :return: length of matched groups, list of group names
        """
        list_of_groups = []
        for relationship in relationships:
            if relationship.source_ref.startswith("intrusion-set--"):
                list_of_groups.append(relationship)
        group_objects = self.source_handle.query(
            [Filter("type", "=", "intrusion-set"), Filter("id", "in", [r.source_ref for r in list_of_groups])]
        )
        names = [x.name for x in group_objects]
        return len(names), names

    def get_software(self, relationships):
        """Sort software out of relationships.

        :param relationships: List of all related relationships to a given technique
        :return: length of matched software, list of software names
        """
        list_of_softwares = []
        for relationship in relationships:
            if relationship.source_ref.startswith("malware--") or relationship.source_ref.startswith("tool--"):
                list_of_softwares.append(relationship.source_ref)
        software_listing = self.source_handle.query([Filter("type", "=", "malware"), Filter("type", "=", "tool")])
        software_objects = []
        for soft in software_listing:
            if soft.id in list_of_softwares:
                software_objects.append(soft)
        names = [x.name for x in software_objects]
        return len(names), names

    def get_mitigations(self, relationships):
        """Sort mitigations out of relationships.

        :param relationships: List of all related relationships to a given technique
        :return: length of matched mitigations, list of mitigation names
        """
        names = [x.name for x in self.mitigation_objects if x.id in relationships]
        return len(names), names

    def get_datasources(self, relationships):
        """Sort datasources/datacomponents out of relationships.

        :param relationships: List of all related relationships to a given technique
        :return: length of matched datasources/datacomponents, list of associated names
        """
        names = [self.source_mapping[x.source_ref] for x in relationships]
        return len(names), names
    
    def get_campaigns(self, relationships):
        """Sort campaigns out of relationships.

        :param relationships: List of all related relationships to a given technique
        :return: length of matched campaigns, list of campaign names
        """
        names = [x.name for x in self.campaigns if x.id in relationships]
        return len(names), names

    def get_assets(self, relationships):
        """Sort assets out of relationships.

        :param relationships: List of all related relationships to a given technique
        :return: length of matched assets, list of asset names
        """
        names = [x.name for x in self.assets if x.id in relationships]
        return len(names), names

    def get_matrix_template(self):
        """Build the raw dictionary form matrix layer object.

        :return: dictionary representing all entries in the matrix layer
        """
        construct = list()
        full_matrix_listing = self.matrix_handle.get_matrix(self.domain)
        for tactic in full_matrix_listing:
            for tech in tactic.techniques:
                construct.append(
                    dict(techniqueID=tech.id, score=0, tactic=self.matrix_handle.convert(tactic.tactic.name))
                )
            for tech_key in tactic.subtechniques:
                for subtech in tactic.subtechniques[tech_key]:
                    construct.append(
                        dict(techniqueID=subtech.id, score=0, tactic=self.matrix_handle.convert(tactic.tactic.name))
                    )
        return construct

    def get_technique_obj(self, techniqueID, tactic):
        """Extract the matching technique object from the tech_listing.

        :param techniqueID: the technique object's id
        :param tactic: optional tactic for the technique object (shortname - ex. "reconnaissance")
        :return: the matching technique object (or a UnableToFindTechnique exception)
        """
        try:
            return self.tech_listing[(techniqueID, tactic)]
        except KeyError:
            pass  # didn't find a specific match for that combo, let's drop the tactic and see what we get
        try:
            return self.tech_no_tactic_listing[techniqueID]
        except KeyError:
            raise UnableToFindTechnique

    def update_template(self, obj_type, complete_tech_listing):
        """Update an existing dictionary of layer techniques with the appropriate matching objects.

        :param obj_type: the type of object to update the data with
        :param complete_tech_listing: 'clean' technique dictionary template
        :return: Updated technique dictionary
        """
        temp = complete_tech_listing
        for entry in temp:
            tech = self.get_technique_obj(entry["techniqueID"], entry["tactic"])
            score = 0
            listing = []
            if obj_type == "group":
                try:
                    related = self.simplifier["intrusion-set"][tech.id]
                    score, listing = self.get_groups(related)
                except KeyError:
                    pass
            elif obj_type == "software":
                try:
                    related = self.simplifier["software"][tech.id]
                    score, listing = self.get_software(related)
                except KeyError:
                    pass
            elif obj_type == "mitigation":
                try:
                    related = self.simplifier["course-of-action"][tech.id]
                    score, listing = self.get_mitigations(related)
                except KeyError:
                    pass  # we don't have any matches for this one
            elif obj_type == "datasource":
                try:
                    related = self.simplifier["datasource"][tech.id]
                    score, listing = self.get_datasources(related)
                except KeyError:
                    pass
            elif obj_type == "campaign":
                try:
                    related = self.simplifier["campaign"][tech.id]
                    score, listing = self.get_campaigns(related)
                except KeyError:
                    pass
            elif obj_type == "asset":
                try:
                    related = self.simplifier["asset"][tech.id]
                    score, listing = self.get_assets(related)
                except KeyError:
                    pass
            entry["score"] = score
            entry["comment"] = ", ".join(listing)
        return temp

    def generate_layer(self, obj_type):
        """Generate a layer.

        :param obj_type: the type of object data to compute over (group, software, or mitigation)
        :return: layer object with annotated techniques
        """
        typeChecker(type(self).__name__, obj_type, str, "type")
        categoryChecker(type(self).__name__, obj_type, ["group", "software", "mitigation", "datasource", "campaign", "asset"], "type")
        initial_list = self.get_matrix_template()
        updated_list = self.update_template(obj_type, initial_list)
        if obj_type == "group":
            p_name = "groups"
            r_type = "using"
        elif obj_type == "software":
            p_name = "software"
            r_type = "using"
        elif obj_type == "datasource":
            p_name = "data sources"
            r_type = "detecting"
        elif obj_type == "campaign":
            p_name = "campaigns"
            r_type = "using"
        elif obj_type == "asset":
            p_name = "assets"
            r_type = "targeted by"
        else:  # mitigation case
            p_name = "mitigations"
            r_type = "mitigating"
        desc = (
            f"Overview of techniques used by {p_name}. Score is the number of {p_name} "
            f"{r_type} the technique, and comment lists the {r_type} {p_name}"
        )
        raw_layer = dict(name=f"{p_name} overview", domain="enterprise-attack", description=desc)
        raw_layer["techniques"] = updated_list
        output_layer = Layer(raw_layer)
        return output_layer
