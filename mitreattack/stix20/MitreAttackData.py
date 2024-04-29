"""MitreAttackData Library."""

from itertools import chain

import stix2
from dateutil import parser
from stix2 import Filter
from stix2.utils import get_type_from_id

from mitreattack.stix20.custom_attack_objects import StixObjectFactory


class MitreAttackData:
    """MitreAttackData object."""

    stix_types = [
        "attack-pattern",
        "malware",
        "tool",
        "intrusion-set",
        "campaign",
        "course-of-action",
        "x-mitre-matrix",
        "x-mitre-tactic",
        "x-mitre-data-source",
        "x-mitre-data-component",
        "x-mitre-asset",
    ]

    # software:group
    all_software_used_by_all_groups = None
    all_groups_using_all_software = None
    # software:campaign
    all_software_used_by_all_campaigns = None
    all_campaigns_using_all_software = None
    # group:campaign
    all_groups_attributing_to_all_campaigns = None
    all_campaigns_attributed_to_all_groups = None
    # technique:group
    all_techniques_used_by_all_groups = None
    all_groups_using_all_techniques = None
    # technique:campaign
    all_techniques_used_by_all_campaigns = None
    all_campaigns_using_all_techniques = None
    # technique:software
    all_techniques_used_by_all_software = None
    all_software_using_all_techniques = None
    # technique:mitigation
    all_techniques_mitigated_by_all_mitigations = None
    all_mitigations_mitigating_all_techniques = None
    # technique:subtechnique
    all_parent_techniques_of_all_subtechniques = None
    all_subtechniques_of_all_techniques = None
    # technique:data-component
    all_techniques_detected_by_all_datacomponents = None
    all_datacomponents_detecting_all_techniques = None
    # technique:asset
    all_techniques_targeting_all_assets = None
    all_assets_targeted_by_all_techniques = None

    def __init__(self, stix_filepath: str = None, src: stix2.MemoryStore = None):
        """Initialize a MitreAttackData object.

        Parameters
        ----------
        stix_file : str, optional
            Filepath to a STIX 2.0 bundle. Mutually exclusive with `src`.
        src : stix2.MemoryStore, optional
            A STIX 2.0 bundle that has already been loaded into memory. Mutually exclusive with `stix_file`.
        """
        if not stix_filepath and not src:
            raise TypeError("MitreAttackData cannot be initialized without one of `stix_filepath` or `src`.")
        elif stix_filepath and src:
            raise TypeError("MitreAttackData cannot be initialized with both `stix_filepath` and `src`.")

        if stix_filepath and not isinstance(stix_filepath, str):
            raise TypeError(f"Argument stix_filepath must be of type str, not {type(stix_filepath)}")

        self.stix_filepath = None
        self.src = None

        if stix_filepath:
            self.stix_filepath = stix_filepath
            self.src = stix2.MemoryStore()
            self.src.load_from_file(stix_filepath)
        elif src:
            self.src = src

    ###################################
    # Utilities
    ###################################

    def print_stix_object(self, object: object, pretty=True):
        """Print a STIX object.

        Parameters
        ----------
        object : object
            the object to print
        pretty : bool, optional
            pretty print the object, by default True
        """
        print(object.serialize(pretty))

    ###################################
    # STIX Objects Section
    ###################################

    def remove_revoked_deprecated(self, stix_objects: list) -> list:
        """Remove revoked or deprecated objects from queries made to the data source.

        Parameters
        ----------
        stix_objects : list
            list of STIX objects from a query made to the data source

        Returns
        -------
        list
            list of STIX objects with revoked and deprecated objects filtered out
        """
        # Note we use .get() because the property may not be present in the JSON data. The default is False
        # if the property is not set.
        return list(
            filter(
                lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False, stix_objects
            )
        )

    def get_matrices(self, remove_revoked_deprecated=False) -> list:
        """Retrieve all matrix objects.

        Parameters
        ----------
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of Matrix objects
        """
        return self.get_objects_by_type("x-mitre-matrix", remove_revoked_deprecated)

    def get_tactics(self, remove_revoked_deprecated=False) -> list:
        """Retrieve all tactic objects.

        Parameters
        ----------
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of Tactic objects
        """
        return self.get_objects_by_type("x-mitre-tactic", remove_revoked_deprecated)

    def get_techniques(self, include_subtechniques=True, remove_revoked_deprecated=False) -> list:
        """Retrieve all technique objects.

        Parameters
        ----------
        include_subtechniques : bool, optional
            include sub-techniques in the result, by default True
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of AttackPattern objects
        """
        filters = [Filter("type", "=", "attack-pattern")]
        if not include_subtechniques:
            # filter out sub-techniques
            filters.append(Filter("x_mitre_is_subtechnique", "=", False))

        techniques = self.src.query(filters)

        if remove_revoked_deprecated:
            techniques = self.remove_revoked_deprecated(techniques)

        return techniques

    def get_subtechniques(self, remove_revoked_deprecated=False) -> list:
        """Retrieve all sub-technique objects.

        Parameters
        ----------
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of AttackPattern objects
        """
        subtechniques = self.src.query(
            [Filter("type", "=", "attack-pattern"), Filter("x_mitre_is_subtechnique", "=", True)]
        )

        if remove_revoked_deprecated:
            subtechniques = self.remove_revoked_deprecated(subtechniques)

        return subtechniques

    def get_mitigations(self, remove_revoked_deprecated=False) -> list:
        """Retrieve all mitigation objects.

        Parameters
        ----------
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of CourseOfAction objects
        """
        return self.get_objects_by_type("course-of-action", remove_revoked_deprecated)

    def get_groups(self, remove_revoked_deprecated=False) -> list:
        """Retrieve all group objects.

        Parameters
        ----------
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of IntrusionSet objects
        """
        return self.get_objects_by_type("intrusion-set", remove_revoked_deprecated)

    def get_software(self, remove_revoked_deprecated=False) -> list:
        """Retrieve all software objects.

        Parameters
        ----------
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of Tool and Malware objects
        """
        software = self.get_objects_by_type("tool", remove_revoked_deprecated)
        malware = self.get_objects_by_type("malware", remove_revoked_deprecated)
        software.extend(malware)
        return software

    def get_campaigns(self, remove_revoked_deprecated=False) -> list:
        """Retrieve all campaign objects.

        Parameters
        ----------
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of Campaign objects
        """
        return self.get_objects_by_type("campaign", remove_revoked_deprecated)

    def get_assets(self, remove_revoked_deprecated=False) -> list:
        """Retrieve all asset objects.

        Parameters
        ----------
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of Asset objects
        """
        return self.get_objects_by_type("x-mitre-asset", remove_revoked_deprecated)

    def get_datasources(self, remove_revoked_deprecated=False) -> list:
        """Retrieve all data source objects.

        Parameters
        ----------
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of DataSource objects
        """
        return self.get_objects_by_type("x-mitre-data-source", remove_revoked_deprecated)

    def get_datacomponents(self, remove_revoked_deprecated=False) -> list:
        """Retrieve all data component objects.

        Parameters
        ----------
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of DataComponent objects
        """
        return self.get_objects_by_type("x-mitre-data-component", remove_revoked_deprecated)

    ###################################
    # Get STIX Objects by Value
    ###################################

    def get_objects_by_type(self, stix_type: str, remove_revoked_deprecated=False) -> list:
        """Retrieve objects by STIX type.

        Parameters
        ----------
        stix_type : str
            the STIX type of the objects to retrieve
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of stix2.v20.sdo._DomainObject or CustomStixObject objects
        """
        objects = self.src.query([Filter("type", "=", stix_type)])

        if remove_revoked_deprecated:
            objects = self.remove_revoked_deprecated(objects)

        if not objects:
            return []

        # since ATT&CK has custom objects, we need to reconstruct the query results
        return [StixObjectFactory(o) for o in objects]

    def get_objects_by_content(self, content: str, object_type: str = None, remove_revoked_deprecated=False) -> list:
        """Retrieve objects by the content of their description.

        Parameters
        ----------
        content : str
            the content string to search for
        object_type : str, optional
            the STIX object type (must be 'attack-pattern', 'malware', 'tool', 'intrusion-set',
            'campaign', 'course-of-action', 'x-mitre-matrix', 'x-mitre-tactic',
            'x-mitre-data-source', 'x-mitre-data-component', 'x-mitre-asset', or 'relationship')
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of objects where the given content string appears in the description
        """
        if object_type and object_type not in self.stix_types and object_type != "relationship":
            # invalid object type
            raise ValueError(f"object_type must be one of {self.stix_types} or 'relationship'")

        filters = [Filter("type", "=", object_type)] if object_type else []
        objects = self.src.query(filters)

        matched_objects = []
        for obj in objects:
            if content.lower() in obj.get("description", "").lower():
                matched_objects.append(obj)

        if remove_revoked_deprecated:
            matched_objects = self.remove_revoked_deprecated(matched_objects)

        return matched_objects

    def get_techniques_by_platform(self, platform: str, remove_revoked_deprecated=False) -> list:
        """Retrieve techniques under a specific platform.

        Parameters
        ----------
        platform : str
            platform to search
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of AttackPattern objects under the given platform
        """
        filters = [Filter("type", "=", "attack-pattern"), Filter("x_mitre_platforms", "contains", platform)]
        techniques = self.src.query(filters)
        if remove_revoked_deprecated:
            techniques = self.remove_revoked_deprecated(techniques)
        return techniques

    def get_techniques_by_tactic(self, tactic_shortname: str, domain: str, remove_revoked_deprecated=False) -> list:
        """Retrieve techniques by tactic.

        Parameters
        ----------
        tactic_shortname : str
            the x_mitre_shortname of the tactic (e.g. 'defense-evasion')
        domain : str
            domain of the tactic (must be 'enterprise-attack', 'mobile-attack', or 'ics-attack')
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of AttackPattern objects under the given tactic
        """
        # validate domain input
        domain_to_kill_chain = {
            "enterprise-attack": "mitre-attack",
            "mobile-attack": "mitre-mobile-attack",
            "ics-attack": "mitre-ics-attack",
        }
        if domain not in domain_to_kill_chain.keys():
            raise ValueError(f"domain must be one of {domain_to_kill_chain.keys()}")

        # query techniques by tactic/domain; kill_chain_name differs by domain
        techniques = self.src.query(
            [
                Filter("type", "=", "attack-pattern"),
                Filter("kill_chain_phases.phase_name", "=", tactic_shortname),
                Filter("kill_chain_phases.kill_chain_name", "=", domain_to_kill_chain[domain]),
            ]
        )
        if remove_revoked_deprecated:
            techniques = self.remove_revoked_deprecated(techniques)
        return techniques

    def get_tactics_by_matrix(self) -> dict:
        """Retrieve the structured list of tactics within each matrix.

        The order of the tactics in the list matches the ordering of tactics in that matrix.

        Returns
        -------
        dict
            a mapping of tactics to matrices {matrix_name: [Tactics]}
        """
        tactics = {}
        matrices = self.src.query(
            [
                Filter("type", "=", "x-mitre-matrix"),
            ]
        )
        for i in range(len(matrices)):
            tactics[matrices[i]["name"]] = []
            for tactic_id in matrices[i]["tactic_refs"]:
                tactics[matrices[i]["name"]].append(self.src.get(tactic_id))

        return tactics

    def get_tactics_by_technique(self, stix_id) -> list:
        """Retrieve the list of tactics within a particular technique.

        Parameters
        ----------
        stix_id : str
            the stix id of the technique to be queried.

        Returns
        -------
        list
            a list of tactics that the technique to be queried contains.
        """
        technique = self.get_object_by_stix_id(stix_id)

        # get tactic shortnames from technique
        shortnames = []
        for phase in technique.get("kill_chain_phases"):
            shortnames.append(phase["phase_name"])

        # map shortnames to tactic objects
        all_tactics = self.get_tactics()
        technique_tactics = []
        for tactic in all_tactics:
            if tactic.get_shortname() in shortnames:
                technique_tactics.append(tactic)

        return technique_tactics
    
    def get_procedure_examples_by_technique(self, stix_id) -> list:
        """Retrieve the list of procedure examples by technique.

        Parameters
        ----------
        stix_id : str
            the stix id of the technique.

        Returns
        -------
        list
            a list of stix2.v20.Relationship objects describing the software, groups, and campaigns using the technique.
        """
        procedures = self.src.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "uses"),
                Filter("target_ref", "=", stix_id),
            ]
        )
        return procedures

    def get_objects_created_after(self, timestamp: str, remove_revoked_deprecated=False) -> list:
        """Retrieve objects which have been created after a given time.

        Parameters
        ----------
        timestamp : str
            timestamp to search (e.g. "2018-10-01T00:14:20.652Z")
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of stix2.v20.sdo._DomainObject or CustomStixObject objects created after the given time
        """
        objects = self.src.query([Filter("created", ">", timestamp)])
        if remove_revoked_deprecated:
            objects = self.remove_revoked_deprecated(objects)
        return objects

    def get_objects_modified_after(self, date: str, remove_revoked_deprecated=False) -> list:
        """Retrieve objects which have been modified after a given time.

        Parameters
        ----------
        date : str
            date to search (e.g. "2022-10-01", "2022-10-01T00:00:00.000Z", "October 1, 2022", etc.)
        remove_revoked_deprecated : bool, optional
            remove revoked or deprecated objects from the query, by default False

        Returns
        -------
        list
            a list of stix2.v20.sdo._DomainObject or CustomStixObject objects created after the given time
        """
        date_parser = parser.parse(date)
        date_parser = date_parser.strftime("%Y-%m-%dT%H:%M:%SZ")

        objects = self.src.query([Filter("modified", ">", date_parser)])

        if remove_revoked_deprecated:
            objects = self.remove_revoked_deprecated(objects)
        return objects

    def get_techniques_used_by_group_software(self, group_stix_id: str) -> list:
        """Get techniques used by a group's software.

        Because a group uses software, and software uses techniques, groups can be considered indirect users
        of techniques used by their software. These techniques are oftentimes distinct from the techniques
        used directly by a group, although there are occasionally intersections in these two sets of techniques.

        Parameters
        ----------
        group_stix_id : str
            the STIX ID of the group object

        Returns
        -------
        list
            a list of AttackPattern objects used by the group's software.
        """
        # get the malware, tools that the group uses
        group_uses = [
            r
            for r in self.src.relationships(group_stix_id, "uses", source_only=True)
            if get_type_from_id(r.target_ref) in ["malware", "tool"]
        ]

        # get the technique stix ids that the malware, tools use
        source_refs = [r.target_ref for r in group_uses]
        software_uses = self.src.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "uses"),
                Filter("source_ref", "in", source_refs),
            ]
        )

        # get the techniques themselves
        technique_ids = [r.target_ref for r in software_uses]
        return self.src.query([Filter("type", "=", "attack-pattern"), Filter("id", "in", technique_ids)])

    ###################################
    # Get STIX Object by Value
    ###################################

    def get_object_by_stix_id(self, stix_id: str) -> object:
        """Retrieve a single object by STIX ID.

        Parameters
        ----------
        stix_id : str
            the STIX ID of the object to retrieve

        Returns
        -------
        stix2.v20.sdo._DomainObject | CustomStixObject
            the STIX Domain Object specified by the STIX ID
        """
        sdo = self.src.get(stix_id)

        if not sdo:
            raise ValueError(f"{stix_id} not found")

        return StixObjectFactory(sdo)

    def get_object_by_attack_id(self, attack_id: str, stix_type: str) -> object:
        """Retrieve a single object by its ATT&CK ID.

        Note: in prior versions of ATT&CK, mitigations had 1:1 relationships with techniques and shared their
        technique's ID. Searching by ATT&CK ID alone does not work properly for techniques since
        technique ATT&CK IDs are not truly unique. The STIX type must be specified when searching by ATT&CK
        ID to avoid this issue.

        Parameters
        ----------
        attack_id : str
            the ATT&CK ID of the object to retrieve
        stix_type : str
            the object STIX type (must be 'attack-pattern', 'malware', 'tool', 'intrusion-set',
            'campaign', 'course-of-action', 'x-mitre-matrix', 'x-mitre-tactic',
            'x-mitre-data-source', 'x-mitre-data-component', or 'x-mitre-asset')

        Returns
        -------
        stix2.v20.sdo._DomainObject | CustomStixObject
            the STIX Domain Object specified by the ATT&CK ID
        """
        # validate type
        if stix_type not in self.stix_types:
            raise ValueError(f"stix_type must be one of {self.stix_types}")

        sdo = self.src.query(
            [
                Filter("external_references.external_id", "=", attack_id.upper()),
                Filter("type", "=", stix_type),
            ]
        )

        if not sdo:
            return None

        return StixObjectFactory(sdo[0])

    def get_objects_by_name(self, name: str, stix_type: str) -> list:
        """Retrieve objects by name.

        Note: the query by name is case sensitive.

        Parameters
        ----------
        name : str
            the name of the object to retrieve
        stix_type : str
            the STIX object type (must be 'attack-pattern', 'malware', 'tool', 'intrusion-set',
            'campaign', 'course-of-action', 'x-mitre-matrix', 'x-mitre-tactic',
            'x-mitre-data-source', 'x-mitre-data-component', or 'x-mitre-asset')

        Returns
        -------
        list
            a list of STIX Domain Objects specified by the name and type
        """
        # validate type
        if stix_type not in self.stix_types:
            raise ValueError(f"stix_type must be one of {self.stix_types}")

        filters = [Filter("type", "=", stix_type), Filter("name", "=", name)]
        objects = self.src.query(filters)

        if not objects:
            return []

        # since ATT&CK has custom objects, we need to reconstruct the query results
        return [StixObjectFactory(o) for o in objects]

    def get_groups_by_alias(self, alias: str) -> list:
        """Retrieve the groups corresponding to a given alias.

        Note: the query by alias is case sensitive.

        Parameters
        ----------
        alias : str
            the alias of the group

        Returns
        -------
        list
            a list of stix2.v20.sdo.IntrusionSet objects corresponding to the alias
        """
        filters = [Filter("type", "=", "intrusion-set"), Filter("aliases", "contains", alias)]
        return self.src.query(filters)

    def get_campaigns_by_alias(self, alias: str) -> list:
        """Retrieve the campaigns corresponding to a given alias.

        Note: the query by alias is case sensitive.

        Parameters
        ----------
        alias : str
            the alias of the campaign

        Returns
        -------
        list
            a list of stix2.v20.sdo.Campaign objects corresponding to the alias
        """
        filters = [Filter("type", "=", "campaign"), Filter("aliases", "contains", alias)]
        return self.src.query(filters)

    def get_software_by_alias(self, alias: str) -> list:
        """Retrieve the software corresponding to a given alias.

        Note: the query by alias is case sensitive.

        Parameters
        ----------
        alias : str
            the alias of the software

        Returns
        -------
        list
            a list of stix2.v20.sdo.Tool and stix2.v20.sdo.Malware objects corresponding to the alias
        """
        malware_filter = [Filter("type", "=", "malware"), Filter("x_mitre_aliases", "contains", alias)]
        tool_filter = [Filter("type", "=", "tool"), Filter("x_mitre_aliases", "contains", alias)]
        software = list(chain.from_iterable(self.src.query(f) for f in [malware_filter, tool_filter]))
        return software

    ###################################
    # Get Object Information
    ###################################

    def get_attack_id(self, stix_id: str) -> str | None:
        """Get the object's ATT&CK ID.

        Parameters
        ----------
        stix_id : str
            the STIX ID of the object

        Returns
        -------
        str
            the ATT&CK ID of the object
        """
        obj = self.get_object_by_stix_id(stix_id)
        external_references = obj.get("external_references")
        if external_references:
            attack_source = external_references[0]
            if attack_source.get("external_id") and attack_source.get("source_name") == "mitre-attack":
                return attack_source["external_id"]
        return None

    def get_stix_type(self, stix_id: str) -> str:
        """Get the object's STIX type.

        Parameters
        ----------
        stix_id : str
            the STIX ID of the object

        Returns
        -------
        str
            the STIX type of the object
        """
        return get_type_from_id(stix_id)

    def get_name(self, stix_id: str) -> str:
        """Get the object's name.

        Parameters
        ----------
        stix_id : str
            the STIX ID of the object

        Returns
        -------
        str
            the name of the object
        """
        obj = self.get_object_by_stix_id(stix_id)
        return obj.get("name") if obj.get("name") else None

    ###################################
    # Relationship Section
    ###################################

    def get_related(self, source_type: str, relationship_type: str, target_type: str, reverse: bool = False) -> dict:
        """Build relationship mappings.

        Parameters
        ----------
        source_type : str
            source type for the relationships, e.g. 'intrusion-set'
        relationship_type : str
            relationship type for the relationships, e.g. 'uses'
        target_type : str
            target type for the relationships, e.g. 'attack-pattern'
        reverse : bool, optional
            build reverse mapping of target to source, by default False

        Returns
        -------
        dict
            if reverse=False, relationship mapping of source_object_id => [{target_object, relationship[]}];
            if reverse=True, relationship mapping of target_object_id => [{source_object, relationship[]}]
        """
        relationships = self.src.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", relationship_type),
                Filter("revoked", "=", False),
            ]
        )
        relationships = self.remove_revoked_deprecated(relationships)

        # stix_id => [ { relationship, related_object_id } for each related object ]
        id_to_related = {}

        # build the dict
        for relationship in relationships:
            if source_type in relationship.source_ref and target_type in relationship.target_ref:
                if (relationship.source_ref in id_to_related and not reverse) or (
                    relationship.target_ref in id_to_related and reverse
                ):
                    # append to existing entry
                    if not reverse:
                        id_to_related[relationship.source_ref].append(
                            {"relationship": relationship, "id": relationship.target_ref}
                        )
                    else:
                        id_to_related[relationship.target_ref].append(
                            {"relationship": relationship, "id": relationship.source_ref}
                        )
                else:
                    # create a new entry
                    if not reverse:
                        id_to_related[relationship.source_ref] = [
                            {"relationship": relationship, "id": relationship.target_ref}
                        ]
                    else:
                        id_to_related[relationship.target_ref] = [
                            {"relationship": relationship, "id": relationship.source_ref}
                        ]

        # all objects of relevant type
        if not reverse:
            targets = self.src.query([Filter("type", "=", target_type)])
        else:
            targets = self.src.query([Filter("type", "=", source_type)])

        # remove revoked/deprecated objects
        targets = self.remove_revoked_deprecated(targets)

        # build lookup of stixID to stix object
        id_to_target = {}
        for target in targets:
            id_to_target[target["id"]] = target

        # build final output mappings
        output = {}
        for stix_id in id_to_related:
            value = []
            for related in id_to_related[stix_id]:
                if related["id"] not in id_to_target:
                    continue  # targeting a revoked object
                value.append(
                    {
                        "object": StixObjectFactory(id_to_target[related["id"]]),
                        "relationships": [related["relationship"]],
                    }
                )
            output[stix_id] = value
        return output

    def merge(self, map_a: dict, map_b: dict) -> dict:
        """Merge two relationship mappings resulting from `get_related()`.

        Parameters
        ----------
        map_a : dict
            the first relationship mapping
        map_b : dict
            the second relationship mapping

        Returns
        -------
        dict
            the merged relationship mapping
        """
        for id in map_b:
            if id in map_a:
                map_a[id].extend(map_b[id])
            else:
                map_a[id] = map_b[id]
        return map_a

    def add_inherited_campaign_relationships(
        self, related_campaigns, inherited_campaign_relationships, object_relationships
    ) -> dict:
        """Add inherited relationships to list of [{"object": object, "relationships": [relationship]}].

        Parameters
        ----------
        related_campaigns : dict
            campaigns related to the object: [object_stix_id => [ {campaign, [campaign_uses_object]} ]]
        inherited_campaign_relationships : dict
            relationships to be inherited from campaigns: [campaign_id => [ {related_object, [campaign_uses_related_object]} ]]
        object_relationships : dict
            direct relationships with the object itself: [object_stix_id => [ {related_object, [relationship]} ]]
        """
        for stix_id, campaigns in related_campaigns.items():
            for campaign in campaigns:
                if campaign["object"]["id"] not in inherited_campaign_relationships:
                    # no relationships inherited from campaign
                    continue

                # inheriting relationships from campaign
                for stix_object in inherited_campaign_relationships[campaign["object"]["id"]]:
                    # append inherited campaign relationship and campaign/group relationship
                    relationship = {
                        "object": stix_object["object"],
                        "relationships": stix_object["relationships"] + campaign["relationships"],
                    }

                    if stix_id not in object_relationships:
                        # add inherited relationship entry from attributed campaign
                        object_relationships[stix_id] = [relationship]
                        continue

                    # object exists, add inherited campaign relationships to existing list
                    object_relationships[stix_id].append(relationship)

        # remove duplicates
        object_relationships = self.remove_duplicates(object_relationships)
        return object_relationships

    def remove_duplicates(self, relationship_map) -> dict:
        """Remove duplicate objects in a list of [{"object": object, "relationships": [relationship]}]."""
        deduplicated_map = {}  # {stix_id => [{"object": object, "relationships": []}]}
        for stix_id, sdos in relationship_map.items():
            sdo_list = []
            seen_sdo_ids = []
            for sdo in sdos:
                if sdo["object"]["id"] not in seen_sdo_ids:
                    seen_sdo_ids.append(sdo["object"]["id"])
                    sdo_list.append(sdo)
                    continue

                # seen this object before, append relationships
                for index, item in enumerate(sdo_list):
                    if item["object"].id == sdo["object"].id:
                        sdo_list[index]["relationships"] = item["relationships"] + sdo["relationships"]
            deduplicated_map[stix_id] = sdo_list
        return deduplicated_map

    ###################################
    # Software/Group Relationships
    ###################################

    def get_all_software_used_by_all_groups(self) -> dict:
        """Retrieve all software used by all groups.

        Returns
        -------
        dict
            a mapping of group_stix_id => [{"object": Malware|Tool, "relationships": Relationship[]}] for each software used by the group and each software used
            by campaigns attributed to the group
        """
        # return data if it has already been fetched
        if self.all_software_used_by_all_groups:
            return self.all_software_used_by_all_groups

        # get software used by groups: [group_id => [ {software, [group_uses_software]} ]]
        tools_used_by_groups = self.get_related("intrusion-set", "uses", "tool")
        malware_used_by_groups = self.get_related("intrusion-set", "uses", "malware")
        software_used_by_groups = self.merge(tools_used_by_groups, malware_used_by_groups)

        # get software used by campaigns: [campaign_id => [ {software, [campaign_uses_software]} ]]
        tools_used_by_campaigns = self.get_related("campaign", "uses", "tool")
        malware_used_by_campaigns = self.get_related("campaign", "uses", "malware")
        software_used_by_campaigns = self.merge(tools_used_by_campaigns, malware_used_by_campaigns)

        # get groups attributing to campaigns: [group_id => [ {campaign, [campaign_attributed-to_group]} ]]
        groups_attributing = self.get_related("campaign", "attributed-to", "intrusion-set", reverse=True)

        # add inherited relationships to software used by groups
        software_used_by_groups = self.add_inherited_campaign_relationships(
            groups_attributing, software_used_by_campaigns, software_used_by_groups
        )

        self.all_software_used_by_all_groups = software_used_by_groups
        return software_used_by_groups

    def get_software_used_by_group(self, group_stix_id: str) -> list:
        """Get all software used by a group.

        Parameters
        ----------
        group_stix_id : str
            the STIX ID of the group

        Returns
        -------
        list
            a list of {"object": Malware|Tool, "relationships": Relationship[]} for each software used by the group and each software used
            by campaigns attributed to the group
        """
        software_used_by_groups = self.get_all_software_used_by_all_groups()
        return software_used_by_groups[group_stix_id] if group_stix_id in software_used_by_groups else []

    def get_all_groups_using_all_software(self) -> dict:
        """Get all groups using all software.

        Returns
        -------
        dict
            a mapping of software_stix_id => [{"object": IntrusionSet, "relationships": Relationship[]}] for each group using the software and each attributed campaign
            using the software
        """
        # return data if it has already been fetched
        if self.all_groups_using_all_software:
            return self.all_groups_using_all_software

        # get groups using software: [software_id => [ {group, [group_uses_software]} ]]
        groups_using_tools = self.get_related("intrusion-set", "uses", "tool", reverse=True)
        groups_using_malware = self.get_related("intrusion-set", "uses", "malware", reverse=True)
        groups_using_software = self.merge(groups_using_tools, groups_using_malware)

        # get campaigns using software: [software_id => [ {campaign, [campaign_uses_software]} ]]
        campaigns_using_tools = self.get_related("campaign", "uses", "tool", reverse=True)
        campaigns_using_malware = self.get_related("campaign", "uses", "malware", reverse=True)
        campaigns_using_software = self.merge(campaigns_using_tools, campaigns_using_malware)

        # get groups attributing to campaigns: [campaign_id => [ {group, [campaign_attributed-to_group]} ]]
        attributed_campaigns = self.get_related("campaign", "attributed-to", "intrusion-set")

        # add inherited relationships to groups using software
        groups_using_software = self.add_inherited_campaign_relationships(
            campaigns_using_software, attributed_campaigns, groups_using_software
        )

        self.all_groups_using_all_software = groups_using_software
        return groups_using_software

    def get_groups_using_software(self, software_stix_id: str) -> list:
        """Get all groups using a software.

        Parameters
        ----------
        stix_id : str
            the STIX ID of the software

        Returns
        -------
        list
            a list of {"object": IntrusionSet, "relationships": Relationship[]} for each group using the software and each attributed campaign
            using the software
        """
        groups_using_software = self.get_all_groups_using_all_software()
        return groups_using_software[software_stix_id] if software_stix_id in groups_using_software else []

    ###################################
    # Software/Campaign Relationships
    ###################################

    def get_all_software_used_by_all_campaigns(self) -> dict:
        """Get all software used by all campaigns.

        Returns
        -------
        dict
            a mapping of campaign_stix_id => [{"object": Malware|Tool, "relationships": Relationship[]}] for each software used by the campaign
        """
        # return data if it has already been fetched
        if self.all_software_used_by_all_campaigns:
            return self.all_software_used_by_all_campaigns

        tools_used_by_campaigns = self.get_related("campaign", "uses", "tool")
        malware_used_by_campaigns = self.get_related("campaign", "uses", "malware")
        self.all_software_used_by_all_campaigns = self.merge(tools_used_by_campaigns, malware_used_by_campaigns)

        return self.all_software_used_by_all_campaigns

    def get_software_used_by_campaign(self, campaign_stix_id: str) -> list:
        """Get all software used by a campaign.

        Parameters
        ----------
        campaign_stix_id : str
            the STIX ID of the campaign

        Returns
        -------
        list
            a list of {"object": Malware|Tool, "relationships": Relationship[]} for each software used by the campaign
        """
        software_used_by_campaigns = self.get_all_software_used_by_all_campaigns()
        return software_used_by_campaigns[campaign_stix_id] if campaign_stix_id in software_used_by_campaigns else []

    def get_all_campaigns_using_all_software(self) -> dict:
        """Get all campaigns using all software.

        Returns
        -------
        dict
            a mapping of software_stix_id => [{"object": Campaign, "relationships": Relationship[]}] for each campaign using the software
        """
        # return data if it has already been fetched
        if self.all_campaigns_using_all_software:
            return self.all_campaigns_using_all_software

        campaigns_using_tools = self.get_related("campaign", "uses", "tool", reverse=True)
        campaigns_using_malware = self.get_related("campaign", "uses", "malware", reverse=True)
        self.all_campaigns_using_all_software = self.merge(campaigns_using_tools, campaigns_using_malware)

        return self.all_campaigns_using_all_software

    def get_campaigns_using_software(self, software_stix_id: str) -> list:
        """Get all campaigns using a software.

        Parameters
        ----------
        software_stix_id : str
            the STIX ID of the software

        Returns
        -------
        list
            a list of {"object": Campaign, "relationships": Relationship[]} for each campaign using the software
        """
        campaigns_using_software = self.get_all_campaigns_using_all_software()
        return campaigns_using_software[software_stix_id] if software_stix_id in campaigns_using_software else []

    ###################################
    # Campaign/Group Relationships
    ###################################

    def get_all_groups_attributing_to_all_campaigns(self) -> dict:
        """Get all groups attributing to all campaigns.

        Returns
        -------
        dict
            a mapping of campaign_stix_id => [{"object": IntrusionSet, "relationships: Relationship[]}] for each group attributing to the campaign
        """
        # return data if it has already been fetched
        if self.all_groups_attributing_to_all_campaigns:
            return self.all_groups_attributing_to_all_campaigns

        self.all_groups_attributing_to_all_campaigns = self.get_related("campaign", "attributed-to", "intrusion-set")

        return self.all_groups_attributing_to_all_campaigns

    def get_groups_attributing_to_campaign(self, campaign_stix_id: str) -> list:
        """Get all groups attributing to a campaign.

        Parameters
        ----------
        campaign_stix_id : str
            the STIX ID of the campaign

        Returns
        -------
        list
            a list of {"object": IntrusionSet, "relationships": Relationship[]} for each group attributing to the campaign
        """
        groups_attributing_to_campaigns = self.get_all_groups_attributing_to_all_campaigns()
        return (
            groups_attributing_to_campaigns[campaign_stix_id]
            if campaign_stix_id in groups_attributing_to_campaigns
            else []
        )

    def get_all_campaigns_attributed_to_all_groups(self) -> dict:
        """Get all campaigns attributed to all groups.

        Returns
        -------
        dict
            a mapping of group_stix_id => [{"object": Campaign, "relationships": Relationship[]}] for each campaign attributed to the group
        """
        # return data if it has already been fetched
        if self.all_campaigns_attributed_to_all_groups:
            return self.all_campaigns_attributed_to_all_groups

        self.all_campaigns_attributed_to_all_groups = self.get_related(
            "campaign", "attributed-to", "intrusion-set", reverse=True
        )

        return self.all_campaigns_attributed_to_all_groups

    def get_campaigns_attributed_to_group(self, group_stix_id: str) -> list:
        """Get all campaigns attributed to a group.

        Parameters
        ----------
        group_stix_id : str
            the STIX ID of the group

        Returns
        -------
        list
            a list of {"object": Campaign, "relationships": Relationship[]} for each campaign attributed to the group
        """
        campaigns_attributed_to_groups = self.get_all_campaigns_attributed_to_all_groups()
        return campaigns_attributed_to_groups[group_stix_id] if group_stix_id in campaigns_attributed_to_groups else []

    ###################################
    # Technique/Group Relationships
    ###################################

    def get_all_techniques_used_by_all_groups(self) -> dict:
        """Get all techniques used by all groups.

        Returns
        -------
        dict
            a mapping of group_stix_id => [{"object": AttackPattern, "relationships": Relationship[]}] for each technique used by the group and
            each technique used by campaigns attributed to the group
        """
        # return data if it has already been fetched
        if self.all_techniques_used_by_all_groups:
            return self.all_techniques_used_by_all_groups

        # get techniques used by groups: [group_id => [ {technique, [group_uses_technique]} ]]
        techniques_used_by_groups = self.get_related("intrusion-set", "uses", "attack-pattern")

        # get techniques used by campaigns: [campaign_id => [ {technique, [campaign_uses_technique]} ]]
        techniques_used_by_campaigns = self.get_related("campaign", "uses", "attack-pattern")

        # get groups attributing to campaigns: [group_id => [ {campaign, [campaign_attributed-to_group]} ]]
        groups_attributing = self.get_related("campaign", "attributed-to", "intrusion-set", reverse=True)

        # add inherited relationships to techniques used by groups
        techniques_used_by_groups = self.add_inherited_campaign_relationships(
            groups_attributing, techniques_used_by_campaigns, techniques_used_by_groups
        )

        self.all_techniques_used_by_all_groups = techniques_used_by_groups
        return techniques_used_by_groups

    def get_techniques_used_by_group(self, group_stix_id: str) -> list:
        """Get all techniques used by a group.

        Parameters
        ----------
        group_stix_id : str
            the STIX ID of the group

        Returns
        -------
        list
            a list of {"object": AttackPattern, "relationships": Relationship[]} for each technique used by the group and
            each technique used by campaigns attributed to the group
        """
        techniques_used_by_groups = self.get_all_techniques_used_by_all_groups()
        return techniques_used_by_groups[group_stix_id] if group_stix_id in techniques_used_by_groups else []

    def get_all_groups_using_all_techniques(self) -> dict:
        """Get all groups using all techniques.

        Returns
        -------
        dict
            a mapping of technique_stix_id => [{"object": IntrusionSet, "relationships": Relationship[]}] for each group using the
            technique and each campaign attributed to groups using the technique
        """
        # return data if it has already been fetched
        if self.all_groups_using_all_techniques:
            return self.all_groups_using_all_techniques

        # get groups using techniques: [technique_id => [ {group, [group_uses_technique]} ]]
        groups_using_techniques = self.get_related("intrusion-set", "uses", "attack-pattern", reverse=True)

        # get campaigns using techniques: [technique_id => [ {campaign, [campaign_uses_technique]} ]]
        campaigns_using_techniques = self.get_related("campaign", "uses", "attack-pattern", reverse=True)

        # get groups attributing to campaigns: [campaign_id => [ {group, [campaign_attributed-to_group]} ]]
        attributed_campaigns = self.get_related("campaign", "attributed-to", "intrusion-set")

        # add inherited relationships to groups using techniques
        groups_using_techniques = self.add_inherited_campaign_relationships(
            campaigns_using_techniques, attributed_campaigns, groups_using_techniques
        )

        self.all_groups_using_all_techniques = groups_using_techniques
        return groups_using_techniques

    def get_groups_using_technique(self, technique_stix_id: str) -> list:
        """Get all groups using a technique.

        Parameters
        ----------
        technique_stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {"object": IntrusionSet, "relationships": Relationship[]} for each group using the technique and each campaign attributed to
            groups using the technique
        """
        groups_using_techniques = self.get_all_groups_using_all_techniques()
        return groups_using_techniques[technique_stix_id] if technique_stix_id in groups_using_techniques else []

    ###################################
    # Technique/Campaign Relationships
    ###################################

    def get_all_techniques_used_by_all_campaigns(self) -> dict:
        """Get all techniques used by all campaigns.

        Returns
        -------
        dict
            a mapping of campaign_stix_id => [{"object": AttackPattern, "relationships": Relationship[]}] for each technique used by the campaign
        """
        # return data if it has already been fetched
        if self.all_techniques_used_by_all_campaigns:
            return self.all_techniques_used_by_all_campaigns

        self.all_techniques_used_by_all_campaigns = self.get_related("campaign", "uses", "attack-pattern")

        return self.all_techniques_used_by_all_campaigns

    def get_techniques_used_by_campaign(self, campaign_stix_id: str) -> list:
        """Get all techniques used by a campaign.

        Parameters
        ----------
        campaign_stix_id : str
            the STIX ID of the campaign

        Returns
        -------
        list
            a list of {"object": AttackPattern, "relationships": Relationship[]} for each technique used by the campaign
        """
        techniques_used_by_campaigns = self.get_all_techniques_used_by_all_campaigns()
        return (
            techniques_used_by_campaigns[campaign_stix_id] if campaign_stix_id in techniques_used_by_campaigns else []
        )

    def get_all_campaigns_using_all_techniques(self) -> dict:
        """Get all campaigns using all techniques.

        Returns
        -------
        dict
            a mapping of technique_stix_id => [{"object": Campaign, "relationships": Relationship[]}] for each campaign using the technique
        """
        # return data if it has already been fetched
        if self.all_campaigns_using_all_techniques:
            return self.all_campaigns_using_all_techniques

        self.all_campaigns_using_all_techniques = self.get_related("campaign", "uses", "attack-pattern", reverse=True)

        return self.all_campaigns_using_all_techniques

    def get_campaigns_using_technique(self, technique_stix_id: str) -> list:
        """Get all campaigns using a technique.

        Parameters
        ----------
        technique_stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {"object": Campaign, "relationships": Relationship[]} for each campaign using the technique
        """
        campaigns_using_techniques = self.get_all_campaigns_using_all_techniques()
        return campaigns_using_techniques[technique_stix_id] if technique_stix_id in campaigns_using_techniques else []

    ###################################
    # Technique/Software Relationships
    ###################################

    def get_all_techniques_used_by_all_software(self) -> dict:
        """Get all techniques used by all software.

        Returns
        -------
        dict
            a mapping of software_stix_id => [{"object": AttackPattern, "relationships": Relationship[]}] for each technique used by the software
        """
        # return data if it has already been fetched
        if self.all_techniques_used_by_all_software:
            return self.all_techniques_used_by_all_software

        techniques_by_tools = self.get_related("tool", "uses", "attack-pattern")
        techniques_by_malware = self.get_related("malware", "uses", "attack-pattern")
        self.all_techniques_used_by_all_software = self.merge(techniques_by_tools, techniques_by_malware)

        return self.all_techniques_used_by_all_software

    def get_techniques_used_by_software(self, software_stix_id: str) -> list:
        """Get all techniques used by a software.

        Parameters
        ----------
        software_stix_id : str
            the STIX ID of the software

        Returns
        -------
        list
            a list of {"object": AttackPattern, "relationships": Relationship[]} for each technique used by the software
        """
        techniques_used_by_software = self.get_all_techniques_used_by_all_software()
        return techniques_used_by_software[software_stix_id] if software_stix_id in techniques_used_by_software else []

    def get_all_software_using_all_techniques(self) -> dict:
        """Get all software using all techniques.

        Returns
        -------
        dict
            a mapping of technique_stix_id => [{"object": Malware|Tool, "relationships": Relationship[]}] for each software using the technique
        """
        # return data if it has already been fetched
        if self.all_software_using_all_techniques:
            return self.all_software_using_all_techniques

        tools_using_techniques = self.get_related("tool", "uses", "attack-pattern", reverse=True)
        malware_using_techniques = self.get_related("malware", "uses", "attack-pattern", reverse=True)
        self.all_software_using_all_techniques = self.merge(tools_using_techniques, malware_using_techniques)

        return self.all_software_using_all_techniques

    def get_software_using_technique(self, technique_stix_id: str) -> list:
        """Get all software using a technique.

        Parameters
        ----------
        technique_stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {"object": Malware|Tool, "relationships": Relationship[]} for each software using the technique
        """
        software_using_techniques = self.get_all_software_using_all_techniques()
        return software_using_techniques[technique_stix_id] if technique_stix_id in software_using_techniques else []

    ###################################
    # Technique/Mitigation Relationships
    ###################################

    def get_all_techniques_mitigated_by_all_mitigations(self) -> dict:
        """Get all techniques mitigated by all mitigations.

        Returns
        -------
        dict
            a mapping of mitigation_stix_id => [{"object": AttackPattern, "relationships": Relationship[]}] for each technique mitigated by the mitigation
        """
        # return data if it has already been fetched
        if self.all_techniques_mitigated_by_all_mitigations:
            return self.all_techniques_mitigated_by_all_mitigations

        self.all_techniques_mitigated_by_all_mitigations = self.get_related(
            "course-of-action", "mitigates", "attack-pattern"
        )

        return self.all_techniques_mitigated_by_all_mitigations

    def get_techniques_mitigated_by_mitigation(self, mitigation_stix_id: str) -> list:
        """Get all techniques being mitigated by a mitigation.

        Parameters
        ----------
        mitigation_stix_id : str
            the STIX ID of the mitigation

        Returns
        -------
        list
            a list of {"object": AttackPattern, "relationships": Relationship[]} for each technique mitigated by the mitigation
        """
        techniques_mitigated_by_mitigations = self.get_all_techniques_mitigated_by_all_mitigations()
        return (
            techniques_mitigated_by_mitigations[mitigation_stix_id]
            if mitigation_stix_id in techniques_mitigated_by_mitigations
            else []
        )

    def get_all_mitigations_mitigating_all_techniques(self) -> dict:
        """Get all mitigations mitigating all techniques.

        Returns
        -------
        dict
            a mapping of technique_stix_id => [{"object": CourseOfAction, "relationships": Relationship[]}] for each mitigation mitigating the technique
        """
        # return data if it has already been fetched
        if self.all_mitigations_mitigating_all_techniques:
            return self.all_mitigations_mitigating_all_techniques

        self.all_mitigations_mitigating_all_techniques = self.get_related(
            "course-of-action", "mitigates", "attack-pattern", reverse=True
        )

        return self.all_mitigations_mitigating_all_techniques

    def get_mitigations_mitigating_technique(self, technique_stix_id: str) -> list:
        """Get all mitigations mitigating a technique.

        Parameters
        ----------
        technique_stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {"object": CourseOfAction, "relationships": Relationship[]} for each mitigation mitigating the technique
        """
        mitigations_mitigating_techniques = self.get_all_mitigations_mitigating_all_techniques()
        return (
            mitigations_mitigating_techniques[technique_stix_id]
            if technique_stix_id in mitigations_mitigating_techniques
            else []
        )

    ###################################
    # Technique/Subtechnique Relationships
    ###################################

    def get_all_parent_techniques_of_all_subtechniques(self) -> dict:
        """Get all parent techniques of all sub-techniques.

        Returns
        -------
        dict
            a mapping of subtechnique_stix_id => [{"object": AttackPattern, "relationships": Relationship[]}] describing the parent technique of the subtechnique
        """
        # return data if it has already been fetched
        if self.all_parent_techniques_of_all_subtechniques:
            return self.all_parent_techniques_of_all_subtechniques

        self.all_parent_techniques_of_all_subtechniques = self.get_related(
            "attack-pattern", "subtechnique-of", "attack-pattern"
        )

        return self.all_parent_techniques_of_all_subtechniques

    def get_parent_technique_of_subtechnique(self, subtechnique_stix_id: str) -> dict:
        """Get the parent technique of a sub-technique.

        Parameters
        ----------
        subtechnique_stix_id : str
            the STIX ID of the sub-technique

        Returns
        -------
        dict
            {"object": AttackPattern, "relationships": Relationship[]} describing the parent technique of the sub-technique
        """
        parent_techniques_of_subtechniques = self.get_all_parent_techniques_of_all_subtechniques()
        return (
            parent_techniques_of_subtechniques[subtechnique_stix_id]
            if subtechnique_stix_id in parent_techniques_of_subtechniques
            else []
        )

    def get_all_subtechniques_of_all_techniques(self) -> dict:
        """Get all subtechniques of all parent techniques.

        Returns
        -------
        dict
            a mapping of technique_stix_id => [{"object": AttackPattern, "relationships": Relationship[]}] for each subtechnique of the technique
        """
        # return data if it has already been fetched
        if self.all_subtechniques_of_all_techniques:
            return self.all_subtechniques_of_all_techniques

        self.all_subtechniques_of_all_techniques = self.get_related(
            "attack-pattern", "subtechnique-of", "attack-pattern", reverse=True
        )

        return self.all_subtechniques_of_all_techniques

    def get_subtechniques_of_technique(self, technique_stix_id: str) -> list:
        """Get all subtechniques of a technique.

        Parameters
        ----------
        technique_stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {"object": AttackPattern, "relationships": Relationship[]} for each subtechnique of the technique
        """
        subtechniques_of_techniques = self.get_all_subtechniques_of_all_techniques()
        return (
            subtechniques_of_techniques[technique_stix_id] if technique_stix_id in subtechniques_of_techniques else []
        )

    ###################################
    # Technique/Data Component Relationships
    ###################################

    def get_all_techniques_detected_by_all_datacomponents(self) -> dict:
        """Get all techniques detected by all data components.

        Returns
        -------
        dict
            a mapping of datacomponent_stix_id => [{"object": AttackPattern, "relationships": Relationship[]}] describing the detections of the data component
        """
        # return data if it has already been fetched
        if self.all_techniques_detected_by_all_datacomponents:
            return self.all_techniques_detected_by_all_datacomponents

        self.all_techniques_detected_by_all_datacomponents = self.get_related(
            "x-mitre-data-component", "detects", "attack-pattern"
        )

        return self.all_techniques_detected_by_all_datacomponents

    def get_techniques_detected_by_datacomponent(self, datacomponent_stix_id: str) -> list:
        """Get all techniques detected by a data component.

        Parameters
        ----------
        datacomponent_stix_id : str
            the STIX ID of the data component

        Returns
        -------
        list
            a list of {"object": AttackPattern, "relationships": Relationship[]} describing the detections of the data component
        """
        techniques_detected_by_datacomponents = self.get_all_techniques_detected_by_all_datacomponents()
        return (
            techniques_detected_by_datacomponents[datacomponent_stix_id]
            if datacomponent_stix_id in techniques_detected_by_datacomponents
            else []
        )

    def get_all_datacomponents_detecting_all_techniques(self) -> dict:
        """Get all data components detecting all techniques.

        Returns
        -------
        dict
            a mapping of technique_stix_id => [{"object": DataComponent, "relationships": Relationship[]}] describing the data components that can detect the technique
        """
        # return data if it has already been fetched
        if self.all_datacomponents_detecting_all_techniques:
            return self.all_datacomponents_detecting_all_techniques

        self.all_datacomponents_detecting_all_techniques = self.get_related(
            "x-mitre-data-component", "detects", "attack-pattern", reverse=True
        )

        return self.all_datacomponents_detecting_all_techniques

    def get_datacomponents_detecting_technique(self, technique_stix_id: str) -> list:
        """Get all data components detecting a technique.

        Parameters
        ----------
        technique_stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {"object": DataComponent, "relationships": Relationship[]} describing the data components that can detect the technique
        """
        datacomponents_detecting_techniques = self.get_all_datacomponents_detecting_all_techniques()
        return (
            datacomponents_detecting_techniques[technique_stix_id]
            if technique_stix_id in datacomponents_detecting_techniques
            else []
        )

    def get_revoking_object(self, revoked_stix_id: str = "") -> object:
        """Given the STIX ID of a revoked object, retrieve the STIX object that replaced ("revoked") it.

        Parameters
        ----------
        revoked_stix_id : str
            the STIX ID of the object that has been revoked

        Returns
        -------
        object
            the object that replaced ("revoked") it
        """
        relations = self.src.relationships(revoked_stix_id, "revoked-by", source_only=True)
        revoked_by = self.src.query([Filter("id", "in", [r.target_ref for r in relations])])

        if not revoked_by:
            return None

        return revoked_by[0]

    ###################################
    # Technique/Asset Relationships
    ###################################

    def get_all_techniques_targeting_all_assets(self) -> dict:
        """Get all techniques targeting all assets.

        Returns
        -------
        dict
            a mapping of asset_stix_id => [{'object': AttackPattern, 'relationships': Relationship[]}] for each technique targeting the asset
        """
        # return data if it has already been fetched
        if self.all_techniques_targeting_all_assets:
            return self.all_techniques_targeting_all_assets

        self.all_techniques_targeting_all_assets = self.get_related(
            "attack-pattern", "targets", "x-mitre-asset", reverse=True
        )

        return self.all_techniques_targeting_all_assets

    def get_techniques_targeting_asset(self, asset_stix_id: str) -> list:
        """Get all techniques targeting an asset.

        Parameters
        ----------
        asset_stix_id : str
            the STIX ID of the asset

        Returns
        -------
        list
            a list of {"object": AttackPattern, "relationships": Relationship[]} for each technique targeting the asset
        """
        techniques_targeting_assets = self.get_all_techniques_targeting_all_assets()
        return techniques_targeting_assets[asset_stix_id] if asset_stix_id in techniques_targeting_assets else []

    def get_all_assets_targeted_by_all_techniques(self) -> dict:
        """Get all assets targeted by all techniques.

        Returns
        -------
        dict
            a mapping of technique_stix_id => [{'object': Asset, 'relationships': Relationship[]}] for each asset targeted by the technique
        """
        # return data if it has already been fetched
        if self.all_assets_targeted_by_all_techniques:
            return self.all_assets_targeted_by_all_techniques

        self.all_assets_targeted_by_all_techniques = self.get_related("attack-pattern", "targets", "x-mitre-asset")

        return self.all_assets_targeted_by_all_techniques

    def get_assets_targeted_by_technique(self, technique_stix_id: str) -> list:
        """Get all assets targeted by a technique.

        Parameters
        ----------
        technique_stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {"object": Asset, "relationships": Relationship[]} for each asset targeted by the technique
        """
        assets_targeted_by_techniques = self.get_all_assets_targeted_by_all_techniques()
        return (
            assets_targeted_by_techniques[technique_stix_id]
            if technique_stix_id in assets_targeted_by_techniques
            else []
        )
