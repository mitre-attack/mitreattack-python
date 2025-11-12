"""Hierarchy builder for grouping STIX objects in parent-child relationships."""

from typing import Dict, List

from mitreattack.diffStix.utils.stix_utils import has_subtechniques, resolve_datacomponent_parent


class HierarchyBuilder:
    """Builds hierarchical groupings of STIX objects (techniques/subtechniques, datasources/components)."""

    def __init__(self, diff_stix_instance):
        """Initialize HierarchyBuilder with a DiffStix instance.

        Parameters
        ----------
        diff_stix_instance : DiffStix
            The DiffStix instance containing data and helper methods
        """
        self.diff_stix = diff_stix_instance

    def get_groupings(self, object_type: str, stix_objects: List, section: str, domain: str) -> List[Dict[str, object]]:
        """Group STIX objects together within a section.

        A "group" in this sense is a set of STIX objects that are all in the same section, e.g. new minor version.
        In this case, since a domain/object type are implied before we get here, it would be
        e.g. "All Enterprise Techniques & Subtechniques, grouped alphabetically by name, and the
        sub-techniques are 'grouped' under their parent technique"

        Parameters
        ----------
        object_type : str
            Type of STIX object that is being worked with.
        stix_objects : List
            List of STIX objects that need to be grouped.
        section : str
            Section of the changelog that is being created with the objects,
            e.g. new major version, revocation, etc.
        domain : str
            ATT&CK domain (e.g., "enterprise-attack")

        Returns
        -------
        List[Dict[str, object]]
            A list of sorted, complex dictionary objects that tell if this "group" of objects have
            their parent objects in the same section.
        """
        datastore_version = "old" if section == "deletions" else "new"
        subtechnique_relationships = self.diff_stix.data[datastore_version][domain]["relationships"]["subtechniques"]
        techniques = self.diff_stix.data[datastore_version][domain]["attack_objects"]["techniques"]
        datacomponents = self.diff_stix.data[datastore_version][domain]["attack_objects"]["datacomponents"]
        datasources = self.diff_stix.data[datastore_version][domain]["attack_objects"]["datasources"]

        childless = []
        parents = []
        children = {}
        # get parents which have children
        if object_type == "datasource":
            for stix_object in stix_objects:
                if stix_object.get("x_mitre_data_source_ref"):
                    children[stix_object["id"]] = stix_object
                else:
                    parents.append(stix_object)
        else:
            for stix_object in stix_objects:
                is_subtechnique = stix_object.get("x_mitre_is_subtechnique")

                if is_subtechnique:
                    children[stix_object["id"]] = stix_object
                elif has_subtechniques(stix_object=stix_object, subtechnique_relationships=subtechnique_relationships):
                    parents.append(stix_object)
                else:
                    childless.append(stix_object)

        parentToChildren = {}
        # subtechniques
        for relationship in subtechnique_relationships.values():
            if relationship["source_ref"] not in children:
                continue

            parent_technique_stix_id = relationship["target_ref"]
            the_subtechnique = children[relationship["source_ref"]]
            if parent_technique_stix_id not in parentToChildren:
                parentToChildren[parent_technique_stix_id] = []
            parentToChildren[parent_technique_stix_id].append(the_subtechnique)

        # datacomponents
        for datacomponent in datacomponents.values():
            if datacomponent["id"] not in children:
                continue

            # Prefer explicit reference, otherwise try a heuristic lookup
            parent_datasource_id = datacomponent.get("x_mitre_data_source_ref")
            if not parent_datasource_id:
                parent_datasource_id = resolve_datacomponent_parent(datacomponent, datasources)
            the_datacomponent = children[datacomponent["id"]]
            if parent_datasource_id:
                if parent_datasource_id not in parentToChildren:
                    parentToChildren[parent_datasource_id] = []
                parentToChildren[parent_datasource_id].append(the_datacomponent)

        # now group parents and children
        groupings = []
        for parent_stix_object in childless + parents:
            child_objects = (
                parentToChildren.pop(parent_stix_object["id"]) if parent_stix_object["id"] in parentToChildren else []
            )
            groupings.append(
                {
                    "parent": parent_stix_object,
                    "parentInSection": True,
                    "children": child_objects,
                }
            )

        for parent_stix_id, child_objects in parentToChildren.items():
            parent_stix_object = None
            if parent_stix_id in techniques:
                parent_stix_object = techniques[parent_stix_id]
            elif parent_stix_id in datasources:
                parent_stix_object = datasources[parent_stix_id]

            if parent_stix_object:
                groupings.append(
                    {
                        "parent": parent_stix_object,
                        "parentInSection": False,
                        "children": child_objects,
                    }
                )

        groupings = sorted(groupings, key=lambda grouping: grouping["parent"]["name"])
        return groupings
