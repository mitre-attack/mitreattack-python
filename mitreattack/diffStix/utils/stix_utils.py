"""STIX object manipulation and parsing utilities."""

from typing import List, Optional


def get_attack_id(stix_obj: dict) -> Optional[str]:
    """Get the object's ATT&CK ID.

    Parameters
    ----------
    stix_obj : dict
        An ATT&CK STIX Domain Object (SDO).

    Returns
    -------
    str (optional)
        The ATT&CK ID of the object. Returns None if not found
    """
    attack_id = None
    external_references = stix_obj.get("external_references")
    if external_references:
        attack_source = external_references[0]
        if attack_source.get("external_id") and attack_source.get("source_name") in [
            "mitre-attack",
            "mitre-mobile-attack",
            "mitre-ics-attack",
        ]:
            attack_id = attack_source["external_id"]
    return attack_id


def deep_copy_stix(stix_objects: List[dict]) -> List[dict]:
    """Transform STIX to dict and deep copy the dict.

    Parameters
    ----------
    stix_objects : List[dict]
        A list of Python dictionaries of ATT&CK STIX Domain Objects.

    Returns
    -------
    List[dict]
        A slightly easier to work with list of Python dictionaries of ATT&CK STIX Domain Objects.
    """
    result = []
    for stix_object in stix_objects:
        # TODO: serialize the STIX objects instead of casting them to dict
        # more details here: https://github.com/mitre/cti/issues/17#issuecomment-395768815
        stix_object = dict(stix_object)
        if "external_references" in stix_object:
            # Create a new list to ensure deep copy
            stix_object["external_references"] = [dict(ref) for ref in stix_object["external_references"]]
        if "kill_chain_phases" in stix_object:
            # Create a new list to ensure deep copy
            stix_object["kill_chain_phases"] = [dict(phase) for phase in stix_object["kill_chain_phases"]]

        if "modified" in stix_object:
            stix_object["modified"] = str(stix_object["modified"])
        if "first_seen" in stix_object:
            stix_object["first_seen"] = str(stix_object["first_seen"])
        if "last_seen" in stix_object:
            stix_object["last_seen"] = str(stix_object["last_seen"])

        if "definition" in stix_object:
            stix_object["definition"] = dict(stix_object["definition"])
        stix_object["created"] = str(stix_object["created"])
        result.append(stix_object)
    return result


def cleanup_values(groupings: List[dict]) -> List[dict]:
    """Clean the values found in the initial groupings of ATT&CK Objects.

    Parameters
    ----------
    groupings : List[dict]
        Whatever comes out of DiffStix.get_groupings()

    Returns
    -------
    List[dict]
        A cleaned up version of groupings.
    """
    new_values = []
    for grouping in groupings:
        if grouping["parentInSection"]:
            new_values.append(grouping["parent"])

        for child in sorted(grouping["children"], key=lambda child: child["name"]):
            new_values.append(child)

    return new_values


def resolve_datacomponent_parent(datacomponent: dict, datasources: dict) -> Optional[str]:
    """Best-effort resolution of a datacomponent's parent datasource when an explicit x_mitre_data_source_ref is not present.

    Strategy:
    1. If the datacomponent contains an explicit 'x_mitre_data_source_ref', return it.
    2. If no match, return None.

    Parameters
    ----------
    datacomponent : dict
        The data component STIX object.
    datasources : dict
        Dictionary of datasources.

    Returns
    -------
    Optional[str]
        The STIX ID of the parent data source, or None if not found.
    """
    # explicit ref
    parent_ref = datacomponent.get("x_mitre_data_source_ref")
    if parent_ref:
        return parent_ref

    # nothing matched
    return None


def has_subtechniques(stix_object: dict, subtechnique_relationships: dict) -> bool:
    """Check if a technique has any subtechniques.

    Parameters
    ----------
    stix_object : dict
        The technique STIX object to check.
    subtechnique_relationships : dict
        Dictionary of subtechnique relationships.

    Returns
    -------
    bool
        True if the technique has subtechniques, False otherwise.
    """
    stix_id = stix_object["id"]

    for relationship in subtechnique_relationships.values():
        if relationship.get("target_ref") == stix_id:
            return True

    return False
