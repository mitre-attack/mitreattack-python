"""Helper functions."""
from mitreattack.constants import MITRE_ATTACK_ID_SOURCE_NAMES


def remove_revoked_depreciated(listing):
    """Remove revoked and depreciated elements from the listing.

    :param listing: input element list
    :return: input element list - revoked elements
    """
    return list(
        filter(lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False, listing)
    )


def construct_relationship_mapping(mapping_obj, rel):
    """Will safely add a relationship to a listing in the mapping_obj.

    :param mapping_obj: A dictionary containing mappings of attack object types (course-of-action,
                        tool, malware, or intrusion-set) to relationships
    :param rel: The relationship to add
    :return: Updated mapping_obj
    """
    if rel["target_ref"] not in mapping_obj:
        mapping_obj[rel["target_ref"]] = []
    mapping_obj[rel["target_ref"]].append(rel)


def get_attack_id(obj):
    """Get the ATT&CK ID from an object.

    :param obj: The object to extract from
    :return: The ATT&CK ID in string form
    """
    if not obj["type"].startswith("x-mitre"):
        for entry in obj["external_references"]:
            if entry["source_name"] in MITRE_ATTACK_ID_SOURCE_NAMES:
                return entry["external_id"]
    else:
        return obj["id"]
    return "-1"


def build_data_strings(data_sources, data_components):
    """Build source->component strings for layer generation.

    :param data_sources: List of Data Sources (dicts)
    :param data_components: List of Data Components (dicts)
    :return: dict mapping of Data Component IDs to generated source->component strings
    """
    out = dict()
    for component in data_components:
        ref = component["x_mitre_data_source_ref"]
        try:
            source = [x for x in data_sources if x["id"] == ref][0]
            name = f"{source['name']}: {component['name']}"
            out[component["id"]] = name
        except IndexError:
            print(
                f'[generator] - (WARNING): no matching data source{ref} found for data component {component["id"]}. '
                f"Skipping..."
            )
            pass
    return out
