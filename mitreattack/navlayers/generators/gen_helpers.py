MITRE_ATTACK_DOMAIN_STRINGS = ['mitre-attack', 'mitre-mobile-attack', 'mitre-ics-attack']


def remove_revoked_depreciated(listing):
    """
    Remove revoked and depreciated elements from the listing
    :param listing: input element list
    :return: input element list - revoked elements
    """
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            listing
        )
    )


def construct_relationship_mapping(mapping_obj, rel):
    """
    Helper to safely add an relationship to a listing in the mapping_obj
    :param mapping_obj: A dictionary containing mappings of attack object types (course-of-action,
                        tool, malware, or intrusion-set) to relationships
    :param rel: The relationship to add
    :return: Updated mapping_obj
    """
    if rel['target_ref'] not in mapping_obj:
        mapping_obj[rel['target_ref']] = []
    mapping_obj[rel['target_ref']].append(rel)


def get_attack_id(obj):
    """
    Helper function to get the ATT&CK ID from an object
    :param obj: The object to extract from
    :return: The ATT&CK ID in string form
    """
    for entry in obj['external_references']:
        if entry['source_name'] in MITRE_ATTACK_DOMAIN_STRINGS:
            return entry['external_id']
    return '-1'
