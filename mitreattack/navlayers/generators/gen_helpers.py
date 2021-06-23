def remove_revoked(listing):
    """
    Remove revoked elements from the listing
    :param listing: input element list
    :return: input element list - revoked elements
    """
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            listing
        )
    )


def construct_relationship_mapping(mapping_obj, entry):
    """
    Helper to safely add an entry to a listing in the mapping_obj
    :param mapping_obj: A dictionary containing mappings of references to entries
    :param entry: The entry to add
    :return: Updated mapping_obj
    """
    if entry['target_ref'] not in mapping_obj:
        mapping_obj[entry['target_ref']] = []
    mapping_obj[entry['target_ref']].append(entry)


def get_attack_id(obj):
    """
    Helper function to get the ATT&CK ID from an object
    :param obj: The object to extract from
    :return: The ATT&CK ID in string form
    """
    for entry in obj['external_references']:
        if entry['source_name'] == 'mitre-attack':
            return entry['external_id']
    return '-1'
