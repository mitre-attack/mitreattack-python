"""Constants and configuration values for changelog generation."""

import datetime
import os

# Date-based defaults
DATE = datetime.datetime.today()
THIS_MONTH = DATE.strftime("%B_%Y")

# Default layer file paths
LAYER_DEFAULTS = [
    os.path.join("output", f"{THIS_MONTH}_Updates_Enterprise.json"),
    os.path.join("output", f"{THIS_MONTH}_Updates_Mobile.json"),
    os.path.join("output", f"{THIS_MONTH}_Updates_ICS.json"),
    os.path.join("output", f"{THIS_MONTH}_Updates_Pre.json"),
]

# Domain mappings
DOMAIN_TO_LABEL = {
    "enterprise-attack": "Enterprise",
    "mobile-attack": "Mobile",
    "ics-attack": "ICS",
}

# ATT&CK object type mappings
ATTACK_TYPE_TO_TITLE = {
    "techniques": "Techniques",
    "software": "Software",
    "groups": "Groups",
    "campaigns": "Campaigns",
    "assets": "Assets",
    "mitigations": "Mitigations",
    "datasources": "Data Sources",
    "datacomponents": "Data Components",
    "detectionstrategies": "Detection Strategies",
    "analytics": "Analytics",
}

# Object types to process
ATTACK_TYPES = [
    "techniques",
    "software",
    "groups",
    "campaigns",
    "assets",
    "mitigations",
    "datasources",
    "datacomponents",
    "detectionstrategies",
    "analytics",
]

# Section descriptions for changelog
SECTION_DESCRIPTIONS = {
    "additions": "ATT&CK objects which are only present in the new release.",
    "major_version_changes": "ATT&CK objects that have a major version change. (e.g. 1.0 → 2.0)",
    "minor_version_changes": "ATT&CK objects that have a minor version change. (e.g. 1.0 → 1.1)",
    "other_version_changes": "ATT&CK objects that have a version change of any other kind. (e.g. 1.0 → 1.2)",
    "patches": "ATT&CK objects that have been patched while keeping the version the same. (e.g., 1.0 → 1.0 but something like a typo, a URL, or some metadata was fixed)",
    "revocations": "ATT&CK objects which are revoked by a different object.",
    "deprecations": "ATT&CK objects which are deprecated and no longer in use, and not replaced.",
    "deletions": "ATT&CK objects which are no longer found in the STIX data.",
    "unchanged": "ATT&CK objects which did not change between the two versions.",
}


# Section headers by object type
def get_section_headers(object_type: str) -> dict:
    """Get section headers for a specific object type.

    Parameters
    ----------
    object_type : str
        The ATT&CK object type (e.g., "techniques", "software")

    Returns
    -------
    dict
        Section headers for the given object type
    """
    return {
        "additions": f"New {ATTACK_TYPE_TO_TITLE[object_type]}",
        "major_version_changes": "Major Version Changes",
        "minor_version_changes": "Minor Version Changes",
        "other_version_changes": "Other Version Changes",
        "patches": "Patches",
        "deprecations": "Deprecations",
        "revocations": "Revocations",
        "deletions": "Deletions",
        "unchanged": "Unchanged",
    }


# Navigator layer colors for different change types
LAYER_COLORS = {
    "additions": "#a1d99b",
    "major_version_changes": "#2ca25f",
    "minor_version_changes": "#99d8c9",
    "other_version_changes": "#feb24c",
    "patches": "#ffeda0",
    "revocations": "#fc4e2a",
    "deprecations": "#e31a1c",
}

# Layer legend labels
LAYER_LEGEND_LABELS = {
    "additions": "additions: New objects",
    "major_version_changes": "major version changes: Object has a new major version",
    "minor_version_changes": "minor version changes: Object has a new minor version",
    "other_version_changes": "other version changes: Object has a different version increment",
    "patches": "patches: Object has a patch",
    "revocations": "revocations: Object has been revoked",
    "deprecations": "deprecations: Object has been deprecated",
}

# Default change categories
CHANGE_CATEGORIES = [
    "additions",
    "major_version_changes",
    "minor_version_changes",
    "other_version_changes",
    "patches",
    "revocations",
    "deprecations",
    "deletions",
]

# Change categories with unchanged
CHANGE_CATEGORIES_WITH_UNCHANGED = CHANGE_CATEGORIES + ["unchanged"]
