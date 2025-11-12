"""Configuration manager for DiffStix constants and mappings."""

from typing import Dict, List


class ConfigurationManager:
    """Manages domain labels, object type titles, and section configurations."""

    @property
    def domain_labels(self) -> Dict[str, str]:
        """Map domain identifiers to human-readable labels.

        Returns
        -------
        Dict[str, str]
            Mapping of domain ID to display label
        """
        return {
            "enterprise-attack": "Enterprise",
            "mobile-attack": "Mobile",
            "ics-attack": "ICS",
        }

    @property
    def type_titles(self) -> Dict[str, str]:
        """Map ATT&CK object types to human-readable titles.

        Returns
        -------
        Dict[str, str]
            Mapping of object type to display title
        """
        return {
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

    @property
    def section_descriptions(self) -> Dict[str, str]:
        """Get descriptions for each changelog section type.

        Returns
        -------
        Dict[str, str]
            Mapping of section name to description
        """
        return {
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

    @property
    def object_types(self) -> List[str]:
        """Get the list of supported ATT&CK object types.

        Returns
        -------
        List[str]
            List of object type identifiers
        """
        return [
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

    def get_section_headers(self, object_type: str) -> Dict[str, str]:
        """Generate section headers for a specific object type.

        Parameters
        ----------
        object_type : str
            The ATT&CK object type (e.g., 'techniques', 'software')

        Returns
        -------
        Dict[str, str]
            Mapping of section name to header text
        """
        type_title = self.type_titles[object_type]
        return {
            "additions": f"New {type_title}",
            "major_version_changes": "Major Version Changes",
            "minor_version_changes": "Minor Version Changes",
            "other_version_changes": "Other Version Changes",
            "patches": "Patches",
            "deprecations": "Deprecations",
            "revocations": "Revocations",
            "deletions": "Deletions",
            "unchanged": "Unchanged",
        }

    def get_all_section_headers(self) -> Dict[str, Dict[str, str]]:
        """Generate section headers for all object types.

        Returns
        -------
        Dict[str, Dict[str, str]]
            Nested mapping of object type to section headers
        """
        return {object_type: self.get_section_headers(object_type) for object_type in self.object_types}
