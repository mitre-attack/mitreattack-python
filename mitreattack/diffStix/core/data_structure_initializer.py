"""Data structure initializer for DiffStix nested data model."""

from typing import Dict, List


class DataStructureInitializer:
    """Initializes the nested data structure for tracking ATT&CK changes."""

    @staticmethod
    def create_structure(domains: List[str], object_types: List[str]) -> Dict:
        """Create the base data structure for change tracking.

        The data structure has three main sections:
        - "old": Old version STIX data for each domain
        - "new": New version STIX data for each domain
        - "changes": Detected changes organized by object type and domain

        Parameters
        ----------
        domains : List[str]
            List of ATT&CK domains to initialize (e.g., ["enterprise-attack", "mobile-attack"])
        object_types : List[str]
            List of ATT&CK object types (e.g., ["techniques", "software", "groups"])

        Returns
        -------
        Dict
            Initialized nested data structure ready for loading STIX data
        """
        data = {
            "old": {},
            "new": {},
            # Changes are dynamic based on what object types and domains are requested
            "changes": {
                # Structure will be:
                # "techniques": {
                #     "enterprise-attack": {
                #         "additions": [],
                #         "deletions": [],
                #         "major_version_changes": [],
                #         "minor_version_changes": [],
                #         "other_version_changes": [],
                #         "patches": [],
                #         "revocations": [],
                #         "deprecations": [],
                #         "unchanged": [],
                #     },
                #     "mobile-attack": {...},
                # },
                # "software": {...},
            },
        }

        # Initialize domain-specific data structures for old and new versions
        for domain in domains:
            for datastore_version in ["old", "new"]:
                data[datastore_version][domain] = {
                    "attack_objects": {
                        # Will contain entries like:
                        # "techniques": {},
                        # "software": {},
                        # etc.
                    },
                    "attack_release_version": None,  # Will be set to "X.Y" format
                    "stix_datastore": None,  # Will be set to <stix.MemoryStore> instance
                    "relationships": {
                        "subtechniques": {},
                        "revoked-by": {},
                        "mitigations": {},
                        "detections": {},
                    },
                }

                # Initialize empty dict for each object type
                for obj_type in object_types:
                    data[datastore_version][domain]["attack_objects"][obj_type] = {}

        return data
