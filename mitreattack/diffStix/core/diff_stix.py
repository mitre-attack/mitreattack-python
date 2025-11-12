"""Main DiffStix class for detecting and summarizing differences between ATT&CK versions."""

from __future__ import annotations

from typing import Dict, List, Optional

import stix2
from loguru import logger
from rich.progress import track
from stix2 import MemoryStore

from mitreattack.diffStix.core.change_detector import ChangeDetector
from mitreattack.diffStix.core.contributor_tracker import ContributorTracker
from mitreattack.diffStix.core.data_loader import DataLoader
from mitreattack.diffStix.core.domain_statistics import DomainStatistics
from mitreattack.diffStix.core.hierarchy_builder import HierarchyBuilder
from mitreattack.diffStix.core.statistics_collector import StatisticsCollector
from mitreattack.diffStix.formatters.json_generator import JsonGenerator
from mitreattack.diffStix.formatters.layer_generator import LayerGenerator
from mitreattack.diffStix.formatters.markdown_generator import MarkdownGenerator
from mitreattack.diffStix.utils.stix_utils import (
    get_attack_id,
)
from mitreattack.diffStix.utils.version_utils import (
    AttackObjectVersion,
    get_attack_object_version,
    version_increment_is_valid,
)


class DiffStix(object):
    """Utilities for detecting and summarizing differences between two versions of the ATT&CK content."""

    def __init__(
        self,
        domains: Optional[List[str]] = None,
        layers: Optional[List[str]] = None,
        unchanged: bool = False,
        old: Optional[str] = "old",
        new: str = "new",
        show_key: bool = False,
        site_prefix: str = "",
        use_mitre_cti: bool = False,
        verbose: bool = False,
        include_contributors: bool = False,
    ):
        """Construct a new DiffStix object.

        Parameters
        ----------
        domains : List[str], optional
            List of domains to parse, by default ["enterprise-attack", "mobile-attack", "ics-attack"]
        layers : List[str], optional
            Array of output filenames for layer files, by default None
        unchanged : bool, optional
            Include unchanged ATT&CK objects in diff comparison, by default False
        old : str, optional
            Directory to load old STIX data from, by default "old"
        new : str, optional
            Directory to load new STIX data from, by default "new"
        show_key : bool, optional
            Output key to markdown file, by default False
        site_prefix : str, optional
            Prefix links in markdown output, by default ""
        use_mitre_cti : bool, optional
            Use https://github.com/mitre/cti for loading old STIX data, by default False
        verbose : bool, optional
            Print progress bar and status messages to stdout, by default False
        include_contributors : bool, optional
            Include contributor information for new contributors, by default False
        """
        if domains is None:
            domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
        self.domains = domains
        self.layers = layers
        self.unchanged = unchanged
        self.old = old
        self.new = new
        self.show_key = show_key
        self.site_prefix = site_prefix
        self.types = [
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
        self.use_mitre_cti = use_mitre_cti
        self.verbose = verbose
        self.include_contributors = include_contributors

        self.domain_to_domain_label = {
            "enterprise-attack": "Enterprise",
            "mobile-attack": "Mobile",
            "ics-attack": "ICS",
        }
        self.attack_type_to_title = {
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

        self.section_descriptions = {
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

        self.section_headers = {}
        for object_type in self.types:
            self.section_headers[object_type] = {
                "additions": f"New {self.attack_type_to_title[object_type]}",
                "major_version_changes": "Major Version Changes",
                "minor_version_changes": "Minor Version Changes",
                "other_version_changes": "Other Version Changes",
                "patches": "Patches",
                "deprecations": "Deprecations",
                "revocations": "Revocations",
                "deletions": "Deletions",
                "unchanged": "Unchanged",
            }

        # Initialize contributor tracker for the new release
        self._contributor_tracker = ContributorTracker()

        # data gets loaded into here in the load_data() function. All other functionalities rely on this data structure
        self.data = {
            "old": {},
            "new": {},
            # changes are dynamic based on what object types and domains are requested
            "changes": {
                # "technique": {
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

        for domain in self.domains:
            for datastore_version in ["old", "new"]:
                self.data[datastore_version][domain] = {
                    "attack_objects": {
                        # self.types
                        # "techniques": {},
                        # ...
                    },
                    "attack_release_version": None,  # "X.Y"
                    "stix_datastore": None,  # <stix.MemoryStore>
                    "relationships": {
                        "subtechniques": {},
                        "revoked-by": {},
                    },
                }

                for _type in self.types:
                    self.data[datastore_version][domain]["attack_objects"][_type] = {}

        # Initialize data loader and change detector before data loading
        self._data_loader = DataLoader(self)
        self._change_detector = ChangeDetector(self)

        self.load_data()

        # Initialize components after data is loaded
        self._hierarchy_builder = HierarchyBuilder(self)
        self._statistics_collector = StatisticsCollector(self)
        self._markdown_generator = MarkdownGenerator(self)
        self._layer_generator = LayerGenerator(self)
        self._json_generator = JsonGenerator(self)

    @property
    def release_contributors(self) -> dict:
        """Get the release contributors dictionary for backward compatibility.

        Returns
        -------
        dict
            Dictionary of contributor names to contribution counts.
        """
        return self._contributor_tracker.release_contributors

    @release_contributors.setter
    def release_contributors(self, value: dict):
        """Set the release contributors dictionary for backward compatibility.

        Parameters
        ----------
        value : dict
            Dictionary of contributor names to contribution counts.
        """
        self._contributor_tracker.release_contributors = value

    def _detect_revocation(self, stix_id: str, old_obj: dict, new_obj: dict, new_attack_objects: dict, domain: str):
        """Detect if an object has been newly revoked.

        Parameters
        ----------
        stix_id : str
            The STIX ID of the object.
        old_obj : dict
            The old version of the STIX object.
        new_obj : dict
            The new version of the STIX object.
        new_attack_objects : dict
            Dictionary of all new attack objects for this type.
        domain : str
            The ATT&CK domain.

        Returns
        -------
        None, True, or False
            None if not a revocation scenario (not revoked or already revoked),
            True if newly revoked and successfully validated,
            False if validation failed (object should be skipped).
        """
        return self._change_detector.detect_revocation(stix_id, old_obj, new_obj, new_attack_objects, domain)

    def _detect_deprecation(self, old_obj: dict, new_obj: dict) -> bool:
        """Detect if an object has been newly deprecated.

        Parameters
        ----------
        old_obj : dict
            The old version of the STIX object.
        new_obj : dict
            The new version of the STIX object.

        Returns
        -------
        bool
            True if the object was newly deprecated, False otherwise.
        """
        return self._change_detector.detect_deprecation(old_obj, new_obj)

    def _categorize_version_change(
        self, stix_id: str, old_obj: dict, new_obj: dict
    ) -> tuple[str | None, AttackObjectVersion, AttackObjectVersion]:
        """Categorize the type of version change for an object.

        Parameters
        ----------
        stix_id : str
            The STIX ID of the object.
        old_obj : dict
            The old version of the STIX object.
        new_obj : dict
            The new version of the STIX object.

        Returns
        -------
        tuple[str | None, AttackObjectVersion, AttackObjectVersion]
            A tuple containing:
            - category: 'major', 'minor', 'other', 'patch', or None (unchanged)
            - old_version: The old version
            - new_version: The new version
        """
        return self._change_detector.categorize_version_change(stix_id, old_obj, new_obj)

    def _process_description_changes(self, old_obj: dict, new_obj: dict):
        """Process and store description changes between old and new objects.

        Parameters
        ----------
        old_obj : dict
            The old version of the STIX object.
        new_obj : dict
            The new version of the STIX object.
        """
        return self._change_detector.process_description_changes(old_obj, new_obj)

    def _process_relationship_changes(self, new_obj: dict, domain: str):
        """Process relationship changes for attack patterns (techniques).

        Parameters
        ----------
        new_obj : dict
            The new version of the STIX object.
        domain : str
            The ATT&CK domain.
        """
        return self._change_detector.process_relationship_changes(new_obj, domain)

    def load_data(self):
        """Load data from files into data dict."""
        # Import here to avoid circular dependency

        from deepdiff import DeepDiff

        for domain in track(self.domains, description="Loading domains"):
            self.load_domain(domain=domain)

        for domain in track(self.domains, description="Finding changes by domain"):
            for obj_type in self.types:
                logger.debug(f"Loading: [{domain:17}]/{obj_type}")

                old_attack_objects = self.data["old"][domain]["attack_objects"][obj_type]
                new_attack_objects = self.data["new"][domain]["attack_objects"][obj_type]

                intersection = old_attack_objects.keys() & new_attack_objects.keys()
                additions = new_attack_objects.keys() - old_attack_objects.keys()
                deletions = old_attack_objects.keys() - new_attack_objects.keys()

                # sets to store the ids of objects for each section
                major_version_changes = set()
                minor_version_changes = set()
                other_version_changes = set()
                patches = set()
                revocations = set()
                deprecations = set()
                unchanged = set()

                # find changes, revocations and deprecations
                for stix_id in intersection:
                    old_stix_obj = old_attack_objects[stix_id]
                    new_stix_obj = new_attack_objects[stix_id]

                    ddiff = DeepDiff(old_stix_obj, new_stix_obj, ignore_order=True, verbose_level=2)
                    detailed_diff = ddiff.to_json()
                    new_stix_obj["detailed_diff"] = detailed_diff

                    # Check for revocations (skip object if revocation validation fails or already revoked)
                    revocation_result = self._detect_revocation(
                        stix_id, old_stix_obj, new_stix_obj, new_attack_objects, domain
                    )
                    if revocation_result is False:
                        # Revocation validation failed - skip this object entirely (like original 'continue')
                        continue
                    elif revocation_result is True:
                        revocations.add(stix_id)
                        continue
                    elif revocation_result is None and new_stix_obj.get("revoked"):
                        # Object is revoked but was already revoked - skip (matches original if-elif-else behavior)
                        continue

                    # Check for deprecations
                    if self._detect_deprecation(old_stix_obj, new_stix_obj):
                        deprecations.add(stix_id)
                        continue
                    elif new_stix_obj.get("x_mitre_deprecated"):
                        # Object is deprecated but was already deprecated - skip (matches original if-elif-else behavior)
                        continue

                    # Process normal version changes
                    category, old_version, new_version = self._categorize_version_change(
                        stix_id, old_stix_obj, new_stix_obj
                    )

                    if category == "major":
                        major_version_changes.add(stix_id)
                    elif category == "minor":
                        minor_version_changes.add(stix_id)
                    elif category == "other":
                        other_version_changes.add(stix_id)
                    elif category == "patch":
                        patches.add(stix_id)
                    else:
                        unchanged.add(stix_id)

                    if new_version != old_version:
                        new_stix_obj["version_change"] = f"{old_version} → {new_version}"

                    # Process description and relationship changes
                    self._process_description_changes(old_stix_obj, new_stix_obj)
                    self._process_relationship_changes(new_stix_obj, domain)

                #############
                # New objects
                #############
                for stix_id in additions:
                    new_stix_obj = new_attack_objects[stix_id]
                    attack_id = get_attack_id(new_stix_obj)

                    # Add contributions from additions
                    self.update_contributors(old_object=None, new_object=new_stix_obj)

                    # verify version is 1.0
                    x_mitre_version = get_attack_object_version(stix_obj=new_stix_obj)
                    if not version_increment_is_valid(None, x_mitre_version, "additions"):
                        logger.warning(
                            f"{stix_id} - Unexpected new version. Expected 1.0, but is {x_mitre_version}. [{attack_id}] {new_stix_obj['name']}"
                        )

                #################
                # Deleted objects
                #################
                for stix_id in deletions:
                    old_stix_obj = old_attack_objects[stix_id]
                    attack_id = get_attack_id(old_stix_obj)

                #############################
                # Create self.data["changes"]
                #############################
                if obj_type not in self.data["changes"]:
                    self.data["changes"][obj_type] = {}

                # sorted(groupings, key=lambda grouping: grouping["parent"]["name"])
                # sorted(additions, key=lambda stix_object: stix_object["name"])

                self.data["changes"][obj_type][domain] = {
                    "additions": sorted(
                        [new_attack_objects[stix_id] for stix_id in additions],
                        key=lambda stix_object: stix_object["name"],
                    ),
                    "major_version_changes": sorted(
                        [new_attack_objects[stix_id] for stix_id in major_version_changes],
                        key=lambda stix_object: stix_object["name"],
                    ),
                    "minor_version_changes": sorted(
                        [new_attack_objects[stix_id] for stix_id in minor_version_changes],
                        key=lambda stix_object: stix_object["name"],
                    ),
                    "other_version_changes": sorted(
                        [new_attack_objects[stix_id] for stix_id in other_version_changes],
                        key=lambda stix_object: stix_object["name"],
                    ),
                    "patches": sorted(
                        [new_attack_objects[stix_id] for stix_id in patches],
                        key=lambda stix_object: stix_object["name"],
                    ),
                    "revocations": sorted(
                        [new_attack_objects[stix_id] for stix_id in revocations],
                        key=lambda stix_object: stix_object["name"],
                    ),
                    "deprecations": sorted(
                        [new_attack_objects[stix_id] for stix_id in deprecations],
                        key=lambda stix_object: stix_object["name"],
                    ),
                    "deletions": sorted(
                        [old_attack_objects[stix_id] for stix_id in deletions],
                        key=lambda stix_object: stix_object["name"],
                    ),
                }

                # only create unchanged data if we want to display it later
                if self.unchanged:
                    self.data["changes"][obj_type][domain]["unchanged"] = [
                        new_attack_objects[stix_id] for stix_id in unchanged
                    ]

                logger.debug(f"Loaded:  [{domain:17}]/{obj_type}")

    def _collect_related_objects(
        self, stix_id: str, domain: str, relationship_type: str, object_type: str, age: str
    ) -> dict:
        """Collect related objects from relationships.

        Parameters
        ----------
        stix_id : str
            The STIX ID of the technique to find relationships for.
        domain : str
            The ATT&CK domain.
        relationship_type : str
            The type of relationship (e.g., 'mitigations', 'detections').
        object_type : str
            The type of object to collect (e.g., 'mitigations', 'datacomponents').
        age : str
            Either 'old' or 'new' to specify which data version to use.

        Returns
        -------
        dict
            Dictionary of related objects keyed by STIX ID.
        """
        return self._change_detector.collect_related_objects(stix_id, domain, relationship_type, object_type, age)

    def _create_changelog_entry(self, old_items: dict, new_items: dict, formatter: callable = None) -> dict:
        """Create a changelog entry with shared, new, and dropped items.

        Parameters
        ----------
        old_items : dict
            Dictionary of old objects or strings keyed by STIX ID.
        new_items : dict
            Dictionary of new objects or strings keyed by STIX ID.
        formatter : callable, optional
            Function to format item into string. Defaults to "ID: name" format for objects.
            If items are already strings, pass lambda x: x.

        Returns
        -------
        dict
            Dictionary with 'shared', 'new', and 'dropped' keys containing sorted lists.
        """
        return self._change_detector.create_changelog_entry(old_items, new_items, formatter)

    def find_technique_mitigation_changes(self, new_stix_obj: dict, domain: str):
        """Find changes in the relationships between Techniques and Mitigations.

        Parameters
        ----------
        new_stix_obj : dict
            An ATT&CK Technique (attack-pattern) STIX Domain Object (SDO).
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]
        """
        return self._change_detector.find_technique_mitigation_changes(new_stix_obj, domain)

    def _collect_detection_objects(self, stix_id: str, domain: str, age: str) -> tuple[dict[str, str], dict[str, str]]:
        """Collect detection-related objects (datacomponents and detectionstrategies) for a technique.

        Parameters
        ----------
        stix_id : str
            The STIX ID of the technique to find detections for.
        domain : str
            The ATT&CK domain.
        age : str
            Either 'old' or 'new' to specify which data version to use.

        Returns
        -------
        tuple[dict[str, str], dict[str, str]]
            Two dictionaries:
            - datacomponent_detections: formatted detection strings keyed by STIX ID
            - detectionstrategy_detections: formatted detection strings keyed by STIX ID
        """
        return self._change_detector.collect_detection_objects(stix_id, domain, age)

    def find_technique_detection_changes(self, new_stix_obj: dict, domain: str):
        """Find changes in the relationships between Techniques and Datacomponents.

        Parameters
        ----------
        new_stix_obj : dict
            An ATT&CK Technique (attack-pattern) STIX Domain Object (SDO).
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]
        """
        return self._change_detector.find_technique_detection_changes(new_stix_obj, domain)

    def load_domain(self, domain: str):
        """Load data from directory according to domain.

        Parameters
        ----------
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]
        """
        return self._data_loader.load_domain(domain)

    def get_datastore_from_mitre_cti(self, domain: str, datastore_version: str) -> stix2.MemoryStore:
        """Load data from MITRE CTI repo according to domain.

        Parameters
        ----------
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]
        datastore_version : str
            The comparative version of the ATT&CK datastore. Choices are either "old" or "new".

        Returns
        -------
        stix2.MemoryStore
            STIX MemoryStore object representing an ATT&CK domain.
        """
        # Lazy initialization for backward compatibility with tests
        if not hasattr(self, "_data_loader"):
            self._data_loader = DataLoader(self)
        return self._data_loader.get_datastore_from_mitre_cti(domain, datastore_version)

    def parse_extra_data(self, data_store: stix2.MemoryStore, domain: str, datastore_version: str):
        """Parse STIX datastore objects and relationships.

        Parameters
        ----------
        data_store : stix2.MemoryStore
            STIX MemoryStore object representing an ATT&CK domain.
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]
        datastore_version : str
            The comparative version of the ATT&CK datastore. Choices are either "old" or "new".
        """
        return self._data_loader.parse_extra_data(data_store, domain, datastore_version)

    def update_contributors(self, old_object: Optional[dict], new_object: dict):
        """Update contributors list if new object has contributors.

        Parameters
        ----------
        old_object : Optional[dict]
            An ATT&CK STIX Domain Object (SDO).
        new_object : dict
            An ATT&CK STIX Domain Object (SDO).
        """
        self._contributor_tracker.update_contributors(old_object, new_object)

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
        return self._hierarchy_builder.get_groupings(object_type, stix_objects, section, domain)

    def get_contributor_section(self) -> str:
        """Get contributors that are only found in the new STIX data.

        Returns
        -------
        str
            Markdown representation of the contributors found
        """
        return self._contributor_tracker.get_contributor_section()

    def get_parent_stix_object(self, stix_object: dict, datastore_version: str, domain: str) -> dict:
        """Given an ATT&CK STIX object, find and return it's parent STIX object.

        Parameters
        ----------
        stix_object : dict
            An ATT&CK STIX Domain Object (SDO).
        datastore_version : str
            The comparative version of the ATT&CK datastore. Choices are either "old" or "new".
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]

        Returns
        -------
        dict
            The parent STIX object, if one can be found. Otherwise an empty dictionary is returned.
        """
        subtechnique_relationships = self.data[datastore_version][domain]["relationships"]["subtechniques"]
        techniques = self.data[datastore_version][domain]["attack_objects"]["techniques"]
        datasources = self.data[datastore_version][domain]["attack_objects"]["datasources"]

        if stix_object.get("x_mitre_is_subtechnique"):
            for subtechnique_relationship in subtechnique_relationships.values():
                if subtechnique_relationship["source_ref"] == stix_object["id"]:
                    parent_id = subtechnique_relationship["target_ref"]
                    return techniques[parent_id]
        elif stix_object["type"] == "x-mitre-data-component":
            parent_ref = stix_object.get("x_mitre_data_source_ref")
            if parent_ref and parent_ref in datasources:
                return datasources[parent_ref]
            # No parent datasource available for this datacomponent.
            return {}

        # possible reasons for no parent object: deprecated/revoked/wrong object type passed in
        return {}

    def placard(self, stix_object: dict, section: str, domain: str) -> str:
        """Get a section list item for the given STIX Domain Object (SDO) according to section type.

        Parameters
        ----------
        stix_object : dict
            An ATT&CK STIX Domain Object (SDO).
        section : str
            Section change type, e.g major_version_change, revocations, etc.
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]

        Returns
        -------
        str
            Final return string to be displayed in the Changelog.
        """
        return self._markdown_generator.placard(stix_object, section, domain)

    def _collect_domain_statistics(self, datastore: MemoryStore, domain_name: str) -> DomainStatistics:
        """Collect statistics for a single domain from a STIX datastore.

        Parameters
        ----------
        datastore : MemoryStore
            The STIX MemoryStore containing the domain data.
        domain_name : str
            Display name of the domain (e.g., "Enterprise", "Mobile", "ICS").

        Returns
        -------
        DomainStatistics
            Statistics for the domain.
        """
        return self._statistics_collector.collect_domain_statistics(datastore, domain_name)

    def _collect_unique_object_counts(self, datastore_version: str) -> dict[str, int]:
        """Collect counts of unique objects across all domains for a specific version.

        Some objects (Software, Groups, Campaigns) may appear in multiple domains.
        This function counts unique objects to avoid double-counting.

        Parameters
        ----------
        datastore_version : str
            Either "old" or "new" to specify which version's data to analyze.

        Returns
        -------
        dict of str to int
            Counts of unique software, groups, and campaigns.
        """
        return self._statistics_collector.collect_unique_object_counts(datastore_version)

    def get_statistics_section(self, datastore_version: str = "new") -> str:
        """Generate a markdown section with ATT&CK statistics for all domains.

        Parameters
        ----------
        datastore_version : str, optional
            Either "old" or "new" to specify which version's statistics to generate.
            Defaults to "new".

        Returns
        -------
        str
            Markdown-formatted statistics section.
        """
        return self._statistics_collector.generate_statistics_section(datastore_version)

    def get_markdown_section_data(self, groupings, section: str, domain: str) -> str:
        """Parse a list of STIX objects in a section and return a string for the whole section."""
        return self._markdown_generator.get_markdown_section_data(groupings, section, domain)

    def get_md_key(self) -> str:
        """Create string describing each type of difference (change, addition, etc).

        Returns
        -------
        str
            Key for change types used in Markdown output.
        """
        return self._markdown_generator.get_md_key()

    def get_markdown_string(self) -> str:
        """Return a markdown string summarizing detected differences."""
        return self._markdown_generator.generate()

    def get_layers_dict(self):
        """Return ATT&CK Navigator layers in dict format summarizing detected differences.

        Returns a dict mapping domain to its layer dict.
        """
        return self._layer_generator.generate()

    def get_changes_dict(self):
        """Return dict format summarizing detected differences."""
        return self._json_generator.generate()
