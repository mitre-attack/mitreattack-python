"""Main DiffStix class for detecting and summarizing differences between ATT&CK versions."""

from __future__ import annotations

from typing import Dict, List, Optional

import stix2
from loguru import logger
from rich.progress import track
from stix2 import MemoryStore

from mitreattack.diffStix.core.change_detector import ChangeDetector
from mitreattack.diffStix.core.configuration_manager import ConfigurationManager
from mitreattack.diffStix.core.contributor_tracker import ContributorTracker
from mitreattack.diffStix.core.data_loader import DataLoader
from mitreattack.diffStix.core.data_structure_initializer import DataStructureInitializer
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
        self.use_mitre_cti = use_mitre_cti
        self.verbose = verbose
        self.include_contributors = include_contributors

        # Initialize configuration manager for constants and mappings
        self._config = ConfigurationManager()
        self.types = self._config.object_types
        self.domain_to_domain_label = self._config.domain_labels
        self.attack_type_to_title = self._config.type_titles
        self.section_descriptions = self._config.section_descriptions
        self.section_headers = self._config.get_all_section_headers()

        # Initialize contributor tracker for the new release
        self._contributor_tracker = ContributorTracker()

        # Initialize the nested data structure for tracking changes
        # Data gets loaded into here in the load_data() function
        self.data = DataStructureInitializer.create_structure(self.domains, self.types)

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


    def load_data(self):
        """Orchestrate loading STIX data and detecting changes."""
        self._load_all_domains()
        self._detect_all_changes()

    def _load_all_domains(self):
        """Load STIX data for all configured domains."""
        for domain in track(self.domains, description="Loading domains"):
            self._data_loader.load_domain(domain=domain)

    def _detect_all_changes(self):
        """Detect and categorize changes across all domains and object types."""
        for domain in track(self.domains, description="Finding changes by domain"):
            for obj_type in self.types:
                self._detect_changes_for_type(domain, obj_type)

    def _detect_changes_for_type(self, domain: str, obj_type: str):
        """Detect changes for a specific object type within a domain.

        Parameters
        ----------
        domain : str
            ATT&CK domain (e.g., "enterprise-attack")
        obj_type : str
            ATT&CK object type (e.g., "techniques", "software")
        """
        logger.debug(f"Loading: [{domain:17}]/{obj_type}")

        old_attack_objects = self.data["old"][domain]["attack_objects"][obj_type]
        new_attack_objects = self.data["new"][domain]["attack_objects"][obj_type]

        # Categorize objects into sections
        changes = self._categorize_object_changes(old_attack_objects, new_attack_objects, domain, obj_type)

        # Store the categorized changes
        self._store_categorized_changes(domain, obj_type, changes, old_attack_objects, new_attack_objects)

        logger.debug(f"Loaded:  [{domain:17}]/{obj_type}")

    def _categorize_object_changes(self, old_objects: dict, new_objects: dict, domain: str, obj_type: str) -> dict:
        """Categorize all changes for objects in a domain.

        Parameters
        ----------
        old_objects : dict
            Old version objects keyed by STIX ID
        new_objects : dict
            New version objects keyed by STIX ID
        domain : str
            ATT&CK domain
        obj_type : str
            ATT&CK object type

        Returns
        -------
        dict
            Dictionary with sets of STIX IDs for each change category
        """
        from deepdiff import DeepDiff

        intersection = old_objects.keys() & new_objects.keys()
        additions = new_objects.keys() - old_objects.keys()
        deletions = old_objects.keys() - new_objects.keys()

        # Sets to store the IDs of objects for each section
        changes = {
            "additions": additions,
            "deletions": deletions,
            "major_version_changes": set(),
            "minor_version_changes": set(),
            "other_version_changes": set(),
            "patches": set(),
            "revocations": set(),
            "deprecations": set(),
            "unchanged": set(),
        }

        # Process objects that exist in both versions
        for stix_id in intersection:
            old_stix_obj = old_objects[stix_id]
            new_stix_obj = new_objects[stix_id]

            # Calculate detailed diff
            ddiff = DeepDiff(old_stix_obj, new_stix_obj, ignore_order=True, verbose_level=2)
            new_stix_obj["detailed_diff"] = ddiff.to_json()

            # Check for revocations
            revocation_result = self._change_detector.detect_revocation(
                stix_id, old_stix_obj, new_stix_obj, new_objects, domain
            )
            if revocation_result is False:
                continue  # Validation failed - skip
            elif revocation_result is True:
                changes["revocations"].add(stix_id)
                continue
            elif revocation_result is None and new_stix_obj.get("revoked"):
                continue  # Already revoked - skip

            # Check for deprecations
            if self._change_detector.detect_deprecation(old_stix_obj, new_stix_obj):
                changes["deprecations"].add(stix_id)
                continue
            elif new_stix_obj.get("x_mitre_deprecated"):
                continue  # Already deprecated - skip

            # Categorize version changes
            category, old_version, new_version = self._change_detector.categorize_version_change(
                stix_id, old_stix_obj, new_stix_obj
            )

            if category == "major":
                changes["major_version_changes"].add(stix_id)
            elif category == "minor":
                changes["minor_version_changes"].add(stix_id)
            elif category == "other":
                changes["other_version_changes"].add(stix_id)
            elif category == "patch":
                changes["patches"].add(stix_id)
            else:
                changes["unchanged"].add(stix_id)

            if new_version != old_version:
                new_stix_obj["version_change"] = f"{old_version} → {new_version}"

            # Process description and relationship changes
            self._change_detector.process_description_changes(old_stix_obj, new_stix_obj)
            self._change_detector.process_relationship_changes(new_stix_obj, domain)

        # Process new objects
        self._process_additions(changes["additions"], new_objects)

        return changes

    def _process_additions(self, additions: set, new_objects: dict):
        """Process and validate newly added objects.

        Parameters
        ----------
        additions : set
            Set of STIX IDs for new objects
        new_objects : dict
            New version objects keyed by STIX ID
        """
        for stix_id in additions:
            new_stix_obj = new_objects[stix_id]
            attack_id = get_attack_id(new_stix_obj)

            # Add contributions from additions
            self._contributor_tracker.update_contributors(old_object=None, new_object=new_stix_obj)

            # Verify version is 1.0
            x_mitre_version = get_attack_object_version(stix_obj=new_stix_obj)
            if not version_increment_is_valid(None, x_mitre_version, "additions"):
                logger.warning(
                    f"{stix_id} - Unexpected new version. Expected 1.0, but is {x_mitre_version}. [{attack_id}] {new_stix_obj['name']}"
                )

    def _store_categorized_changes(
        self, domain: str, obj_type: str, changes: dict, old_objects: dict, new_objects: dict
    ):
        """Store categorized changes in the data structure.

        Parameters
        ----------
        domain : str
            ATT&CK domain
        obj_type : str
            ATT&CK object type
        changes : dict
            Dictionary with sets of STIX IDs for each change category
        old_objects : dict
            Old version objects keyed by STIX ID
        new_objects : dict
            New version objects keyed by STIX ID
        """
        if obj_type not in self.data["changes"]:
            self.data["changes"][obj_type] = {}

        self.data["changes"][obj_type][domain] = {
            "additions": sorted(
                [new_objects[stix_id] for stix_id in changes["additions"]],
                key=lambda stix_object: stix_object["name"],
            ),
            "major_version_changes": sorted(
                [new_objects[stix_id] for stix_id in changes["major_version_changes"]],
                key=lambda stix_object: stix_object["name"],
            ),
            "minor_version_changes": sorted(
                [new_objects[stix_id] for stix_id in changes["minor_version_changes"]],
                key=lambda stix_object: stix_object["name"],
            ),
            "other_version_changes": sorted(
                [new_objects[stix_id] for stix_id in changes["other_version_changes"]],
                key=lambda stix_object: stix_object["name"],
            ),
            "patches": sorted(
                [new_objects[stix_id] for stix_id in changes["patches"]],
                key=lambda stix_object: stix_object["name"],
            ),
            "revocations": sorted(
                [new_objects[stix_id] for stix_id in changes["revocations"]],
                key=lambda stix_object: stix_object["name"],
            ),
            "deprecations": sorted(
                [new_objects[stix_id] for stix_id in changes["deprecations"]],
                key=lambda stix_object: stix_object["name"],
            ),
            "deletions": sorted(
                [old_objects[stix_id] for stix_id in changes["deletions"]],
                key=lambda stix_object: stix_object["name"],
            ),
        }

        # Only create unchanged data if we want to display it later
        if self.unchanged:
            self.data["changes"][obj_type][domain]["unchanged"] = [
                new_objects[stix_id] for stix_id in changes["unchanged"]
            ]

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
        """Given an ATT&CK STIX object, find and return its parent STIX object.

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
        return self._hierarchy_builder.get_parent_stix_object(stix_object, datastore_version, domain)

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
