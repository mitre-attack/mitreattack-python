"""Main DiffStix class for detecting and summarizing differences between ATT&CK versions."""

from __future__ import annotations

import datetime
import difflib
from typing import Dict, List, Optional

import stix2
from loguru import logger
from rich.progress import track
from stix2 import Filter, MemoryStore

from mitreattack.diffStix.core.contributor_tracker import ContributorTracker
from mitreattack.diffStix.core.domain_statistics import DomainStatistics
from mitreattack.diffStix.core.statistics_collector import StatisticsCollector
from mitreattack.diffStix.formatters.json_generator import JsonGenerator
from mitreattack.diffStix.formatters.layer_generator import LayerGenerator
from mitreattack.diffStix.formatters.markdown_generator import MarkdownGenerator
from mitreattack.diffStix.utils.stix_utils import (
    cleanup_values,
    deep_copy_stix,
    get_attack_id,
    has_subtechniques,
    resolve_datacomponent_parent,
)
from mitreattack.diffStix.utils.url_utils import (
    get_relative_data_component_url,
    get_relative_url_from_stix,
)
from mitreattack.diffStix.utils.version_utils import (
    AttackObjectVersion,
    get_attack_object_version,
    is_major_version_change,
    is_minor_version_change,
    is_other_version_change,
    is_patch_change,
    version_increment_is_valid,
)
from mitreattack.stix20 import MitreAttackData


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

        self.load_data()

        # Initialize components after data is loaded
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
        # Not revoked at all - continue to deprecation/version checking
        if not new_obj.get("revoked"):
            return None

        # Already revoked in old version - not a change, but still revoked
        # Original code would exit the if block and NOT process as version change
        if old_obj.get("revoked"):
            return None

        # Newly revoked - validate the revocation
        if stix_id not in self.data["new"][domain]["relationships"]["revoked-by"]:
            logger.error(f"[{stix_id}] revoked object has no revoked-by relationship")
            return False  # Validation error - skip this object

        revoked_by_key = self.data["new"][domain]["relationships"]["revoked-by"][stix_id][0]["target_ref"]
        if revoked_by_key not in new_attack_objects:
            logger.error(f"{stix_id} revoked by {revoked_by_key}, but {revoked_by_key} not found in new STIX bundle!!")
            return False  # Validation error - skip this object

        revoking_object = new_attack_objects[revoked_by_key]
        new_obj["revoked_by"] = revoking_object
        return True  # Successfully detected new revocation

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
        if not new_obj.get("x_mitre_deprecated"):
            return False

        # If previously deprecated, not a change
        return not old_obj.get("x_mitre_deprecated")

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
        # Verify if there are new contributors on the object
        self.update_contributors(old_object=old_obj, new_object=new_obj)

        old_version = get_attack_object_version(old_obj)
        new_version = get_attack_object_version(new_obj)
        new_obj["previous_version"] = old_version

        if is_major_version_change(old_version=old_version, new_version=new_version):
            return "major", old_version, new_version
        elif is_minor_version_change(old_version=old_version, new_version=new_version):
            return "minor", old_version, new_version
        elif is_other_version_change(old_version=old_version, new_version=new_version):
            attack_id = get_attack_id(new_obj)
            logger.warning(
                f"{stix_id} - Unexpected version increase {old_version} → {new_version}. [{attack_id}] {new_obj['name']}"
            )
            return "other", old_version, new_version
        elif is_patch_change(old_stix_obj=old_obj, new_stix_obj=new_obj):
            return "patch", old_version, new_version
        else:
            return None, old_version, new_version

    def _process_description_changes(self, old_obj: dict, new_obj: dict):
        """Process and store description changes between old and new objects.

        Parameters
        ----------
        old_obj : dict
            The old version of the STIX object.
        new_obj : dict
            The new version of the STIX object.
        """
        if "description" not in old_obj or "description" not in new_obj:
            return

        old_lines = old_obj["description"].replace("\n", " ").splitlines()
        new_lines = new_obj["description"].replace("\n", " ").splitlines()
        old_lines_unique = [line for line in old_lines if line not in new_lines]
        new_lines_unique = [line for line in new_lines if line not in old_lines]

        if old_lines_unique or new_lines_unique:
            html_diff = difflib.HtmlDiff(wrapcolumn=60)
            html_diff._legend = ""  # type: ignore[attr-defined]
            delta = html_diff.make_table(old_lines, new_lines, "Old Description", "New Description")
            new_obj["description_change_table"] = delta

    def _process_relationship_changes(self, new_obj: dict, domain: str):
        """Process relationship changes for attack patterns (techniques).

        Parameters
        ----------
        new_obj : dict
            The new version of the STIX object.
        domain : str
            The ATT&CK domain.
        """
        if new_obj["type"] == "attack-pattern":
            self.find_technique_mitigation_changes(new_obj, domain)
            self.find_technique_detection_changes(new_obj, domain)

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
        related_objects = {}
        all_domain_objects = self.data[age][domain]["attack_objects"][object_type]

        for _, relationship in self.data[age][domain]["relationships"][relationship_type].items():
            if relationship.get("x_mitre_deprecated") or relationship.get("revoked"):
                continue
            if stix_id == relationship["target_ref"]:
                source_ref_id = relationship["source_ref"]
                if source_ref_id in all_domain_objects:
                    related_obj = all_domain_objects[source_ref_id]
                    related_objects[related_obj["id"]] = related_obj

        return related_objects

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
        if formatter is None:
            formatter = lambda obj: f"{get_attack_id(stix_obj=obj)}: {obj['name']}"

        shared = old_items.keys() & new_items.keys()
        brand_new = new_items.keys() - old_items.keys()
        dropped = old_items.keys() - new_items.keys()

        return {
            "shared": sorted([formatter(new_items[stix_id]) for stix_id in shared]),
            "new": sorted([formatter(new_items[stix_id]) for stix_id in brand_new]),
            "dropped": sorted([formatter(old_items[stix_id]) for stix_id in dropped]),
        }

    def find_technique_mitigation_changes(self, new_stix_obj: dict, domain: str):
        """Find changes in the relationships between Techniques and Mitigations.

        Parameters
        ----------
        new_stix_obj : dict
            An ATT&CK Technique (attack-pattern) STIX Domain Object (SDO).
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]
        """
        stix_id = new_stix_obj["id"]

        old_mitigations = self._collect_related_objects(stix_id, domain, "mitigations", "mitigations", "old")
        new_mitigations = self._collect_related_objects(stix_id, domain, "mitigations", "mitigations", "new")

        new_stix_obj["changelog_mitigations"] = self._create_changelog_entry(old_mitigations, new_mitigations)

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
        all_datasources = self.data[age][domain]["attack_objects"]["datasources"]
        all_datacomponents = self.data[age][domain]["attack_objects"]["datacomponents"]
        all_detectionstrategies = self.data[age][domain]["attack_objects"]["detectionstrategies"]

        datacomponent_detections = {}
        detectionstrategy_detections = {}

        for _, detection_relationship in self.data[age][domain]["relationships"]["detections"].items():
            if detection_relationship.get("x_mitre_deprecated") or detection_relationship.get("revoked"):
                continue
            if stix_id == detection_relationship["target_ref"]:
                sourceref_id = detection_relationship["source_ref"]

                # Handle datacomponents with parent datasource resolution
                if sourceref_id in all_datacomponents:
                    datacomponent = all_datacomponents[sourceref_id]
                    datasource_id = datacomponent.get("x_mitre_data_source_ref")
                    if not datasource_id:
                        datasource_id = resolve_datacomponent_parent(datacomponent, all_datasources)

                    if datasource_id and datasource_id in all_datasources:
                        datasource = all_datasources[datasource_id]
                        datasource_attack_id = get_attack_id(stix_obj=datasource)
                        datacomponent_detections[sourceref_id] = (
                            f"{datasource_attack_id}: {datasource['name']} ({datacomponent['name']})"
                        )
                    else:
                        # No parent datasource identified — show standalone
                        datacomponent_detections[sourceref_id] = f"{datacomponent['name']}"

                # Handle detectionstrategies
                if sourceref_id in all_detectionstrategies:
                    detectionstrategy = all_detectionstrategies[sourceref_id]
                    detectionstrategy_attack_id = get_attack_id(stix_obj=detectionstrategy)
                    detectionstrategy_detections[sourceref_id] = (
                        f"{detectionstrategy_attack_id}: {detectionstrategy['name']}"
                    )

        return datacomponent_detections, detectionstrategy_detections

    def find_technique_detection_changes(self, new_stix_obj: dict, domain: str):
        """Find changes in the relationships between Techniques and Datacomponents.

        Parameters
        ----------
        new_stix_obj : dict
            An ATT&CK Technique (attack-pattern) STIX Domain Object (SDO).
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]
        """
        stix_id = new_stix_obj["id"]

        # Collect detection objects from old and new data
        old_datacomponent_detections, old_detectionstrategy_detections = self._collect_detection_objects(
            stix_id, domain, "old"
        )
        new_datacomponent_detections, new_detectionstrategy_detections = self._collect_detection_objects(
            stix_id, domain, "new"
        )

        # Create changelog for datacomponent detections
        new_stix_obj["changelog_datacomponent_detections"] = self._create_changelog_entry(
            old_datacomponent_detections,
            new_datacomponent_detections,
            formatter=lambda obj: obj,  # Already formatted as strings
        )

        # Create changelog for detectionstrategy detections
        new_stix_obj["changelog_detectionstrategy_detections"] = self._create_changelog_entry(
            old_detectionstrategy_detections,
            new_detectionstrategy_detections,
            formatter=lambda obj: obj,  # Already formatted as strings
        )

    def load_domain(self, domain: str):
        """Load data from directory according to domain.

        Parameters
        ----------
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]
        """
        # Import here to avoid circular dependency
        import os

        from mitreattack import release_info

        for datastore_version in ["old", "new"]:
            # only allow github.com/mitre/cti to be used for the old STIX domain
            if self.use_mitre_cti and datastore_version == "old":
                data_store = self.get_datastore_from_mitre_cti(domain=domain, datastore_version=datastore_version)
            else:
                directory = self.old if datastore_version == "old" else self.new
                if directory is None:
                    raise ValueError(
                        f"Directory path for {datastore_version} data cannot be None when not using MITRE CTI"
                    )
                stix_file = os.path.join(directory, f"{domain}.json")

                attack_version = release_info.get_attack_version(domain=domain, stix_file=stix_file)
                self.data[datastore_version][domain]["attack_release_version"] = attack_version

                data_store = MemoryStore()
                data_store.load_from_file(stix_file)

            self.data[datastore_version][domain]["stix_datastore"] = data_store
            self.parse_extra_data(data_store=data_store, domain=domain, datastore_version=datastore_version)

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
        # Import here to avoid circular dependency
        import sys

        import requests
        from requests.adapters import HTTPAdapter, Retry

        from mitreattack import release_info

        error_message = f"Unable to successfully download ATT&CK STIX data from GitHub for {domain}. Please try again."
        s = requests.Session()
        retries = Retry(total=10, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
        s.mount("http", HTTPAdapter(max_retries=retries))
        stix_url = f"https://raw.githubusercontent.com/mitre/cti/master/{domain}/{domain}.json"
        try:
            stix_response = s.get(stix_url, timeout=60)
            if stix_response.status_code != 200:
                logger.error(error_message)
                sys.exit(1)
        except (requests.exceptions.ContentDecodingError, requests.exceptions.JSONDecodeError):
            stix_response = s.get(stix_url, timeout=60)
            if stix_response.status_code != 200:
                logger.error(error_message)
                sys.exit(1)

        stix_json = stix_response.json()
        attack_version = release_info.get_attack_version(domain=domain, stix_content=stix_response.content)
        self.data[datastore_version][domain]["attack_release_version"] = attack_version

        data_store = MemoryStore(stix_data=stix_json["objects"])
        return data_store

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
        # Import here to avoid circular dependency

        attack_type_to_stix_filter = {
            "techniques": [Filter("type", "=", "attack-pattern")],
            "software": [Filter("type", "=", "malware"), Filter("type", "=", "tool")],
            "groups": [Filter("type", "=", "intrusion-set")],
            "campaigns": [Filter("type", "=", "campaign")],
            "assets": [Filter("type", "=", "x-mitre-asset")],
            "mitigations": [Filter("type", "=", "course-of-action")],
            "datasources": [Filter("type", "=", "x-mitre-data-source")],
            "datacomponents": [Filter("type", "=", "x-mitre-data-component")],
            "detectionstrategies": [Filter("type", "=", "x-mitre-detection-strategy")],
            "analytics": [Filter("type", "=", "x-mitre-analytic")],
        }
        for object_type, stix_filters in attack_type_to_stix_filter.items():
            raw_data = []
            for stix_filter in stix_filters:
                temp_filtered_list = data_store.query(stix_filter)
                raw_data.extend(temp_filtered_list)

            raw_data = deep_copy_stix(raw_data)
            self.data[datastore_version][domain]["attack_objects"][object_type] = {
                attack_object["id"]: attack_object for attack_object in raw_data
            }

        subtechnique_relationships = data_store.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "subtechnique-of"),
            ]
        )
        self.data[datastore_version][domain]["relationships"]["subtechniques"] = {
            relationship["id"]: relationship for relationship in subtechnique_relationships
        }

        revoked_by_relationships = data_store.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "revoked-by"),
            ]
        )

        # use list in case STIX object was revoked more than once
        for relationship in revoked_by_relationships:
            source_id = relationship["source_ref"]
            if source_id not in self.data[datastore_version][domain]["relationships"]["revoked-by"]:
                self.data[datastore_version][domain]["relationships"]["revoked-by"][source_id] = []
            self.data[datastore_version][domain]["relationships"]["revoked-by"][source_id].append(relationship)

        mitigating_relationships = data_store.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "mitigates"),
            ]
        )
        self.data[datastore_version][domain]["relationships"]["mitigations"] = {
            relationship["id"]: relationship for relationship in mitigating_relationships
        }

        detection_relationships = data_store.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "detects"),
            ]
        )
        self.data[datastore_version][domain]["relationships"]["detections"] = {
            relationship["id"]: relationship for relationship in detection_relationships
        }

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

        Returns
        -------
        List[Dict[str, object]]
            A list of sorted, complex dictionary objects that tell if this "group" of objects have
            their parent objects in the same section.
        """
        datastore_version = "old" if section == "deletions" else "new"
        subtechnique_relationships = self.data[datastore_version][domain]["relationships"]["subtechniques"]
        techniques = self.data[datastore_version][domain]["attack_objects"]["techniques"]
        datacomponents = self.data[datastore_version][domain]["attack_objects"]["datacomponents"]
        datasources = self.data[datastore_version][domain]["attack_objects"]["datasources"]

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
