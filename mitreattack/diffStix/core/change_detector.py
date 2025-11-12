"""Change detector for analyzing differences between STIX object versions."""

import difflib
from typing import Dict

from loguru import logger

from mitreattack.diffStix.utils.stix_utils import get_attack_id, resolve_datacomponent_parent
from mitreattack.diffStix.utils.version_utils import (
    AttackObjectVersion,
    get_attack_object_version,
    is_major_version_change,
    is_minor_version_change,
    is_other_version_change,
    is_patch_change,
)


class ChangeDetector:
    """Detects and categorizes changes between old and new versions of STIX objects."""

    def __init__(self, diff_stix_instance):
        """Initialize ChangeDetector with a DiffStix instance.

        Parameters
        ----------
        diff_stix_instance : DiffStix
            The DiffStix instance containing data and helper methods
        """
        self.diff_stix = diff_stix_instance

    def detect_revocation(self, stix_id: str, old_obj: dict, new_obj: dict, new_attack_objects: dict, domain: str):
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
        if stix_id not in self.diff_stix.data["new"][domain]["relationships"]["revoked-by"]:
            logger.error(f"[{stix_id}] revoked object has no revoked-by relationship")
            return False  # Validation error - skip this object

        revoked_by_key = self.diff_stix.data["new"][domain]["relationships"]["revoked-by"][stix_id][0]["target_ref"]
        if revoked_by_key not in new_attack_objects:
            logger.error(f"{stix_id} revoked by {revoked_by_key}, but {revoked_by_key} not found in new STIX bundle!!")
            return False  # Validation error - skip this object

        revoking_object = new_attack_objects[revoked_by_key]
        new_obj["revoked_by"] = revoking_object
        return True  # Successfully detected new revocation

    def detect_deprecation(self, old_obj: dict, new_obj: dict) -> bool:
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

    def categorize_version_change(
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
        self.diff_stix.update_contributors(old_object=old_obj, new_object=new_obj)

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

    def process_description_changes(self, old_obj: dict, new_obj: dict):
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

    def process_relationship_changes(self, new_obj: dict, domain: str):
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

    def collect_related_objects(
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
        all_domain_objects = self.diff_stix.data[age][domain]["attack_objects"][object_type]

        for _, relationship in self.diff_stix.data[age][domain]["relationships"][relationship_type].items():
            if relationship.get("x_mitre_deprecated") or relationship.get("revoked"):
                continue
            if stix_id == relationship["target_ref"]:
                source_ref_id = relationship["source_ref"]
                if source_ref_id in all_domain_objects:
                    related_obj = all_domain_objects[source_ref_id]
                    related_objects[related_obj["id"]] = related_obj

        return related_objects

    def create_changelog_entry(self, old_items: dict, new_items: dict, formatter: callable = None) -> dict:
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

        old_mitigations = self.collect_related_objects(stix_id, domain, "mitigations", "mitigations", "old")
        new_mitigations = self.collect_related_objects(stix_id, domain, "mitigations", "mitigations", "new")

        new_stix_obj["changelog_mitigations"] = self.create_changelog_entry(old_mitigations, new_mitigations)

    def collect_detection_objects(self, stix_id: str, domain: str, age: str) -> tuple[dict[str, str], dict[str, str]]:
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
        all_datasources = self.diff_stix.data[age][domain]["attack_objects"]["datasources"]
        all_datacomponents = self.diff_stix.data[age][domain]["attack_objects"]["datacomponents"]
        all_detectionstrategies = self.diff_stix.data[age][domain]["attack_objects"]["detectionstrategies"]

        datacomponent_detections = {}
        detectionstrategy_detections = {}

        for _, detection_relationship in self.diff_stix.data[age][domain]["relationships"]["detections"].items():
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
        old_datacomponent_detections, old_detectionstrategy_detections = self.collect_detection_objects(
            stix_id, domain, "old"
        )
        new_datacomponent_detections, new_detectionstrategy_detections = self.collect_detection_objects(
            stix_id, domain, "new"
        )

        # Create changelog for datacomponent detections
        new_stix_obj["changelog_datacomponent_detections"] = self.create_changelog_entry(
            old_datacomponent_detections,
            new_datacomponent_detections,
            formatter=lambda obj: obj,  # Already formatted as strings
        )

        # Create changelog for detectionstrategy detections
        new_stix_obj["changelog_detectionstrategy_detections"] = self.create_changelog_entry(
            old_detectionstrategy_detections,
            new_detectionstrategy_detections,
            formatter=lambda obj: obj,  # Already formatted as strings
        )
