"""A helper script to generate changelogs between different versions of ATT&CK."""

import argparse
import datetime
import difflib
import json
import os
import re
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import markdown
import requests
import stix2
from dateutil import parser as dateparser
from deepdiff import DeepDiff
from loguru import logger
from requests.adapters import HTTPAdapter, Retry
from rich.progress import track
from stix2 import Filter, MemoryStore
from tqdm import tqdm

from mitreattack import release_info

# explanation of modification types to data objects for legend in layer files
date = datetime.datetime.today()
this_month = date.strftime("%B_%Y")
layer_defaults = [
    os.path.join("output", f"{this_month}_Updates_Enterprise.json"),
    os.path.join("output", f"{this_month}_Updates_Mobile.json"),
    os.path.join("output", f"{this_month}_Updates_ICS.json"),
    os.path.join("output", f"{this_month}_Updates_Pre.json"),
]


@dataclass
class AttackObjectVersion:
    """An ATT&CK object version."""

    major: int
    minor: int

    def __repr__(self):
        return f"{self.major}.{self.minor}"


# TODO: Implement a custom decoder as well. Possible solution at this link
# https://alexisgomes19.medium.com/custom-json-encoder-with-python-f52c91b48cd2
class AttackChangesEncoder(json.JSONEncoder):
    """Custom JSON encoder for changes made to ATT&CK between releases."""

    def default(self, obj):
        """Handle custom object types so they can be serialized to JSON."""
        if isinstance(obj, AttackObjectVersion):
            return str(obj)

        return json.JSONEncoder.default(self, obj)


class DiffStix(object):
    """Utilities for detecting and summarizing differences between two versions of the ATT&CK content."""

    def __init__(
        self,
        domains: List[str] = ["enterprise-attack", "mobile-attack", "ics-attack"],
        layers: List[str] = None,
        unchanged: bool = False,
        old: str = "old",
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
        self.domains = domains
        self.layers = layers
        self.unchanged = unchanged
        self.old = old
        self.new = new
        self.show_key = show_key
        self.site_prefix = site_prefix
        self.types = ["techniques", "software", "groups", "campaigns", "assets", "mitigations", "datasources", "datacomponents"]
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

        # will hold information of contributors of the new release {... {"contributor_credit/name_as_key": counter]} ...}
        self.release_contributors = {}

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

    def load_data(self):
        """Load data from files into data dict."""
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
                    attack_id = get_attack_id(new_stix_obj)

                    ddiff = DeepDiff(old_stix_obj, new_stix_obj, ignore_order=True, verbose_level=2)
                    detailed_diff = ddiff.to_json()
                    new_stix_obj["detailed_diff"] = detailed_diff

                    ########################################
                    # Newly revoked objects
                    ########################################
                    if new_stix_obj.get("revoked"):
                        # only work with newly revoked objects
                        if not old_stix_obj.get("revoked"):
                            if stix_id not in self.data["new"][domain]["relationships"]["revoked-by"]:
                                logger.error(f"[{stix_id}] revoked object has no revoked-by relationship")
                                continue

                            revoked_by_key = self.data["new"][domain]["relationships"]["revoked-by"][stix_id][0][
                                "target_ref"
                            ]
                            if revoked_by_key not in new_attack_objects:
                                logger.error(
                                    f"{stix_id} revoked by {revoked_by_key}, but {revoked_by_key} not found in new STIX bundle!!"
                                )
                                continue

                            revoking_object = new_attack_objects[revoked_by_key]
                            new_stix_obj["revoked_by"] = revoking_object

                            revocations.add(stix_id)

                    ##########################
                    # Newly deprecated objects
                    ##########################
                    elif new_stix_obj.get("x_mitre_deprecated"):
                        # if previously deprecated, not a change
                        if not old_stix_obj.get("x_mitre_deprecated"):
                            deprecations.add(stix_id)

                    #############################################################
                    # Objects shared between old and new STIX bundles by STIX IDs
                    #############################################################
                    else:
                        # Verify if there are new contributors on the object
                        self.update_contributors(old_object=old_stix_obj, new_object=new_stix_obj)

                        old_version = get_attack_object_version(old_stix_obj)
                        new_version = get_attack_object_version(new_stix_obj)
                        new_stix_obj["previous_version"] = old_version

                        if is_major_version_change(old_version=old_version, new_version=new_version):
                            major_version_changes.add(stix_id)
                        elif is_minor_version_change(old_version=old_version, new_version=new_version):
                            minor_version_changes.add(stix_id)
                        elif is_other_version_change(old_version=old_version, new_version=new_version):
                            logger.warning(
                                f"{stix_id} - Unexpected version increase {old_version} → {new_version}. [{attack_id}] {new_stix_obj['name']}"
                            )
                            other_version_changes.add(stix_id)
                        elif is_patch_change(old_stix_obj=old_stix_obj, new_stix_obj=new_stix_obj):
                            patches.add(stix_id)
                        else:
                            unchanged.add(stix_id)

                        if new_version != old_version:
                            new_stix_obj["version_change"] = f"{old_version} → {new_version}"

                        # Description changes
                        #####################
                        old_lines = old_stix_obj["description"].replace("\n", " ").splitlines()
                        new_lines = new_stix_obj["description"].replace("\n", " ").splitlines()
                        old_lines_unique = [line for line in old_lines if line not in new_lines]
                        new_lines_unique = [line for line in new_lines if line not in old_lines]
                        if old_lines_unique or new_lines_unique:
                            html_diff = difflib.HtmlDiff(wrapcolumn=60)
                            html_diff._legend = ""
                            delta = html_diff.make_table(old_lines, new_lines, "Old Description", "New Description")
                            new_stix_obj["description_change_table"] = delta

                        # Relationship changes
                        ######################
                        if new_stix_obj["type"] == "attack-pattern":
                            self.find_technique_mitigation_changes(new_stix_obj, domain)
                            self.find_technique_detection_changes(new_stix_obj, domain)

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
        all_old_domain_mitigations = self.data["old"][domain]["attack_objects"]["mitigations"]
        all_new_domain_mitigations = self.data["new"][domain]["attack_objects"]["mitigations"]
        old_mitigations = {}
        new_mitigations = {}

        for _, mitigation_relationship in self.data["old"][domain]["relationships"]["mitigations"].items():
            if mitigation_relationship.get("x_mitre_deprecated") or mitigation_relationship.get("revoked"):
                continue
            if stix_id == mitigation_relationship["target_ref"]:
                old_mitigation_id = mitigation_relationship["source_ref"]
                old_mitigation = all_old_domain_mitigations[old_mitigation_id]
                old_mitigations[old_mitigation["id"]] = old_mitigation

        for _, mitigation_relationship in self.data["new"][domain]["relationships"]["mitigations"].items():
            if mitigation_relationship.get("x_mitre_deprecated") or mitigation_relationship.get("revoked"):
                continue
            if stix_id == mitigation_relationship["target_ref"]:
                new_mitigation_id = mitigation_relationship["source_ref"]
                new_mitigation = all_new_domain_mitigations[new_mitigation_id]
                new_mitigations[new_mitigation["id"]] = new_mitigation

        shared_mitigations = old_mitigations.keys() & new_mitigations.keys()
        brand_new_mitigations = new_mitigations.keys() - old_mitigations.keys()
        dropped_mitigations = old_mitigations.keys() - new_mitigations.keys()

        new_stix_obj["changelog_mitigations"] = {
            "shared": sorted(
                [
                    f"{get_attack_id(stix_obj=new_mitigations[stix_id])}: {new_mitigations[stix_id]['name']}"
                    for stix_id in shared_mitigations
                ]
            ),
            "new": sorted(
                [
                    f"{get_attack_id(stix_obj=new_mitigations[stix_id])}: {new_mitigations[stix_id]['name']}"
                    for stix_id in brand_new_mitigations
                ]
            ),
            "dropped": sorted(
                [
                    f"{get_attack_id(stix_obj=old_mitigations[stix_id])}: {old_mitigations[stix_id]['name']}"
                    for stix_id in dropped_mitigations
                ]
            ),
        }

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
        all_old_domain_datasources = self.data["old"][domain]["attack_objects"]["datasources"]
        all_old_domain_datacomponents = self.data["old"][domain]["attack_objects"]["datacomponents"]
        all_new_domain_datasources = self.data["new"][domain]["attack_objects"]["datasources"]
        all_new_domain_datacomponents = self.data["new"][domain]["attack_objects"]["datacomponents"]
        old_detections = {}
        new_detections = {}

        for _, detection_relationship in self.data["old"][domain]["relationships"]["detections"].items():
            if detection_relationship.get("x_mitre_deprecated") or detection_relationship.get("revoked"):
                continue
            if stix_id == detection_relationship["target_ref"]:
                old_datacomponent_id = detection_relationship["source_ref"]
                old_datacomponent = all_old_domain_datacomponents[old_datacomponent_id]
                old_datasource_id = old_datacomponent["x_mitre_data_source_ref"]
                old_datasource = all_old_domain_datasources[old_datasource_id]
                old_datasource_attack_id = get_attack_id(stix_obj=old_datasource)
                old_detections[
                    old_datacomponent_id
                ] = f"{old_datasource_attack_id}: {old_datasource['name']} ({old_datacomponent['name']})"

        for _, detection_relationship in self.data["new"][domain]["relationships"]["detections"].items():
            if detection_relationship.get("x_mitre_deprecated") or detection_relationship.get("revoked"):
                continue
            if stix_id == detection_relationship["target_ref"]:
                new_datacomponent_id = detection_relationship["source_ref"]
                new_datacomponent = all_new_domain_datacomponents[new_datacomponent_id]
                new_datasource_id = new_datacomponent["x_mitre_data_source_ref"]
                new_datasource = all_new_domain_datasources[new_datasource_id]
                new_datasource_attack_id = get_attack_id(stix_obj=new_datasource)
                new_detections[
                    new_datacomponent_id
                ] = f"{new_datasource_attack_id}: {new_datasource['name']} ({new_datacomponent['name']})"

        shared_detections = old_detections.keys() & new_detections.keys()
        brand_new_detections = new_detections.keys() - old_detections.keys()
        dropped_detections = old_detections.keys() - new_detections.keys()

        new_stix_obj["changelog_detections"] = {
            "shared": sorted([f"{new_detections[stix_id]}" for stix_id in shared_detections]),
            "new": sorted([f"{new_detections[stix_id]}" for stix_id in brand_new_detections]),
            "dropped": sorted([f"{old_detections[stix_id]}" for stix_id in dropped_detections]),
        }

    def load_domain(self, domain: str):
        """Load data from directory according to domain.

        Parameters
        ----------
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]
        """
        for datastore_version in ["old", "new"]:
            # only allow github.com/mitre/cti to be used for the old STIX domain
            if self.use_mitre_cti and datastore_version == "old":
                data_store = self.get_datastore_from_mitre_cti(domain=domain, datastore_version=datastore_version)
            else:
                directory = self.old if datastore_version == "old" else self.new
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
        attack_type_to_stix_filter = {
            "techniques": [Filter("type", "=", "attack-pattern")],
            "software": [Filter("type", "=", "malware"), Filter("type", "=", "tool")],
            "groups": [Filter("type", "=", "intrusion-set")],
            "campaigns": [Filter("type", "=", "campaign")],
            "assets": [Filter("type", "=", "x-mitre-asset")],
            "mitigations": [Filter("type", "=", "course-of-action")],
            "datasources": [Filter("type", "=", "x-mitre-data-source")],
            "datacomponents": [Filter("type", "=", "x-mitre-data-component")],
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
        if new_object.get("x_mitre_contributors"):
            new_object_contributors = set(new_object["x_mitre_contributors"])

            # Check if old objects had contributors
            if old_object is None or not old_object.get("x_mitre_contributors"):
                old_object_contributors = set()
            else:
                old_object_contributors = set(old_object["x_mitre_contributors"])

            # Remove old contributors from showing up
            # if contributors are the same the result will be empty
            new_contributors = new_object_contributors - old_object_contributors

            # Update counter of contributor to track contributions
            for new_contributor in new_contributors:
                if self.release_contributors.get(new_contributor):
                    self.release_contributors[new_contributor] += 1
                else:
                    self.release_contributors[new_contributor] = 1

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

            parent_datasource_id = datacomponent["x_mitre_data_source_ref"]
            the_datacomponent = children[datacomponent["id"]]
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
        contribSection = "## Contributors to this release\n\n"
        sorted_contributors = sorted(self.release_contributors, key=lambda v: v.lower())

        for contributor in sorted_contributors:
            # do not include ATT&CK as contributor
            if contributor == "ATT&CK":
                continue
            contribSection += f"* {contributor}\n"

        return contribSection

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
            return datasources[stix_object.get("x_mitre_data_source_ref")]

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
        datastore_version = "old" if section == "deletions" else "new"

        if section == "deletions":
            placard_string = stix_object["name"]

        elif section == "revocations":
            revoker = stix_object["revoked_by"]

            if revoker.get("x_mitre_is_subtechnique"):
                parent_object = self.get_parent_stix_object(
                    stix_object=revoker, datastore_version=datastore_version, domain=domain
                )
                parent_name = parent_object.get("name", "ERROR NO PARENT")
                relative_url = get_relative_url_from_stix(stix_object=revoker)
                revoker_link = f"{self.site_prefix}/{relative_url}"
                placard_string = (
                    f"{stix_object['name']} (revoked by {parent_name}: [{revoker['name']}]({revoker_link}))"
                )

            elif revoker["type"] == "x-mitre-data-component":
                parent_object = self.get_parent_stix_object(
                    stix_object=revoker, datastore_version=datastore_version, domain=domain
                )
                parent_name = parent_object.get("name", "ERROR NO PARENT")
                relative_url = get_relative_data_component_url(datasource=parent_object, datacomponent=stix_object)
                revoker_link = f"{self.site_prefix}/{relative_url}"
                placard_string = (
                    f"{stix_object['name']} (revoked by {parent_name}: [{revoker['name']}]({revoker_link}))"
                )

            else:
                relative_url = get_relative_url_from_stix(stix_object=revoker)
                revoker_link = f"{self.site_prefix}/{relative_url}"
                placard_string = f"{stix_object['name']} (revoked by [{revoker['name']}]({revoker_link}))"

        else:
            if stix_object["type"] == "x-mitre-data-component":
                parent_object = self.get_parent_stix_object(
                    stix_object=stix_object, datastore_version=datastore_version, domain=domain
                )
                if parent_object:
                    relative_url = get_relative_data_component_url(datasource=parent_object, datacomponent=stix_object)
                    placard_string = f"[{stix_object['name']}]({self.site_prefix}/{relative_url})"

            else:
                relative_url = get_relative_url_from_stix(stix_object=stix_object)
                placard_string = f"[{stix_object['name']}]({self.site_prefix}/{relative_url})"

        version_string = get_placard_version_string(stix_object=stix_object, section=section)
        full_placard_string = f"{placard_string} {version_string}"
        return full_placard_string

    def get_markdown_section_data(self, groupings, section: str, domain: str) -> str:
        """Parse a list of STIX objects in a section and return a string for the whole section."""
        sectionString = ""
        for grouping in groupings:
            if grouping["parentInSection"]:
                placard_string = self.placard(stix_object=grouping["parent"], section=section, domain=domain)
                sectionString += f"* {placard_string}\n"

            for child in sorted(grouping["children"], key=lambda child: child["name"]):
                placard_string = self.placard(stix_object=child, section=section, domain=domain)

                if grouping["parentInSection"]:
                    sectionString += f"    * {placard_string}\n"
                else:
                    sectionString += f"* {grouping['parent']['name']}: {placard_string}\n"

        return sectionString

    def get_md_key(self) -> str:
        """Create string describing each type of difference (change, addition, etc).

        Returns
        -------
        str
            Key for change types used in Markdown output.
        """
        # end first line with \ to avoid the empty line from dedent()
        key = textwrap.dedent(
            f"""\
            ## Key

            * New objects: {self.section_descriptions["additions"]}
            * Major version changes: {self.section_descriptions["major_version_changes"]}
            * Minor version changes: {self.section_descriptions["minor_version_changes"]}
            * Other version changes: {self.section_descriptions["other_version_changes"]}
            * Patches: {self.section_descriptions["patches"]}
            * Object revocations: {self.section_descriptions["revocations"]}
            * Object deprecations: {self.section_descriptions["deprecations"]}
            * Object deletions: {self.section_descriptions["deletions"]}
            """
        )

        return key

    def get_markdown_string(self):
        """Return a markdown string summarizing detected differences."""
        logger.info("Generating markdown output")
        content = ""

        if self.show_key:
            key_content = self.get_md_key()
            content = f"{key_content}\n\n"

        for object_type in self.types:
            domains = ""

            for domain in self.data["changes"][object_type]:
                # e.g "Enterprise"
                domains += f"### {self.domain_to_domain_label[domain]}\n\n"
                # Skip mobile section for data sources
                if domain == "mobile-attack" and object_type == "datasource":
                    logger.debug("Skipping - ATT&CK for Mobile does not support data sources")
                    domains += "ATT&CK for Mobile does not support data sources\n\n"
                    continue
                domain_sections = ""
                for section, stix_objects in self.data["changes"][object_type][domain].items():
                    header = f"#### {self.section_headers[object_type][section]}"
                    if stix_objects:
                        groupings = self.get_groupings(
                            object_type=object_type,
                            stix_objects=stix_objects,
                            section=section,
                            domain=domain,
                        )
                        section_items = self.get_markdown_section_data(
                            groupings=groupings, section=section, domain=domain
                        )
                        domain_sections += f"{header}\n\n{section_items}\n"

                # add domain sections
                domains += f"{domain_sections}"

            # e.g "techniques"
            content += f"## {self.attack_type_to_title[object_type]}\n\n{domains}"

        # Add contributors if requested by argument
        if self.include_contributors:
            content += self.get_contributor_section()

        return content

    def get_layers_dict(self):
        """Return ATT&CK Navigator layers in dict format summarizing detected differences.

        Returns a dict mapping domain to its layer dict.
        """
        logger.info("Generating ATT&CK Navigator layers")

        colors = {
            "additions": "#a1d99b",  # granny smith apple
            "major_version_changes": "#fcf3a2",  # yellow-ish
            "minor_version_changes": "#c7c4e0",  # light periwinkle
            "other_version_changes": "#B5E5CF",  # mint
            "patches": "#B99095",  # mauve
            "deletions": "#ff00e1",  # hot magenta
            "revocations": "#ff9000",  # dark orange
            "deprecations": "#ff6363",  # bittersweet red
            "unchanged": "#ffffff",  # white
        }

        layers = {}
        thedate = datetime.datetime.today().strftime("%B %Y")
        # for each layer file in the domains mapping
        for domain in self.domains:
            logger.debug(f"Generating ATT&CK Navigator layer for domain: {domain}")
            # build techniques list
            techniques = []
            for section, technique_stix_objects in self.data["changes"]["techniques"][domain].items():
                if section == "revocations" or section == "deprecations":
                    continue

                for technique in technique_stix_objects:
                    problem_detected = False
                    if "kill_chain_phases" not in technique:
                        logger.error(f"{technique['id']}: technique missing a tactic!! {technique['name']}")
                        problem_detected = True
                    if "external_references" not in technique:
                        logger.error(f"{technique['id']}: technique missing external references!! {technique['name']}")
                        problem_detected = True

                    if problem_detected:
                        continue

                    for phase in technique["kill_chain_phases"]:
                        techniques.append(
                            {
                                "techniqueID": technique["external_references"][0]["external_id"],
                                "tactic": phase["phase_name"],
                                "enabled": True,
                                "color": colors[section],
                                # trim the 's' off end of word
                                "comment": section[:-1] if section != "unchanged" else section,
                            }
                        )

            legendItems = []
            for section, description in self.section_descriptions.items():
                legendItems.append({"color": colors[section], "label": f"{section}: {description}"})

            # build layer structure
            layer_json = {
                "versions": {
                    "layer": "4.5",
                    "navigator": "5.0.0",
                    "attack": self.data["new"][domain]["attack_release_version"],
                },
                "name": f"{thedate} {self.domain_to_domain_label[domain]} Updates",
                "description": f"{self.domain_to_domain_label[domain]} updates for the {thedate} release of ATT&CK",
                "domain": domain,
                "techniques": techniques,
                "sorting": 0,
                "hideDisabled": False,
                "legendItems": legendItems,
                "showTacticRowBackground": True,
                "tacticRowBackground": "#205b8f",
                "selectTechniquesAcrossTactics": True,
            }
            layers[domain] = layer_json

        return layers

    def get_changes_dict(self):
        """Return dict format summarizing detected differences."""
        logger.info("Generating changes info")

        changes_dict = {}
        for domain in self.domains:
            changes_dict[domain] = {}

        for object_type, domains in self.data["changes"].items():
            for domain, sections in domains.items():
                changes_dict[domain][object_type] = {}

                for section, stix_objects in sections.items():
                    groupings = self.get_groupings(
                        object_type=object_type,
                        stix_objects=stix_objects,
                        section=section,
                        domain=domain,
                    )
                    # new_values includes parents & children mixed
                    # (e.g. techniques/sub-techniques, data sources/components)
                    new_values = cleanup_values(groupings=groupings)
                    changes_dict[domain][object_type][section] = new_values

        # always add contributors
        changes_dict["new-contributors"] = []
        sorted_contributors = sorted(self.release_contributors, key=lambda v: v.lower())
        for contributor in sorted_contributors:
            # do not include ATT&CK as contributor
            if contributor == "ATT&CK":
                continue
            changes_dict["new-contributors"].append(contributor)

        return changes_dict


def has_subtechniques(stix_object: dict, subtechnique_relationships: List[dict]) -> bool:
    """Return true or false depending on whether the SDO has sub-techniques.

    Parameters
    ----------
    stix_object : dict
        An ATT&CK STIX Domain Object (SDO).
    subtechnique_relationships : List[dict]
        List of STIX Relationship Object (SRO) dictionaries.

    Returns
    -------
    bool
        Returns True if the stix_object has Subtechniques.
    """
    for relationship in subtechnique_relationships.values():
        if relationship["target_ref"] == stix_object["id"]:
            return True

    return False


def get_placard_version_string(stix_object: dict, section: str) -> str:
    """Get the HTML version representation of the ATT&CK STIX object.

    Parameters
    ----------
    stix_object : dict
        An ATT&CK STIX Domain Object (SDO).
    section : str
        Section change type, e.g major_version_change, revocations, etc.

    Returns
    -------
    str
        Final HTML representation of what the version change looks like.
    """
    gray = "#929393"
    red = "#eb6635"
    color = gray

    object_version = get_attack_object_version(stix_obj=stix_object)
    version_display = f"(v{object_version})"

    if section in ["additions", "deprecations", "revocations"]:
        # only display current version
        if not version_increment_is_valid(old_version=None, new_version=object_version, section=section):
            color = red

    elif section == "deletions":
        color = red

    # nothing needs to be added to this statement - it just needs to skip the 'else' clause
    elif section == "patches":
        pass

    else:
        # the "previous_version" key was added in the load_data() function
        old_version = stix_object.get("previous_version")
        if not version_increment_is_valid(old_version=old_version, new_version=object_version, section=section):
            color = red
        version_display = f"(v{old_version}&#8594;v{object_version})"

    return f'<small style="color:{color}">{version_display}</small>'


def cleanup_values(groupings: List[dict]) -> List[dict]:
    """Clean the values found in the initial groupings of ATT&CK Objects.

    Parameters
    ----------
    groupings : List[dict]
        Whatever comes out of DiffStix.get_groupings()

    Returns
    -------
    List[dict]
        A cleaned up version of groupings.
    """
    new_values = []
    for grouping in groupings:
        if grouping["parentInSection"]:
            new_values.append(grouping["parent"])

        for child in sorted(grouping["children"], key=lambda child: child["name"]):
            new_values.append(child)

    return new_values


def version_increment_is_valid(
    old_version: AttackObjectVersion, new_version: AttackObjectVersion, section: str
) -> bool:
    """Validate version increment between old and new STIX objects.

    Valid increments include the following:

        * Major version increases: e.g. 1.2 → 2.0
        * Minor version increases: e.g. 1.2 → 1.3
        * New version for new objects must be 1.0
        * Any value when section is "revocations" or "deprecations"

    Parameters
    ----------
    old_version : AttackObjectVersion
        Old version of an ATT&CK STIX Domain Object (SDO).
    new_version : AttackObjectVersion
        New version of an ATT&CK STIX Domain Object (SDO).
    section : str
        Section change type, e.g major_version_change, revocations, etc.

    Returns
    -------
    bool
        Returns True when a valid version increment is found
    """
    if section in ["revocations", "deprecations"]:
        return True
    if section == "additions":
        if new_version != AttackObjectVersion(major=1, minor=0):
            return False
        return True
    if not (old_version and new_version):
        return False

    major_change = is_major_version_change(old_version=old_version, new_version=new_version)
    minor_change = is_minor_version_change(old_version=old_version, new_version=new_version)

    if major_change or minor_change:
        return True
    return False


def is_major_version_change(old_version: AttackObjectVersion, new_version: AttackObjectVersion) -> bool:
    """Determine if the new version is a major change."""
    next_major_num = old_version.major + 1
    next_major_version = AttackObjectVersion(major=next_major_num, minor=0)
    if new_version == next_major_version:
        return True
    return False


def is_minor_version_change(old_version: AttackObjectVersion, new_version: AttackObjectVersion) -> bool:
    """Determine if the new version is a minor change."""
    next_minor_num = old_version.minor + 1
    next_minor_version = AttackObjectVersion(major=old_version.major, minor=next_minor_num)
    if new_version == next_minor_version:
        return True
    return False


def is_other_version_change(old_version: AttackObjectVersion, new_version: AttackObjectVersion) -> bool:
    """Determine if the new version is an unexpected change."""
    # either stayed the same or was a normal version change
    if is_major_version_change(old_version=old_version, new_version=new_version):
        return False
    elif is_minor_version_change(old_version=old_version, new_version=new_version):
        return False
    elif (old_version.major == new_version.major) and (old_version.minor == new_version.minor):
        return False

    # Possible scenarios
    # * went up by more than 0.1, but not next major version
    # * version number went down
    return True


def is_patch_change(old_stix_obj: dict, new_stix_obj: dict) -> bool:
    """Determine if ATT&CK Object changes are considered a patch change.

    Parameters
    ----------
    old_stix_obj : dict
        Old ATT&CK STIX Domain Object (SDO).
    new_stix_obj : dict
        New ATT&CK STIX Domain Object (SDO).

    Returns
    -------
    bool
        True if the object changed in such a way as to only be considered a patch change.
    """
    stix_id = new_stix_obj["id"]
    attack_id = get_attack_id(new_stix_obj)

    # Version stayed the same, but the modified date changed
    old_version = get_attack_object_version(old_stix_obj)
    new_version = get_attack_object_version(new_stix_obj)
    if new_version == old_version:
        old_date = dateparser.parse(old_stix_obj["modified"])
        new_date = dateparser.parse(new_stix_obj["modified"])
        if new_date != old_date:
            return True

    # description changed, even though modified date didn't
    old_lines = old_stix_obj["description"].replace("\n", " ").splitlines()
    new_lines = new_stix_obj["description"].replace("\n", " ").splitlines()
    old_lines_unique = [line for line in old_lines if line not in new_lines]
    new_lines_unique = [line for line in new_lines if line not in old_lines]
    if old_lines_unique or new_lines_unique:
        logger.warning(
            f"{stix_id} - {attack_id} has a description change "
            "without the version being incremented or the last modified date changing"
        )
        return True

    # doesn't meet the definintion of a patch change
    return False


def get_relative_url_from_stix(stix_object: dict) -> Optional[str]:
    """Parse the website url from a stix object.

    Parameters
    ----------
    stix_object : dict
        An ATT&CK STIX Domain Object (SDO).

    Returns
    -------
    Optional[str]
        The relative URL for the ATT&CK object.
    """
    is_subtechnique = stix_object["type"] == "attack-pattern" and stix_object.get("x_mitre_is_subtechnique")

    if stix_object.get("external_references"):
        url = stix_object["external_references"][0]["url"]
        split_url = url.split("/")
        splitfrom = -3 if is_subtechnique else -2
        link = "/".join(split_url[splitfrom:])
        return link
    return None


def get_relative_data_component_url(datasource: dict, datacomponent: dict) -> str:
    """Create url of data component with parent data source."""
    return f"{get_relative_url_from_stix(stix_object=datasource)}/#{'%20'.join(datacomponent['name'].split(' '))}"


def deep_copy_stix(stix_objects: List[dict]) -> List[dict]:
    """Transform STIX to dict and deep copy the dict.

    Parameters
    ----------
    stix_objects : List[dict]
        A list of Python dictionaries of ATT&CK STIX Domain Objects.

    Returns
    -------
    List[dict]
        A slightly easier to work with list of Python dictionaries of ATT&CK STIX Domain Objects.
    """
    result = []
    for stix_object in stix_objects:
        # TODO: serialize the STIX objects instead of casting them to dict
        # more details here: https://github.com/mitre/cti/issues/17#issuecomment-395768815
        stix_object = dict(stix_object)
        if "external_references" in stix_object:
            for i in range(len(stix_object["external_references"])):
                stix_object["external_references"][i] = dict(stix_object["external_references"][i])
        if "kill_chain_phases" in stix_object:
            for i in range(len(stix_object["kill_chain_phases"])):
                stix_object["kill_chain_phases"][i] = dict(stix_object["kill_chain_phases"][i])

        if "modified" in stix_object:
            stix_object["modified"] = str(stix_object["modified"])
        if "first_seen" in stix_object:
            stix_object["first_seen"] = str(stix_object["first_seen"])
        if "last_seen" in stix_object:
            stix_object["last_seen"] = str(stix_object["last_seen"])

        if "definition" in stix_object:
            stix_object["definition"] = dict(stix_object["definition"])
        stix_object["created"] = str(stix_object["created"])
        result.append(stix_object)
    return result


def get_attack_id(stix_obj: dict) -> Optional[str]:
    """Get the object's ATT&CK ID.

    Parameters
    ----------
    stix_obj : dict
        An ATT&CK STIX Domain Object (SDO).

    Returns
    -------
    str (optional)
        The ATT&CK ID of the object. Returns None if not found
    """
    attack_id = None
    external_references = stix_obj.get("external_references")
    if external_references:
        attack_source = external_references[0]
        if attack_source.get("external_id") and attack_source.get("source_name") in [
            "mitre-attack",
            "mitre-mobile-attack",
            "mitre-ics-attack",
        ]:
            attack_id = attack_source["external_id"]
    return attack_id


def get_attack_object_version(stix_obj: dict) -> AttackObjectVersion:
    """Get the object's ATT&CK version.

    Parameters
    ----------
    stix_obj : dict
        An ATT&CK STIX Domain Object (SDO).

    Returns
    -------
    AttackObjectVersion
        The object version of the ATT&CK object.
    """
    # ICS objects didn't have x_mitre_version until v11.0, so pretend they were version 0.0
    version = stix_obj.get("x_mitre_version", "0.0")
    major, minor = version.split(".")
    major = int(major)
    minor = int(minor)
    object_version = AttackObjectVersion(major=major, minor=minor)
    return object_version


def markdown_to_html(outfile: str, content: str, diffStix: DiffStix):
    """Convert the markdown string passed in to HTML and store in index.html of indicated output file path.

    Parameters
    ----------
    outfile : str
        File to write HTML for the changelog.
    content : str
        Content to write to the changelog file.
    diffStix : DiffStix
        An instance of a DiffStix object.
    """
    logger.info("Writing HTML to file")
    old_version = diffStix.data["old"]["enterprise-attack"]["attack_release_version"]
    new_version = diffStix.data["new"]["enterprise-attack"]["attack_release_version"]
    if new_version:
        header = f"<h1 style='text-align:center;'>ATT&CK Changes Between v{old_version} and v{new_version}</h1>"
    else:
        header = f"<h1 style='text-align:center;'>ATT&CK Changes Between v{old_version} and new content</h1>"

    # Center content
    html_string = """<div style='max-width: 55em;margin: auto;margin-top:20px;font-family: "Roboto", sans-serif;'>"""
    html_string += "<meta charset='utf-8'>"
    html_string += header
    html_string += markdown.markdown(content)
    html_string += "</div>"

    with open(outfile, "w", encoding="utf-8") as outputfile:
        outputfile.write(html_string)


def layers_dict_to_files(outfiles, layers):
    """Print the layers dict passed in to layer files."""
    logger.info("Writing ATT&CK Navigator layers to JSON files")

    # write each layer to separate files
    if "enterprise-attack" in layers:
        enterprise_attack_layer_file = outfiles[0]
        Path(enterprise_attack_layer_file).parent.mkdir(parents=True, exist_ok=True)
        json.dump(layers["enterprise-attack"], open(enterprise_attack_layer_file, "w"), indent=4)

    if "mobile-attack" in layers:
        mobile_attack_layer_file = outfiles[1]
        Path(mobile_attack_layer_file).parent.mkdir(parents=True, exist_ok=True)
        json.dump(layers["mobile-attack"], open(mobile_attack_layer_file, "w"), indent=4)

    if "ics-attack" in layers:
        ics_attack_layer_file = outfiles[2]
        Path(ics_attack_layer_file).parent.mkdir(parents=True, exist_ok=True)
        json.dump(layers["ics-attack"], open(ics_attack_layer_file, "w"), indent=4)


def write_detailed_html(html_file_detailed: str, diffStix: DiffStix):
    """Write a detailed HTML report of changes between ATT&CK versions.

    Parameters
    ----------
    html_file_detailed : str
        File to write HTML for the detailed changelog.
    diffStix : DiffStix
        An instance of a DiffStix object.
    """
    old_version = diffStix.data["old"]["enterprise-attack"]["attack_release_version"]
    new_version = diffStix.data["new"]["enterprise-attack"]["attack_release_version"]

    if new_version:
        header = f"<h1>ATT&CK Changes Between v{old_version} and v{new_version}</h1>"
    else:
        header = f"<h1>ATT&CK Changes Between v{old_version} and new content</h1>"

    frontmatter = [
        textwrap.dedent(
            """\
        <!DOCTYPE html>
        <html>
            <head>
                <title>ATT&CK Changes</title>
                <meta http-equiv="Content-Type" content="text/html; charset=utf8">
                <style type="text/css">
                    table.diff {font-family:Courier; border:medium;}
                    .diff_header {background-color:#e0e0e0}
                    td.diff_header {text-align:right}
                    .diff_next {background-color:#c0c0c0}
                    .diff_add {background-color:#aaffaa}
                    .diff_chg {background-color:#ffff77}
                    .diff_sub {background-color:#ffaaaa}
                </style>
            </head>
            <body>
        """
        ),
        header,
        markdown.markdown(diffStix.get_md_key()),
        textwrap.dedent(
            """\
        <table class=diff summary=Legends>
            <tr>
                <td>
                    <table border= summary=Colors>
                        <tr><th>Colors for description field</th></tr>
                        <tr><td class=diff_add>Added</td></tr>
                        <tr><td class=diff_chg>Changed</td></tr>
                        <tr><td class=diff_sub>Deleted</td></tr>
                    </table>
                </td>
            </tr>
        </table>
        <h2>Additional formats</h2>
        <p>These ATT&CK Navigator layer files can be uploaded to ATT&CK Navigator manually.</p>
        <ul>
            <li><a href="layer-enterprise.json">Enterprise changes</a></li>
            <li><a href="layer-mobile.json">Mobile changes</a></li>
            <li><a href="layer-ics.json">ICS changes</a></li>
        </ul>
        <p>This JSON file contains the machine readble output used to create this page: <a href="changelog.json">changelog.json</a></p>
        """
        ),
    ]

    with open(html_file_detailed, "w", encoding="utf-8", errors="xmlcharrefreplace") as file:
        file.writelines(frontmatter)
        lines = []
        for object_type, domain_data in diffStix.data["changes"].items():
            # this is an obnoxious way of determining if there are changes in any of the sections for any of the domains
            if sum([sum(change_types.values(), []) for change_types in domain_data.values()], []):
                lines.append(f"<h2>{diffStix.attack_type_to_title[object_type]}</h2>")
            else:
                continue

            for domain, change_types in domain_data.items():
                if sum(change_types.values(), []):
                    lines.append(f"<h3>{domain}</h3>")
                else:
                    continue

                for change_type, change_data in change_types.items():
                    if change_type == "unchanged":
                        # Not reporting on unchanged STIX objects for detailed changelog
                        continue

                    datastore_version = "old" if change_type == "deletions" else "new"

                    if change_data:
                        lines.append("<details>")
                        lines.append(f"<summary>{diffStix.section_headers[object_type][change_type]}</summary>")

                    for stix_object in change_data:
                        attack_id = get_attack_id(stix_object)
                        object_version = get_attack_object_version(stix_obj=stix_object)

                        if stix_object["type"] == "x-mitre-data-component" or stix_object.get(
                            "x_mitre_is_subtechnique"
                        ):
                            parent_object = diffStix.get_parent_stix_object(
                                stix_object=stix_object, datastore_version=datastore_version, domain=domain
                            )
                            if parent_object:
                                nameplate = f"{parent_object.get('name')}: {stix_object['name']}"
                            else:
                                logger.warning(f"[{stix_object['id']}] {attack_id} has no parent!")
                                nameplate = f"{stix_object['name']} (No parent object identified. It is likely revoked or deprecated)"
                        else:
                            nameplate = stix_object["name"]

                        if attack_id:
                            nameplate = f"[{attack_id}] {nameplate}"
                        else:
                            if stix_object["type"] != "x-mitre-data-component":
                                logger.warning(f"{stix_object['id']} does not have an ATT&CK ID")

                        lines.append("<hr>")
                        lines.append(f"<h4>{nameplate}</h4>")

                        if object_version:
                            lines.append(f"<p><b>Current version</b>: {object_version}</p>")

                        if change_type in ["additions", "revocations", "deprecations", "deletions"]:
                            if stix_object.get("description"):
                                lines.append(f"<p><b>Description</b>: {markdown.markdown(stix_object['description'])}</p>")

                        if change_type == "revocations":
                            revoked_by_id = get_attack_id(stix_object["revoked_by"])
                            revoked_by_name = stix_object["revoked_by"]["name"]
                            revoked_by_description = stix_object["revoked_by"]["description"]
                            lines.append("<font color=blue>")
                            lines.append(f"<p>This object has been revoked by [{revoked_by_id}] {revoked_by_name}</p>")
                            lines.append("</font>")
                            if revoked_by_description:
                                lines.append(
                                    f"<p><b>Description for [{revoked_by_id}] {revoked_by_name}</b>: {revoked_by_description}</p>"
                                )

                        version_change = stix_object.get("version_change")
                        if version_change:
                            lines.append(f"<p><b>Version changed from</b>: {version_change}</p>")

                        description_change_table = stix_object.get("description_change_table")
                        if description_change_table:
                            lines.append(description_change_table)

                        if object_type == "techniques":
                            # Mitigations!
                            if stix_object.get("changelog_mitigations"):
                                new_mitigations = stix_object["changelog_mitigations"].get("new")
                                dropped_mitigations = stix_object["changelog_mitigations"].get("dropped")
                                if new_mitigations:
                                    lines.append("<p><b>New Mitigations</b>:</p>")
                                    lines.append("<ul>")
                                    for mitigation in new_mitigations:
                                        lines.append(f"  <li>{mitigation}</li>")
                                    lines.append("</ul>")
                                if dropped_mitigations:
                                    lines.append("<p><b>Dropped Mitigations</b>:</p>")
                                    lines.append("<ul>")
                                    for mitigation in dropped_mitigations:
                                        lines.append(f"  <li>{mitigation}</li>")
                                    lines.append("</ul>")

                            # Detections!
                            if stix_object.get("changelog_detections"):
                                new_detections = stix_object["changelog_detections"].get("new")
                                dropped_detections = stix_object["changelog_detections"].get("dropped")
                                if new_detections:
                                    lines.append("<p><b>New Detections</b>:</p>")
                                    lines.append("<ul>")
                                    for detection in new_detections:
                                        lines.append(f"  <li>{detection}</li>")
                                    lines.append("</ul>")
                                if dropped_detections:
                                    lines.append("<p><b>Dropped Detections</b>:</p>")
                                    lines.append("<ul>")
                                    for detection in dropped_detections:
                                        lines.append(f"  <li>{detection}</li>")
                                    lines.append("</ul>")

                        detailed_diff = json.loads(stix_object.get("detailed_diff", "{}"))
                        if detailed_diff:
                            lines.append("<details>")
                            lines.append("<summary>Details</summary>")
                            table_inline_css = "style='border: 1px solid black;border-collapse: collapse;'"

                            # the deepdiff library displays differences with a prefix of:
                            # root['<top-level-key-we-care-about>']
                            regex = r"^root\['(?P<top_stix_key>[^\']*)'\](?P<the_rest>.*)$"
                            for detailed_change_type, detailed_changes in detailed_diff.items():
                                lines.append(f"<table {table_inline_css}>")
                                lines.append(f"<caption>{detailed_change_type}</caption>")
                                lines.append("<thead><tr>")
                                lines.append(f"<th {table_inline_css}>STIX Field</th>")
                                lines.append(f"<th {table_inline_css}>Old value</th>")
                                lines.append(f"<th {table_inline_css}>New Value</th>")
                                lines.append("</tr></thead>")
                                lines.append("<tbody>")

                                if detailed_change_type == "values_changed":
                                    for detailed_change, values in detailed_changes.items():
                                        matches = re.search(regex, detailed_change)
                                        top_stix_key = matches.group("top_stix_key")
                                        the_rest = matches.group("the_rest")
                                        stix_field = f"{top_stix_key}{the_rest}"

                                        old_value = values["old_value"]
                                        new_value = values["new_value"]
                                        lines.append("<tr>")
                                        lines.append(f"<td {table_inline_css}>{stix_field}</td>")
                                        lines.append(f"<td {table_inline_css}>{old_value}</td>")
                                        lines.append(f"<td {table_inline_css}>{new_value}</td>")
                                        lines.append("</tr>")

                                elif detailed_change_type == "iterable_item_added":
                                    for detailed_change, new_value in detailed_changes.items():
                                        stix_field = re.search(regex, detailed_change).group("top_stix_key")
                                        lines.append("<tr>")
                                        lines.append(f"<td {table_inline_css}>{stix_field}</td>")
                                        lines.append(f"<td {table_inline_css}></td>")
                                        lines.append(f"<td {table_inline_css}>{new_value}</td>")
                                        lines.append("</tr>")

                                elif detailed_change_type == "iterable_item_removed":
                                    for detailed_change, old_value in detailed_changes.items():
                                        stix_field = re.search(regex, detailed_change).group("top_stix_key")
                                        lines.append("<tr>")
                                        lines.append(f"<td {table_inline_css}>{stix_field}</td>")
                                        lines.append(f"<td {table_inline_css}>{old_value}</td>")
                                        lines.append(f"<td {table_inline_css}></td>")
                                        lines.append("</tr>")

                                elif detailed_change_type == "dictionary_item_added":
                                    for detailed_change, new_value in detailed_changes.items():
                                        stix_field = re.search(regex, detailed_change).group("top_stix_key")
                                        lines.append("<tr>")
                                        lines.append(f"<td {table_inline_css}>{stix_field}</td>")
                                        lines.append(f"<td {table_inline_css}></td>")
                                        lines.append(f"<td {table_inline_css}>{new_value}</td>")
                                        lines.append("</tr>")

                                elif detailed_change_type == "dictionary_item_removed":
                                    for detailed_change, old_value in detailed_changes.items():
                                        stix_field = re.search(regex, detailed_change).group("top_stix_key")
                                        lines.append("<tr>")
                                        lines.append(f"<td {table_inline_css}>{stix_field}</td>")
                                        lines.append(f"<td {table_inline_css}>{old_value}</td>")
                                        lines.append(f"<td {table_inline_css}></td>")
                                        lines.append("</tr>")

                                else:
                                    lines.append(f"<h5>{detailed_change_type}</h5>")
                                    lines.append("<ul>")
                                    for detailed_change in detailed_changes:
                                        lines.append(f"<li>{detailed_change}</li>")
                                    lines.append("</ul>")

                                lines.append("</tbody></table>")
                            lines.append("</details>")

                    if change_data:
                        lines.append("</details>")

        lines.append(
            """
            </body>
        </html>
        """
        )

        file.writelines(lines)


def get_parsed_args():
    """Create argument parser and parse arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Create changelog reports on the differences between two versions of the ATT&CK content. "
            "Takes STIX bundles as input. For default operation, put "
            "enterprise-attack.json, mobile-attack.json, and ics-attack.json bundles "
            "in 'old' and 'new' folders for the script to compare."
        )
    )

    parser.add_argument(
        "--old",
        type=str,
        # Default is really "old", set below
        default=None,
        help="Directory to load old STIX data from.",
    )

    parser.add_argument(
        "--new",
        type=str,
        default="new",
        help="Directory to load new STIX data from.",
    )

    parser.add_argument(
        "--domains",
        type=str,
        nargs="+",
        choices=["enterprise-attack", "mobile-attack", "ics-attack"],
        default=["enterprise-attack", "mobile-attack", "ics-attack"],
        help="Which domains to report on. Choices (and defaults) are %(choices)s",
    )

    parser.add_argument(
        "--markdown-file",
        type=str,
        help="Create a markdown file reporting changes.",
    )

    parser.add_argument(
        "--html-file",
        type=str,
        help="Create HTML page from markdown content.",
    )

    parser.add_argument(
        "--html-file-detailed",
        type=str,
        help="Create an HTML file reporting detailed changes.",
    )

    parser.add_argument(
        "--json-file",
        type=str,
        help="Create a JSON file reporting changes.",
    )

    parser.add_argument(
        "--layers",
        type=str,
        nargs="*",
        help=f"""
            Create layer files showing changes in each domain
            expected order of filenames is 'enterprise', 'mobile', 'ics', 'pre attack'.
            If values are unspecified, defaults to {", ".join(layer_defaults)}
            """,
    )

    parser.add_argument(
        "--site_prefix",
        type=str,
        default="",
        help="Prefix links in markdown output, e.g. [prefix]/techniques/T1484",
    )

    parser.add_argument(
        "--unchanged",
        action="store_true",
        help="Show objects without changes in the markdown output",
    )

    parser.add_argument(
        "--use-mitre-cti",
        action="store_true",
        help="Use content from the MITRE CTI repo for the -old data",
    )

    parser.add_argument(
        "--show-key",
        action="store_true",
        help="Add a key explaining the change types to the markdown",
    )

    parser.add_argument(
        "--contributors",
        action="store_true",
        help="Show new contributors between releases",
    )
    parser.add_argument(
        "--no-contributors",
        dest="contributors",
        action="store_false",
        help="Do not show new contributors between releases",
    )
    parser.set_defaults(contributors=True)

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print status messages",
    )

    args = parser.parse_args()

    # the default loguru logger logs up to Debug by default
    logger.remove()
    if args.verbose:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True)
    else:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True, level="INFO")

    if args.use_mitre_cti and args.old:
        parser.error("--use-mitre-cti and -old cannot be used together")

    # set a default directory that doesn't conflict with use_mitre_cti
    if not args.old:
        args.old = "old"

    if args.layers is not None:
        if len(args.layers) not in [0, 3]:
            parser.error("-layers requires exactly three files to be specified or none at all")

    return args


def get_new_changelog_md(
    domains: List[str] = ["enterprise-attack", "mobile-attack", "ics-attack"],
    layers: List[str] = layer_defaults,
    unchanged: bool = False,
    old: str = None,
    new: str = "new",
    show_key: bool = False,
    site_prefix: str = "",
    use_mitre_cti: bool = False,
    verbose: bool = False,
    include_contributors: bool = False,
    markdown_file: Optional[str] = None,
    html_file: Optional[str] = None,
    html_file_detailed: Optional[str] = None,
    json_file: Optional[str] = None,
) -> str:
    """Get a Markdown string representation of differences between two ATT&CK versions.

    Additionally, if you want to save HTML, JSON, or detailed output you can do that with this function as well.

    Parameters
    ----------
    domains : List[str], optional
        List of domains to parse, by default ["enterprise-attack", "mobile-attack", "ics-attack"]
    layers : List[str], optional
        Array of output filenames for layer files, by default layer_defaults
    unchanged : bool, optional
        Include unchanged ATT&CK objects in diff comparison, by default False
    old : str, optional
        Directory to load old STIX data from, by default None
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
    markdown_file : str, optional
        If set, writes a markdown file, by default None
    html_file : str, optional
        If set, writes an HTML file from the parsed markdown, by default None
    html_file_detailed : str, optional
        If set, writes a more detailed HTML page, by default None
    json_file : str, optional
        If set, writes JSON file of the changes, by default None

    Returns
    -------
    str
        A Markdown string representation of differences between two ATT&CK versions.
    """
    # the default loguru logger logs up to Debug by default
    logger.remove()
    if verbose:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True)
    else:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True, level="INFO")

    # if old and use_mitre_cti:
    #     logger.error("Multiple sources selected as base STIX to compare against.")
    #     logger.error("When calling get_new_changelog_md(), 'old' is mutually exclusive with 'use_mitre_cti'")
    #     return ""

    diffStix = DiffStix(
        domains=domains,
        layers=layers,
        unchanged=unchanged,
        old=old,
        new=new,
        show_key=show_key,
        site_prefix=site_prefix,
        use_mitre_cti=use_mitre_cti,
        verbose=verbose,
        include_contributors=include_contributors,
    )

    md_string = None
    if markdown_file or html_file:
        md_string = diffStix.get_markdown_string()

    if markdown_file:
        logger.info("Writing markdown to file")
        Path(markdown_file).parent.mkdir(parents=True, exist_ok=True)
        with open(markdown_file, "w") as file:
            file.write(md_string)

    if html_file:
        markdown_to_html(outfile=html_file, content=md_string, diffStix=diffStix)

    if html_file_detailed:
        Path(html_file_detailed).parent.mkdir(parents=True, exist_ok=True)
        logger.info("Writing detailed updates to file")
        write_detailed_html(html_file_detailed=html_file_detailed, diffStix=diffStix)

    if layers:
        if len(layers) == 0:
            # no files specified, e.g. '-layers', use defaults
            diffStix.layers = layer_defaults
            layers = layer_defaults
        elif len(layers) == 3:
            # files specified, e.g. '-layers file.json file2.json file3.json', use specified
            # assumes order of files is enterprise, mobile, pre attack (same order as defaults)
            diffStix.layers = layers

        layers_dict = diffStix.get_layers_dict()
        layers_dict_to_files(outfiles=layers, layers=layers_dict)

    if json_file:
        changes_dict = diffStix.get_changes_dict()

        logger.info("Writing JSON updates to file")
        Path(json_file).parent.mkdir(parents=True, exist_ok=True)
        json.dump(changes_dict, open(json_file, "w"), cls=AttackChangesEncoder, indent=4)

    return md_string


def main():
    """Entrypoint for running this file as a script or as a Python console command."""
    args = get_parsed_args()

    get_new_changelog_md(
        domains=args.domains,
        layers=args.layers,
        unchanged=args.unchanged,
        old=args.old,
        new=args.new,
        show_key=args.show_key,
        site_prefix=args.site_prefix,
        use_mitre_cti=args.use_mitre_cti,
        verbose=args.verbose,
        include_contributors=args.contributors,
        markdown_file=args.markdown_file,
        html_file=args.html_file,
        html_file_detailed=args.html_file_detailed,
        json_file=args.json_file,
    )


if __name__ == "__main__":
    main()
