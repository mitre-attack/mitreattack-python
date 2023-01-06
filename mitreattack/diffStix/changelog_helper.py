import argparse
import datetime
import difflib
import json
import math
import os
import re
import sys
import textwrap
from pprint import pformat
from itertools import chain
from pathlib import Path
from typing import List, Optional

import markdown
import requests
from dateutil import parser as dateparser
from deepdiff import DeepDiff
from loguru import logger
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

# →

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
        types: List[str] = ["technique", "software", "group", "campaign", "mitigation", "datasource"],
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
        types : List[str], optional
            Which types of objects to report on, by default ["technique", "software", "group", "campaign", "mitigation", "datasource"]
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
        self.types = types
        self.use_mitre_cti = use_mitre_cti
        self.verbose = verbose
        self.include_contributors = include_contributors

        self.domain_to_domain_label = {
            "enterprise-attack": "Enterprise",
            "mobile-attack": "Mobile",
            "ics-attack": "ICS",
        }
        self.attack_type_to_section_name = {
            "technique": "Technique",
            "malware": "Malware",
            "software": "Software",
            "group": "Group",
            "campaign": "Campaign",
            "mitigation": "Mitigation",
            "datasource": "Data Source/Data Component",
        }
        self.attack_type_to_title = {
            "technique": "Techniques",
            "malware": "Malware",
            "software": "Software",
            "group": "Groups",
            "campaign": "Campaigns",
            "mitigation": "Mitigations",
            "datasource": "Data Sources/Data Components",
        }

        self.section_descriptions = {
            "additions": "ATT&CK objects which are present in the new STIX data but not the old.",
            "major_version_changes": "ATT&CK objects that have a major version change. (e.g. 1.0 → 2.0)",
            "minor_version_changes": "ATT&CK objects that have a minor version change. (e.g. 1.0 → 1.1)",
            "other_version_changes": "ATT&CK objects that have an unexpected version change. (e.g. 1.0 → 1.3)",
            "metadata_changes": "ATT&CK objects that have at least one field changed, but not the version.",
            "unknown_changes": "ATT&CK objects that have changed while the modified time stayed the same.",
            "revocations": "ATT&CK objects which are revoked by a different object.",
            "deprecations": "ATT&CK objects which are deprecated and no longer in use, and not replaced.",
            "deletions": "ATT&CK objects which are no longer found in the STIX data.",
            "unchanged": "ATT&CK objects which did not change between the two versions.",
        }

        self.section_headers = {}
        for object_type in self.types:
            self.section_headers[object_type] = {
                "additions": f"New {self.attack_type_to_title[object_type]}",
                "major_version_changes": f"Major Version Changes",
                "minor_version_changes": f"Minor Version Changes",
                "other_version_changes": f"Other Version Changes",
                "metadata_changes": f"Metadata-only Changes",
                "unknown_changes": f"Unknown Changes",
                "deprecations": f"Deprecations",
                "revocations": f"Revocations",
                "deletions": f"Deletions",
                "unchanged": f"Unchanged",
            }

        # will hold information of contributors of the new release {... {"contributor_credit/name_as_key": counter]} ...}
        self.release_contributors = {}

        # data gets loaded into here in the load_data() function. All other functionalities rely on this data structure
        self.data = {
            "old": {
                "attack_release_versions": {},
                "stix_datastores": {},
                "attack_objects": {},
                "datasources": {},
                "datacomponents": {},
                "techniques": {},
                "relationships": {
                    "subtechniques": {},
                    "revoked-by": {},
                },
            },
            "new": {
                "attack_release_versions": {},
                "stix_datastores": {},
                "attack_objects": {},
                "datasources": {},
                "datacomponents": {},
                "techniques": {},
                "relationships": {
                    "subtechniques": {},
                    "revoked-by": {},
                },
            },
            # changes are dynamic based on what object types and domains are requested
            "changes": {
                # "technique": {
                #     "enterprise-attack": {
                #         "additions": [],
                #         "deletions": [],
                #         "major_version_changes": [],
                #         "minor_version_changes": [],
                #         "other_version_changes": [],
                #         "metadata_changes": [],
                #         "unknown_changes": [],
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
            self.data["old"]["attack_objects"][domain] = {}
            self.data["new"]["attack_objects"][domain] = {}
            for _type in types:
                self.data["old"]["attack_objects"][domain][_type] = {}
                self.data["new"]["attack_objects"][domain][_type] = {}

        self.load_data()

    def load_domain(self, domain):
        """Load data from directory according to domain"""
        for datastore_version in ["old", "new"]:
            # only allow github.com/mitre/cti to be used for the old STIX domain
            if self.use_mitre_cti and datastore_version == "old":
                data_store = self.get_datastore_from_mitre_cti(domain=domain, datastore_version=datastore_version)
            else:
                directory = self.old if datastore_version == "old" else self.new
                stix_file = os.path.join(directory, f"{domain}.json")

                attack_version = release_info.get_attack_version(domain=domain, stix_file=stix_file)
                self.data[datastore_version]["attack_release_versions"][domain] = attack_version

                data_store = MemoryStore()
                data_store.load_from_file(stix_file)

            self.data[datastore_version]["stix_datastores"][domain] = data_store
            self.parse_extra_data(data_store=data_store, datastore_version=datastore_version)
            self.load_attack_objects(data_store=data_store, domain=domain, datastore_version=datastore_version)

    def get_datastore_from_mitre_cti(self, domain, datastore_version):
        """Load data from MITRE CTI repo according to domain"""
        error_message = f"Unable to successfully download ATT&CK STIX data from GitHub for {domain}. Please try again."
        try:
            stix_response = requests.get(f"https://raw.githubusercontent.com/mitre/cti/master/{domain}/{domain}.json")
        except requests.exceptions.ContentDecodingError:
            logger.error(error_message)
            sys.exit(1)
        if stix_response.status_code == 200:
            stix_json = stix_response.json()

            attack_version = release_info.get_attack_version(domain=domain, stix_content=stix_response.content)
            self.data[datastore_version]["attack_release_versions"][domain] = attack_version

            data_store = MemoryStore(stix_data=stix_json["objects"])
            return data_store
        logger.error(error_message)
        sys.exit(1)

    def parse_extra_data(self, data_store, datastore_version: str):
        """Parse dataStore sub-technique-of relationships"""
        all_techniques = list(data_store.query([Filter("type", "=", "attack-pattern")]))
        all_datasources = list(data_store.query([Filter("type", "=", "x-mitre-data-source")]))
        all_datacomponents = list(data_store.query([Filter("type", "=", "x-mitre-data-component")]))
        subtechnique_relationships = list(
            data_store.query(
                [
                    Filter("type", "=", "relationship"),
                    Filter("relationship_type", "=", "subtechnique-of"),
                ]
            )
        )
        revoked_by_relationships = list(
            data_store.query(
                [
                    Filter("type", "=", "relationship"),
                    Filter("relationship_type", "=", "revoked-by"),
                ]
            )
        )

        for technique in all_techniques:
            self.data[datastore_version]["techniques"][technique["id"]] = technique
        for datasource in all_datasources:
            self.data[datastore_version]["datasources"][datasource["id"]] = datasource
        for datacomponent in all_datacomponents:
            self.data[datastore_version]["datacomponents"][datacomponent["id"]] = datacomponent
        for relationship in subtechnique_relationships:
            self.data[datastore_version]["relationships"]["subtechniques"][relationship["id"]] = relationship

        # use list in case STIX object was revoked more than once
        for relationship in revoked_by_relationships:
            source_id = relationship["source_ref"]
            if source_id not in self.data[datastore_version]["relationships"]["revoked-by"]:
                self.data[datastore_version]["relationships"]["revoked-by"][source_id] = []
            self.data[datastore_version]["relationships"]["revoked-by"][source_id].append(relationship)

    def load_attack_objects(self, data_store, domain, datastore_version: str):
        """Handle data loaded from a directory"""
        attack_type_to_stix_filter = {
            "technique": [Filter("type", "=", "attack-pattern")],
            "software": [Filter("type", "=", "malware"), Filter("type", "=", "tool")],
            "group": [Filter("type", "=", "intrusion-set")],
            "campaign": [Filter("type", "=", "campaign")],
            "mitigation": [Filter("type", "=", "course-of-action")],
            "datasource": [
                Filter("type", "=", "x-mitre-data-source"),
                Filter("type", "=", "x-mitre-data-component"),
            ],
        }
        for obj_type in self.types:
            raw_data = list(chain.from_iterable(data_store.query(f) for f in attack_type_to_stix_filter[obj_type]))
            raw_data = deep_copy_stix(raw_data)

            self.data[datastore_version]["attack_objects"][domain][obj_type] = {item["id"]: item for item in raw_data}

    def update_contributors(self, old_object, new_object):
        """Update contributors list if new object has contributors"""
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

    def load_data(self):
        """Load data from files into data dict."""
        for domain in track(self.domains, description="Loading domains"):
            self.load_domain(domain=domain)

        for obj_type in track(self.types, description="Finding changes"):
            for domain in self.domains:
                logger.debug(f"Loading: [{domain:17}]/{obj_type}")

                old_attack_objects = self.data["old"]["attack_objects"][domain][obj_type]
                new_attack_objects = self.data["new"]["attack_objects"][domain][obj_type]

                intersection = old_attack_objects.keys() & new_attack_objects.keys()
                additions = new_attack_objects.keys() - old_attack_objects.keys()
                deletions = old_attack_objects.keys() - new_attack_objects.keys()

                # sets to store the ids of objects for each section
                major_version_changes = set()
                minor_version_changes = set()
                other_version_changes = set()
                metadata_changes = set()
                unknown_changes = set()
                revocations = set()
                deprecations = set()
                unchanged = set()

                # find changes, revocations and deprecations
                for stix_id in intersection:

                    old_stix_obj = old_attack_objects[stix_id]
                    new_stix_obj = new_attack_objects[stix_id]
                    attack_id = get_attack_id(new_stix_obj)

                    ddiff = DeepDiff(old_stix_obj, new_stix_obj, verbose_level=2)
                    detailed_diff = ddiff.to_json()
                    new_stix_obj["detailed_diff"] = detailed_diff

                    ########################################
                    # Newly revoked objects
                    ########################################
                    if new_stix_obj.get("revoked"):
                        # only work with newly revoked objects
                        if not old_stix_obj.get("revoked"):
                            if stix_id not in self.data["new"]["relationships"]["revoked-by"]:
                                logger.error(f"[{stix_id}] revoked object has no revoked-by relationship")
                                continue

                            revoked_by_key = self.data["new"]["relationships"]["revoked-by"][stix_id][0]["target_ref"]
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
                        if not "x_mitre_deprecated" in old_stix_obj:
                            deprecations.add(stix_id)

                    #############################################################
                    # Objects shared between old and new STIX bundles by STIX IDs
                    #############################################################
                    else:
                        old_version = get_attack_object_version(old_stix_obj)
                        new_version = get_attack_object_version(new_stix_obj)

                        # Verify if there are new contributors on the object
                        self.update_contributors(old_object=old_stix_obj, new_object=new_stix_obj)
                        new_stix_obj["previous_version"] = old_version

                        # Version number didn't change
                        ##############################
                        if new_version == old_version:
                            # check for minor change; modification date increased but not version
                            old_date = dateparser.parse(old_stix_obj["modified"])
                            new_date = dateparser.parse(new_stix_obj["modified"])
                            if new_date != old_date:
                                metadata_changes.add(stix_id)
                            else:
                                unchanged.add(stix_id)

                        # Version number changed
                        ########################
                        else:
                            if is_major_version_change(old_version=old_version, new_version=new_version):
                                major_version_changes.add(stix_id)
                            elif is_minor_version_change(old_version=old_version, new_version=new_version):
                                minor_version_changes.add(stix_id)
                            else:
                                other_version_changes.add(stix_id)
                                logger.warning(
                                    f"{stix_id} - Unexpected version increase {old_version} → {new_version}. [{attack_id}] {new_stix_obj['name']}"
                                )

                            new_stix_obj["version_change"] = f"{old_version} → {new_version}"

                        # Description changes
                        #####################
                        old_lines = old_stix_obj["description"].replace("\n", " ").splitlines()
                        new_lines = new_stix_obj["description"].replace("\n", " ").splitlines()

                        df = [x for x in old_lines if x not in new_lines]
                        df1 = [x for x in new_lines if x not in old_lines]

                        if df != [] or df1 != []:
                            if (
                                (stix_id not in major_version_changes)
                                and (stix_id not in minor_version_changes)
                                and (stix_id not in metadata_changes)
                                and (stix_id not in other_version_changes)
                            ):
                                logger.error(
                                    f"{stix_id} - Somehow {attack_id} has a description change "
                                    "without the version being incremented or the last modified date changing"
                                )
                                unknown_changes.add(stix_id)

                            html_diff = difflib.HtmlDiff(wrapcolumn=60)
                            html_diff._legend = ""

                            delta = html_diff.make_table(old_lines, new_lines, "Old Description", "New Description")
                            new_stix_obj["description_change_table"] = delta

                #############
                # New objects
                #############
                for stix_id in additions:
                    new_stix_obj = new_attack_objects[stix_id]
                    attack_id = get_attack_id(new_stix_obj)

                    # Add contributions from additions
                    self.update_contributors(old_object=None, new_object=new_stix_obj)

                    # verify version is 1.0
                    x_mitre_version = new_stix_obj.get("x_mitre_version")
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
                    "metadata_changes": sorted(
                        [new_attack_objects[stix_id] for stix_id in metadata_changes],
                        key=lambda stix_object: stix_object["name"],
                    ),
                    "unknown_changes": sorted(
                        [new_attack_objects[stix_id] for stix_id in unknown_changes],
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

    def get_groupings(
        self,
        object_type,
        stix_objects,
        section,
    ):
        datastore_version = "old" if section == "deletions" else "new"
        subtechnique_relationships = self.data[datastore_version]["relationships"]["subtechniques"]
        techniques = self.data[datastore_version]["techniques"]
        datacomponents = self.data[datastore_version]["datacomponents"]
        datasources = self.data[datastore_version]["datasources"]

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
            if not relationship["source_ref"] in children:
                continue

            parent_technique_stix_id = relationship["target_ref"]
            the_subtechnique = children[relationship["source_ref"]]
            if not parent_technique_stix_id in parentToChildren:
                parentToChildren[parent_technique_stix_id] = []
            parentToChildren[parent_technique_stix_id].append(the_subtechnique)

        # datacomponents
        for datacomponent in datacomponents.values():
            if not datacomponent["id"] in children:
                continue

            parent_datasource_id = datacomponent["x_mitre_data_source_ref"]
            the_datacomponent = children[datacomponent["id"]]
            if not parent_datasource_id in parentToChildren:
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

    def get_contributor_section(self):
        # Get contributors markdown
        contribSection = "## Contributors to this release\n\n"
        sorted_contributors = sorted(self.release_contributors, key=lambda v: v.lower())

        for contributor in sorted_contributors:
            if contributor == "ATT&CK":
                continue  # do not include ATT&CK as contributor
            contribSection += f"* {contributor}\n"

        return contribSection

    def get_parent_stix_object(self, stix_object, datastore_version: str):
        subtechnique_relationships = self.data[datastore_version]["relationships"]["subtechniques"]
        techniques = self.data[datastore_version]["techniques"]
        datasources = self.data[datastore_version]["datasources"]

        if stix_object.get("x_mitre_is_subtechnique"):
            for subtechnique_relationship in subtechnique_relationships.values():
                if subtechnique_relationship["source_ref"] == stix_object["id"]:
                    parent_id = subtechnique_relationship["target_ref"]
                    return techniques[parent_id]
        elif stix_object["type"] == "x-mitre-data-component":
            return datasources[stix_object.get("x_mitre_data_source_ref")]

        # possible reasons for no parent object: deprecated/revoked/wrong object type passed in
        return {}

    def placard(self, stix_object, section):
        """Get a section list item for the given SDO according to section type"""
        datastore_version = "old" if section == "deletions" else "new"

        if section == "deletions":
            placard_string = stix_object["name"]

        elif section == "revocations":
            revoker = stix_object["revoked_by"]

            if revoker.get("x_mitre_is_subtechnique"):
                parent_object = self.get_parent_stix_object(stix_object=revoker, datastore_version=datastore_version)
                parent_name = parent_object.get("name", default="ERROR NO PARENT")
                relative_url = get_relative_url_from_stix(stix_object=revoker)
                revoker_link = f"{self.site_prefix}/{relative_url}"
                placard_string = (
                    f"{stix_object['name']} (revoked by {parent_name}: [{revoker['name']}]({revoker_link}))"
                )

            elif revoker["type"] == "x-mitre-data-component":
                parent_object = self.get_parent_stix_object(stix_object=revoker, datastore_version=datastore_version)
                parent_name = parent_object.get("name", default="ERROR NO PARENT")
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
                    stix_object=stix_object, datastore_version=datastore_version
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

    def get_markdown_section_data(self, groupings, section):
        """Parse a list of STIX objects in a section and return a string for the whole section."""
        sectionString = ""
        for grouping in groupings:
            if grouping["parentInSection"]:
                placard_string = self.placard(stix_object=grouping["parent"], section=section)
                sectionString += f"* {placard_string}\n"

            for child in sorted(grouping["children"], key=lambda child: child["name"]):
                placard_string = self.placard(stix_object=child, section=section)

                if grouping["parentInSection"]:
                    sectionString += f"    * {placard_string}\n"
                else:
                    sectionString += f"* {grouping['parent']['name']}: {placard_string}\n"

        return sectionString

    def get_md_key(self):
        """Create string describing each type of difference (change, addition, etc).

        Used in get_markdown_string.
        """
        # end first line with \ to avoid the empty line from dedent()
        key = textwrap.dedent(
            f"""\
            ## Key

            * New objects: {self.section_descriptions["additions"]}
            * Major version changes: {self.section_descriptions["major_version_changes"]}
            * Minor version changes: {self.section_descriptions["minor_version_changes"]}
            * Other version changes: {self.section_descriptions["other_version_changes"]}
            * Metadata changes: {self.section_descriptions["metadata_changes"]}
            * Unknown changes: {self.section_descriptions["unknown_changes"]}
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
                    logger.debug(f"Skipping - ATT&CK for Mobile does not support data sources")
                    domains += f"ATT&CK for Mobile does not support data sources\n\n"
                    continue
                domain_sections = ""
                for section, stix_objects in self.data["changes"][object_type][domain].items():
                    header = f"#### {self.section_headers[object_type][section]}"
                    if stix_objects:
                        groupings = self.get_groupings(
                            object_type=object_type,
                            stix_objects=stix_objects,
                            section=section,
                        )
                        section_items = self.get_markdown_section_data(groupings=groupings, section=section)
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
            "metadata_changes": "#B99095",  # mauve
            "unknown_changes": "#3D5B59",  # teal green
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
            for section, technique_stix_objects in self.data["changes"]["technique"][domain].items():
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
                    "layer": "4.4",
                    "navigator": "4.8.0",
                    "attack": self.data["new"]["attack_release_versions"][domain],
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
                    )
                    # new_values includes parents & children mixed (e.g. techniques/sub-techniques, data sources/components)
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


def has_subtechniques(stix_object, subtechnique_relationships):
    """Return true or false depending on whether the SDO has sub-techniques."""
    # for relationship in self.data[datastore_version]["relationships"]["subtechniques"].values():
    for relationship in subtechnique_relationships.values():
        if relationship["target_ref"] == stix_object["id"]:
            return True

    return False


def get_placard_version_string(stix_object, section):
    gray = "#929393"
    red = "#eb6635"
    color = gray

    object_version = get_attack_object_version(stix_obj=stix_object)
    version_display = f"(v{object_version})"

    if section in ["additions", "deprecations", "revocations"]:
        # only display current version
        if not version_increment_is_valid(old_version=None, new_version=str(object_version), section=section):
            color = red

    elif section == "deletions":
        color = red

    # nothing needs to be added to this statement - it just needs to skip the 'else' clause
    elif section == "metadata_changes":
        pass

    else:
        # the "previous_version" key was added in the load_data() function
        old_version = stix_object.get("previous_version")
        if not version_increment_is_valid(old_version=old_version, new_version=str(object_version), section=section):
            color = red
        version_display = f"(v{old_version}&#8594;v{object_version})"

    return f'<small style="color:{color}">{version_display}</small>'


def cleanup_values(groupings):
    new_values = []
    for grouping in groupings:
        if grouping["parentInSection"]:
            new_values.append(grouping["parent"])

        for child in sorted(grouping["children"], key=lambda child: child["name"]):
            new_values.append(child)

    return new_values


def version_increment_is_valid(old_version: str, new_version: str, section: str) -> bool:
    """Validate version increment between old and new STIX objects."""
    if section in ["revocations", "deprecations"]:
        return True
    if section == "additions":
        if new_version != "1.0":
            return False
        return True
    if not (old_version and new_version):
        return False

    old_version = float(old_version)
    new_version = float(new_version)
    major_change = is_major_version_change(old_version=old_version, new_version=new_version)
    minor_change = is_minor_version_change(old_version=old_version, new_version=new_version)

    if major_change or minor_change:
        return True
    return False


def is_major_version_change(old_version: float, new_version: float) -> bool:
    """Determine if the new version is a major change or not."""
    next_major = float(math.floor(old_version + 1))
    if next_major == new_version:
        return True
    return False


def is_minor_version_change(old_version: float, new_version: float) -> bool:
    """Determine if the new version is a minor change or not."""
    diff = round(new_version - old_version, 1)
    if diff == 0.1:
        return True
    return False


def get_relative_url_from_stix(stix_object):
    """Parse the website url from a stix object."""
    is_subtechnique = stix_object["type"] == "attack-pattern" and stix_object.get("x_mitre_is_subtechnique")

    if stix_object.get("external_references"):
        url = stix_object["external_references"][0]["url"]
        split_url = url.split("/")
        splitfrom = -3 if is_subtechnique else -2
        link = "/".join(split_url[splitfrom:])
        return link
    return None


def get_relative_data_component_url(datasource, datacomponent):
    """Create url of data component with parent data source"""
    return f"{get_relative_url_from_stix(stix_object=datasource)}/#{'%20'.join(datacomponent['name'].split(' '))}"


def deep_copy_stix(stix_objects):
    """Transform stix to dict and deep copy the dict."""
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


def get_attack_id(stix_obj) -> Optional[str]:
    """Get the object's ATT&CK ID.

    Parameters
    ----------
    stix_obj :
        The STIX object

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


def get_attack_object_version(stix_obj) -> Optional[float]:
    """Get the object's ATT&CK version.

    Parameters
    ----------
    stix_obj :
        The STIX object

    Returns
    -------
    Optional[float]
        The object version of the ATT&CK object. Defaults to 0.0
    """
    # ICS objects didn't have x_mitre_version until v11.0, so pretend they were version 0.0
    version = stix_obj.get("x_mitre_version", 0)
    return float(version)


def markdown_to_html(outfile, content, diffStix):
    """Convert the markdown string passed in to HTML and store in index.html
    of indicated output file path"""
    logger.info("Writing HTML to file")
    old_version = diffStix.data["old"]["attack_release_versions"]["enterprise-attack"]
    new_version = diffStix.data["new"]["attack_release_versions"]["enterprise-attack"]
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


def write_detailed_html(html_file_detailed, diffStix):
    old_version = diffStix.data["old"]["attack_release_versions"]["enterprise-attack"]
    new_version = diffStix.data["new"]["attack_release_versions"]["enterprise-attack"]

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

    with open(html_file_detailed, "w") as file:
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
                                stix_object=stix_object, datastore_version=datastore_version
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
                                lines.append(f"<p><b>Description</b>: {stix_object['description']}</p>")

                        if change_type == "revocations":
                            revoked_by_id = get_attack_id(stix_object["revoked_by"])
                            revoked_by_name = stix_object["revoked_by"]["name"]
                            revoked_by_description = stix_object["revoked_by"]["description"]
                            lines.append("<font color=blue>")
                            lines.append(f"<p>This object has been revoked by [{revoked_by_id}] {revoked_by_name}</p>")
                            lines.append("</font>")
                            if revoked_by_description:
                                lines.append(f"<p><b>Description for [{revoked_by_id}] {revoked_by_name}</b>: {revoked_by_description}</p>")

                        version_change = stix_object.get("version_change")
                        if version_change:
                            lines.append(f"<p><b>Version changed from</b>: {version_change}</p>")

                        description_change_table = stix_object.get("description_change_table")
                        if description_change_table:
                            lines.append(description_change_table)

                        detailed_diff = json.loads(stix_object.get("detailed_diff", "{}"))
                        if detailed_diff:
                            lines.append("<details>")
                            lines.append(f"<summary>Details</summary>")
                            table_inline_css = "style='border: 1px solid black;border-collapse: collapse;'"

                            # the deepdiff library displays differences with a prefix of: root['<top-level-key-we-care-about>']
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
            "Create -markdown and/or -layers reporting on the changes between two versions of the ATT&CK content. "
            "Takes STIX bundles as input. For default operation, put enterprise-attack.json and mobile-attack.json bundles "
            "in 'old' and 'new' folders for the script to compare."
        )
    )

    parser.add_argument(
        "-old",
        type=str,
        default="old",
        help=f"Directory to load old STIX data from.",
    )

    parser.add_argument(
        "-new",
        type=str,
        default="new",
        help="Directory to load new STIX data from.",
    )

    parser.add_argument(
        "-types",
        type=str,
        nargs="+",
        choices=["technique", "software", "group", "campaign", "mitigation", "datasource"],
        default=["technique", "software", "group", "campaign", "mitigation", "datasource"],
        help="Which types of objects to report on. Choices (and defaults) are %(choices)s",
    )
    parser.add_argument(
        "-domains",
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
        "-layers",
        type=str,
        nargs="*",
        help=f"""
            Create layer files showing changes in each domain
            expected order of filenames is 'enterprise', 'mobile', 'ics', 'pre attack'.
            If values are unspecified, defaults to {", ".join(layer_defaults)}
            """,
    )

    parser.add_argument(
        "-site_prefix",
        type=str,
        default="",
        help="Prefix links in markdown output, e.g. [prefix]/techniques/T1484",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print status messages",
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

    args = parser.parse_args()

    # the default loguru logger logs up to Debug by default
    logger.remove()
    if args.verbose:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True)
    else:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True, level="INFO")

    if args.use_mitre_cti and args.old:
        parser.error("--use-mitre-cti and -old cannot be used together")

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
    types: List[str] = ["technique", "software", "group", "campaign", "mitigation", "datasource"],
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
    types : List[str], optional
        Which types of objects to report on, by default ["technique", "software", "group", "campaign", "mitigation", "datasource"]
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

    if old and use_mitre_cti:
        logger.error("Multiple sources selected as base STIX to compare against.")
        logger.error("When calling get_new_changelog_md(), 'old' is mutually exclusive with 'use_mitre_cti'")
        return ""

    diffStix = DiffStix(
        domains=domains,
        layers=layers,
        unchanged=unchanged,
        old=old,
        new=new,
        show_key=show_key,
        site_prefix=site_prefix,
        types=types,
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
        json.dump(changes_dict, open(json_file, "w"), indent=4)

    return md_string


def main():
    args = get_parsed_args()

    get_new_changelog_md(
        domains=args.domains,
        layers=args.layers,
        unchanged=args.unchanged,
        old=args.old,
        new=args.new,
        show_key=args.show_key,
        site_prefix=args.site_prefix,
        types=args.types,
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