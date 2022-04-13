import argparse
import datetime
import json
import os
from itertools import chain
from pathlib import Path
from typing import List

import markdown
import requests
import urllib3
from dateutil import parser as dateparser
from loguru import logger
from stix2 import Filter, MemoryStore, TAXIICollectionSource
from taxii2client.v20 import Collection
from tqdm import tqdm

# helper maps
domainToDomainLabel = {"enterprise-attack": "Enterprise", "mobile-attack": "Mobile"}
domainToTaxiiCollectionId = {
    "enterprise-attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
    "mobile-attack": "2f669986-b40b-4423-b720-4396ca6a462b",
}
# stix filters for querying for each type of data
attackTypeToStixFilter = {
    "technique": [Filter("type", "=", "attack-pattern")],
    "software": [Filter("type", "=", "malware"), Filter("type", "=", "tool")],
    "group": [Filter("type", "=", "intrusion-set")],
    "mitigation": [Filter("type", "=", "course-of-action")],
    "datasource": [
        Filter("type", "=", "x-mitre-data-source"),
        Filter("type", "=", "x-mitre-data-component"),
    ],
    "datasource-only": [Filter("type", "=", "x-mitre-data-source")],
}
# ATT&CK type to Title
attackTypeToTitle = {
    "technique": "Techniques",
    "malware": "Malware",
    "software": "Software",
    "group": "Groups",
    "mitigation": "Mitigations",
    "datasource": "Data Sources and/or Components",
}
# ATT&CK type to section name
attackTypeToSectionName = {
    "technique": "Technique",
    "malware": "Malware",
    "software": "Software",
    "group": "Group",
    "mitigation": "Mitigation",
    "datasource": "Data Source and/or Component",
}
# how we want to format headers for each section
sectionNameToSectionHeaders = {
    "additions": "New {obj_type}",
    "changes": "{obj_type} changes",
    "minor_changes": "Minor {obj_type} changes",
    "deprecations": "{obj_type} deprecations",
    "revocations": "{obj_type} revocations",
    "deletions": "{obj_type} deletions",
    "unchanged": "Unchanged {obj_type}",
}
# color key for layers
statusToColor = {
    "additions": "#a1d99b",
    "changes": "#fcf3a2",
    "minor_changes": "#c7c4e0",
    "deletions": "#ff00e1",  # this will probably never show up but just in case
    "revocations": "#ff9000",
    "deprecations": "#ff6363",
    "unchanged": "#ffffff",
}
# explanation of modification types to data objects for legend in layer files
statusDescriptions = {
    "additions": "objects which are present in the new data and not the old",
    "changes": "objects which have a newer version number in the new data compared to the old",
    "minor_changes": "objects which have a newer last edit date in the new data than in the old, but the same version number",
    "revocations": "objects which are revoked in the new data but not in the old",
    "deprecations": "objects which are deprecated in the new data but not in the old",
    "deletions": "objects which are present in the old data but not the new",
    "unchanged": "objects which did not change between the two versions",
}
date = datetime.datetime.today()
this_month = date.strftime("%B_%Y")
layer_defaults = [
    os.path.join("output", f"{this_month}_Updates_Enterprise.json"),
    os.path.join("output", f"{this_month}_Updates_Mobile.json"),
    os.path.join("output", f"{this_month}_Updates_Pre.json"),
]
md_default = os.path.join("output", f"updates-{this_month.lower()}.md")
json_default = os.path.join("output", f"updates-{this_month.lower()}.json")


class DiffStix(object):
    """Utilities for detecting and summarizing differences between two versions of the ATT&CK content."""

    def __init__(
        self,
        domains=["enterprise-attack", "mobile-attack"],
        layers=None,
        markdown=None,
        minor_changes=False,
        unchanged=False,
        new="new",
        old="old",
        show_key=False,
        site_prefix="",
        types=["technique", "software", "group", "mitigation", "datasource"],
        use_taxii=False,
        use_mitre_cti=False,
        verbose=False,
        include_contributors=False,
        release_contributors={},
    ):
        """Construct a new DiffStix object.

        params:
            domains: list of domains to parse, e.g. enterprise-attack, mobile-attack
            layers: array of output filenames for layer files, e.g. ['enterprise.json', 'mobile.json', 'pre.json']
            markdown: output filename for markdown content to be written to
            minor_changes: if true, also report minor changes section (changes which didn't increment version)
            new: directory to load for new stix version
            old: directory to load for old stix version
            show_key: if true, output key to markdown file
            site_prefix: prefix links in markdown output
            types: which types of objects to report on, e.g technique, software
            verbose: if true, print progress bar and status messages to stdout
        """
        self.domains = domains
        self.layers = layers
        self.markdown = markdown
        self.minor_changes = minor_changes
        self.unchanged = unchanged
        self.new = new
        self.old = old
        self.show_key = show_key
        self.site_prefix = site_prefix
        self.types = types
        self.use_taxii = use_taxii
        self.use_mitre_cti = use_mitre_cti
        self.verbose = verbose
        self.include_contributors = include_contributors
        # will hold information of contributors of the new release {... {"contributor_credit/name_as_key": counter]} ...}
        self.release_contributors = {}

        # data gets load into here in the load() function. All other functionalities rely on this data structure
        self.data = {
            # {
            #   technique: {
            #     enterprise-attack: {
            #       additions: [],
            #       deletions: [],
            #       changes: [],
            #       minor_changes: [],
            #       revocations: [],
            #       deprecations: [],
            #       unchanged: [],
            #     },
            #     mobile-attack: {...},
            #   },
            #   software: {...},
            # }
        }

        # stixID to object name
        self.stixIDToName = {}

        # all subtechnique-of relationships in the new/old data
        self.new_subtechnique_of_rels = []
        self.old_subtechnique_of_rels = []

        # all data components in the new/old data
        self.new_datacomponents = []
        self.old_datacomponents = []

        # stixID => technique for every technique in the new/old data
        self.new_id_to_technique = {}
        self.old_id_to_technique = {}

        # stixID => data source for every data source in the new/old data
        self.new_id_to_datasource = {}
        self.old_id_to_datasource = {}

        # build the bove data structures
        self.load_data()

        logger.info("removing duplicate relationships")
        self.new_subtechnique_of_rels = [
            i
            for n, i in enumerate(self.new_subtechnique_of_rels)
            if i not in self.new_subtechnique_of_rels[n + 1 :]
        ]
        self.old_subtechnique_of_rels = [
            i
            for n, i in enumerate(self.old_subtechnique_of_rels)
            if i not in self.old_subtechnique_of_rels[n + 1 :]
        ]

        logger.info("removing duplicate data components")
        self.new_datacomponents = [
            i
            for n, i in enumerate(self.new_datacomponents)
            if i not in self.new_datacomponents[n + 1 :]
        ]
        self.old_datacomponents = [
            i
            for n, i in enumerate(self.old_datacomponents)
            if i not in self.old_datacomponents[n + 1 :]
        ]

    def getUrlFromStix(self, datum, is_subtechnique=False):
        """
        Parse the website url from a stix object.
        """
        if datum.get("external_references"):
            url = datum["external_references"][0]["url"]
            split_url = url.split("/")
            splitfrom = -3 if is_subtechnique else -2
            link = "/".join(split_url[splitfrom:])
            return link
        return None

    def getDataComponentUrl(self, datasource, datacomponent):
        """Create url of data component with parent data source"""
        return f"{self.getUrlFromStix(datasource)}/#{'%20'.join(datacomponent['name'].split(' '))}"

    def deep_copy_stix(self, objects):
        """Transform stix to dict and deep copy the dict."""
        result = []
        for obj in objects:
            obj = dict(obj)
            if "external_references" in obj:
                for i in range(len(obj["external_references"])):
                    obj["external_references"][i] = dict(obj["external_references"][i])
            if "kill_chain_phases" in obj:
                for i in range(len(obj["kill_chain_phases"])):
                    obj["kill_chain_phases"][i] = dict(obj["kill_chain_phases"][i])
            if "modified" in obj:
                obj["modified"] = str(obj["modified"])
            if "definition" in obj:
                obj["definition"] = dict(obj["definition"])
            obj["created"] = str(obj["created"])
            result.append(obj)
        return result

    # load data into data structure
    def load_data(self):
        """Load data from files into data dict."""
        pbar = tqdm(
            total=len(self.types) * len(self.domains),
            desc="loading data",
            bar_format="{l_bar}{bar}| [{elapsed}<{remaining}, {rate_fmt}{postfix}]",
        )
        for obj_type in self.types:
            for domain in self.domains:

                def load_datastore(data_store):
                    """Handle data loaded from either a directory or the TAXII server"""
                    raw_data = list(
                        chain.from_iterable(
                            data_store.query(f)
                            for f in attackTypeToStixFilter[obj_type]
                        )
                    )
                    raw_data = self.deep_copy_stix(raw_data)
                    id_to_obj = {item["id"]: item for item in raw_data}

                    return {
                        "id_to_obj": id_to_obj,
                        "keys": set(id_to_obj.keys()),
                        "data_store": data_store,
                    }

                def parse_subtechniques(data_store, new=False):
                    """Parse dataStore sub-technique-of relationships"""
                    if new:
                        for technique in list(
                            data_store.query(attackTypeToStixFilter["technique"])
                        ):
                            self.new_id_to_technique[technique["id"]] = technique
                        self.new_subtechnique_of_rels += list(
                            data_store.query(
                                [
                                    Filter("type", "=", "relationship"),
                                    Filter("relationship_type", "=", "subtechnique-of"),
                                ]
                            )
                        )
                    else:
                        for technique in list(
                            data_store.query(attackTypeToStixFilter["technique"])
                        ):
                            self.old_id_to_technique[technique["id"]] = technique
                        self.old_subtechnique_of_rels += list(
                            data_store.query(
                                [
                                    Filter("type", "=", "relationship"),
                                    Filter("relationship_type", "=", "subtechnique-of"),
                                ]
                            )
                        )

                def parse_datacomponents(data_store, new=False):
                    """Parse dataStore x-mitre-data-components"""
                    if new:
                        for datasource in list(
                            data_store.query(attackTypeToStixFilter["datasource-only"])
                        ):
                            self.new_id_to_datasource[datasource["id"]] = datasource
                        self.new_datacomponents += list(
                            data_store.query(
                                [Filter("type", "=", "x-mitre-data-component")]
                            )
                        )
                    else:
                        for datasource in list(
                            data_store.query(attackTypeToStixFilter["datasource-only"])
                        ):
                            self.old_id_to_datasource[datasource["id"]] = datasource
                        self.old_datacomponents += list(
                            data_store.query(
                                [Filter("type", "=", "x-mitre-data-component")]
                            )
                        )

                def update_contributors(old_object, new_object):
                    """Update contributors list if new object has contributors"""
                    if new_object.get("x_mitre_contributors"):
                        new_object_contributors = set(
                            new_object["x_mitre_contributors"]
                        )

                        # Check if old objects had contributors
                        if old_object is None or not old_object.get(
                            "x_mitre_contributors"
                        ):
                            old_object_contributors = set()
                        else:
                            old_object_contributors = set(
                                old_object["x_mitre_contributors"]
                            )

                        # Remove old contributors from showing up
                        # if contributors are the same the result will be empty
                        new_contributors = (
                            new_object_contributors - old_object_contributors
                        )

                        # Update counter of contributor to track contributions
                        for new_contributor in new_contributors:
                            if self.release_contributors.get(new_contributor):
                                self.release_contributors[new_contributor] += 1
                            else:
                                self.release_contributors[new_contributor] = 1

                def load_dir(dir, new=False):
                    """Load data from directory according to domain"""
                    data_store = MemoryStore()
                    datafile = os.path.join(dir, domain + ".json")
                    data_store.load_from_file(datafile)
                    parse_subtechniques(data_store, new)
                    parse_datacomponents(data_store, new)
                    return load_datastore(data_store)

                def load_taxii(new=False):
                    """Load data from TAXII server according to domain"""
                    collection = Collection(
                        "https://cti-taxii.mitre.org/stix/collections/"
                        + domainToTaxiiCollectionId[domain]
                    )
                    data_store = TAXIICollectionSource(collection)
                    parse_subtechniques(data_store, new)
                    parse_datacomponents(data_store, new)
                    return load_datastore(data_store)

                def load_mitre_cti(new=False):
                    """Load data from MITRE CTI repo according to domain"""
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                    stix_json = requests.get(
                        f"https://raw.githubusercontent.com/mitre/cti/master/{domain}/{domain}.json",
                        verify=False,
                    )
                    if stix_json.status_code == 200:
                        stix_json = stix_json.json()
                        data_store = MemoryStore(stix_data=stix_json["objects"])
                        parse_subtechniques(data_store, new)
                        parse_datacomponents(data_store, new)
                        return load_datastore(data_store)
                    exit(f"\n{domain} stix bundle download was unsuccessful")

                logger.debug(f"Loading: [{domain:17}]/{obj_type}")

                if self.use_taxii:
                    old = load_taxii(False)
                elif self.use_mitre_cti:
                    old = load_mitre_cti(False)
                else:
                    old = load_dir(self.old, False)
                new = load_dir(self.new, True)

                intersection = old["keys"] & new["keys"]
                additions = new["keys"] - old["keys"]
                deletions = old["keys"] - new["keys"]

                # sets to store the ids of objects for each section
                changes = set()
                minor_changes = set()
                revocations = set()
                deprecations = set()
                unchanged = set()

                # find changes, revocations and deprecations
                for key in intersection:

                    # find revoked objects in the new bundle
                    if (
                        "revoked" in new["id_to_obj"][key]
                        and new["id_to_obj"][key]["revoked"]
                    ):
                        # only work with newly revoked objects
                        if (
                            not "revoked" in old["id_to_obj"][key]
                            or not old["id_to_obj"][key]["revoked"]
                        ):
                            # store the revoking object
                            revoked_by_key = new["data_store"].query(
                                [
                                    Filter("type", "=", "relationship"),
                                    Filter("relationship_type", "=", "revoked-by"),
                                    Filter("source_ref", "=", key),
                                ]
                            )
                            if len(revoked_by_key) == 0:
                                logger.error(
                                    f"[{key}] revoked object has no revoked-by relationship"
                                )
                                continue
                            else:
                                revoked_by_key = revoked_by_key[0]["target_ref"]

                            if revoked_by_key not in new["id_to_obj"]:
                                logger.error(f"{key} revoked by {revoked_by_key}, but {revoked_by_key} not found in new STIX bundle!!")
                                continue

                            new["id_to_obj"][key]["revoked_by"] = new["id_to_obj"][
                                revoked_by_key
                            ]

                            revocations.add(key)
                        # else it was already revoked, and not a change; do nothing with it

                    # find deprecated objects
                    elif (
                        "x_mitre_deprecated" in new["id_to_obj"][key]
                        and new["id_to_obj"][key]["x_mitre_deprecated"]
                    ):
                        # if previously deprecated, not a change
                        if not "x_mitre_deprecated" in old["id_to_obj"][key]:
                            deprecations.add(key)

                    # find all other changed objects
                    else:
                        # try getting version numbers; should only lack version numbers if something has gone
                        # horribly wrong or a revoked object has slipped through
                        try:
                            old_version = float(
                                old["id_to_obj"][key]["x_mitre_version"]
                            )
                        except ValueError:
                            logger.error(
                                f"ERROR: cannot get old version for object: {key}"
                            )

                        try:
                            new_version = float(
                                new["id_to_obj"][key]["x_mitre_version"]
                            )
                        except ValueError:
                            logger.error(
                                f"ERROR: cannot get new version for object: {key}"
                            )

                        # Verify if there are new contributors on the object
                        update_contributors(
                            old["id_to_obj"][key], new["id_to_obj"][key]
                        )

                        # check for changes
                        if new_version > old_version:
                            # an update has occurred to this object
                            changes.add(key)
                        else:
                            # check for minor change; modification date increased but not version
                            old_date = dateparser.parse(
                                old["id_to_obj"][key]["modified"]
                            )
                            new_date = dateparser.parse(
                                new["id_to_obj"][key]["modified"]
                            )
                            if new_date > old_date:
                                minor_changes.add(key)
                            else:
                                unchanged.add(key)

                # Add contributions from additions
                for key in additions:
                    update_contributors(None, new["id_to_obj"][key])

                # set data
                if obj_type not in self.data:
                    self.data[obj_type] = {}
                self.data[obj_type][domain] = {
                    "additions": [new["id_to_obj"][key] for key in additions],
                    "changes": [new["id_to_obj"][key] for key in changes],
                }
                # only create minor_changes data if we want to display it later
                if self.minor_changes:
                    self.data[obj_type][domain]["minor_changes"] = [
                        new["id_to_obj"][key] for key in minor_changes
                    ]

                # ditto for unchanged
                if self.unchanged:
                    self.data[obj_type][domain]["unchanged"] = [
                        new["id_to_obj"][key] for key in unchanged
                    ]

                self.data[obj_type][domain]["revocations"] = [
                    new["id_to_obj"][key] for key in revocations
                ]
                self.data[obj_type][domain]["deprecations"] = [
                    new["id_to_obj"][key] for key in deprecations
                ]

                # only show deletions if objects were deleted
                if len(deletions) > 0:
                    self.data[obj_type][domain]["deletions"] = [
                        old["id_to_obj"][key] for key in deletions
                    ]

                logger.debug(f"Loaded:  [{domain:17}]/{obj_type}")
                pbar.update(1)
        pbar.close()

    def get_md_key(self):
        """Create string describing each type of difference (change, addition, etc).

        Used in get_markdown_string.

        Includes minor changes if the DiffStix instance was instantiated with the minor_changes argument.

        Includes deletions if the changes include deletions.
        """

        have_deletions = False
        for types in self.data.keys():
            for domain in self.data[types].keys():
                if "deletions" in self.data[types][domain].keys():
                    have_deletions = True

        key = "#### Key\n\n"
        key += (
            "* New objects: " + statusDescriptions["additions"] + "\n"
            "* Object changes: " + statusDescriptions["changes"] + "\n"
        )
        if self.minor_changes:
            key += (
                "* Minor object changes: " + statusDescriptions["minor_changes"] + "\n"
            )
        if self.unchanged:
            key += "* Unchanged objects: " + statusDescriptions["unchanged"] + "\n"
        key += (
            "* Object revocations: " + statusDescriptions["revocations"] + "\n"
            "* Object deprecations: " + statusDescriptions["deprecations"]
        )
        if have_deletions:
            key += "\n" + "* Object deletions: " + statusDescriptions["deletions"]
        return key

    def has_subtechniques(self, sdo, new=False):
        """Return true or false depending on whether the SDO has sub-techniques.

        new determines whether to parse from the new or old data"""
        if new:
            return (
                len(
                    list(
                        filter(
                            lambda rel: rel["target_ref"] == sdo["id"],
                            self.new_subtechnique_of_rels,
                        )
                    )
                )
                > 0
            )
        else:
            return (
                len(
                    list(
                        filter(
                            lambda rel: rel["target_ref"] == sdo["id"],
                            self.old_subtechnique_of_rels,
                        )
                    )
                )
                > 0
            )

    def get_groupings(
        self,
        obj_type,
        items,
        subtechnique_of_rels,
        id_to_technique,
        datacomponents,
        id_to_datasource,
    ):
        # get parents which have children
        if obj_type != "datasource":
            childless = list(
                filter(
                    lambda item: not self.has_subtechniques(item, True)
                    and not (
                        "x_mitre_is_subtechnique" in item
                        and item["x_mitre_is_subtechnique"]
                    ),
                    items,
                )
            )
            parents = list(
                filter(
                    lambda item: self.has_subtechniques(item, True)
                    and not (
                        "x_mitre_is_subtechnique" in item
                        and item["x_mitre_is_subtechnique"]
                    ),
                    items,
                )
            )
            children = {
                item["id"]: item
                for item in filter(
                    lambda item: ("x_mitre_is_subtechnique") in item
                    and (item["x_mitre_is_subtechnique"]),
                    items,
                )
            }
        else:
            childless = (
                []
            )  # all data sources should have data components, i.e., should have children
            parents = list(
                filter(
                    lambda item: not (
                        "x_mitre_data_source_ref" in item
                        and item["x_mitre_data_source_ref"]
                    ),
                    items,
                )
            )
            children = {
                item["id"]: item
                for item in filter(
                    lambda item: ("x_mitre_data_source_ref") in item
                    and (item["x_mitre_data_source_ref"]),
                    items,
                )
            }

        # stixID => [ children ]
        parentToChildren = {}
        for relationship in subtechnique_of_rels:
            if relationship["target_ref"] in parentToChildren:
                if relationship["source_ref"] in children:
                    parentToChildren[relationship["target_ref"]].append(
                        children[relationship["source_ref"]]
                    )
            else:
                if relationship["source_ref"] in children:
                    parentToChildren[relationship["target_ref"]] = [
                        children[relationship["source_ref"]]
                    ]

        for datacomponent in datacomponents:
            if datacomponent["x_mitre_data_source_ref"] in parentToChildren:
                if datacomponent["id"] in children:
                    parentToChildren[datacomponent["x_mitre_data_source_ref"]].append(
                        children[datacomponent["id"]]
                    )
            else:
                if datacomponent["id"] in children:
                    parentToChildren[datacomponent["x_mitre_data_source_ref"]] = [
                        children[datacomponent["id"]]
                    ]

        # now group parents and children
        groupings = []
        for parent in childless + parents:
            parent_children = (
                parentToChildren.pop(parent["id"])
                if parent["id"] in parentToChildren
                else []
            )
            groupings.append(
                {
                    "parent": parent,
                    "parentInSection": True,
                    "children": parent_children,
                }
            )

        for parentID in parentToChildren:
            if id_to_technique.get(parentID):
                parentObj = id_to_technique[parentID]
            elif id_to_datasource.get(parentID):
                parentObj = id_to_datasource[parentID]

            if parentObj:
                groupings.append(
                    {
                        "parent": parentObj,
                        "parentInSection": False,
                        "children": parentToChildren[parentID],
                    }
                )

        groupings = sorted(groupings, key=lambda grouping: grouping["parent"]["name"])
        return groupings

    def get_markdown_string(self):
        """Return a markdown string summarizing detected differences."""

        def getSectionList(items, obj_type, section):
            """Parse a list of items in a section and return a string for the items."""
            logger.debug(f"getting section list for {obj_type}/{section}")

            if section == "deletions":
                subtechnique_of_rels = self.old_subtechnique_of_rels
                id_to_technique = self.old_id_to_technique
                datacomponents = self.old_datacomponents
                id_to_datasource = self.old_id_to_datasource
            else:
                subtechnique_of_rels = self.new_subtechnique_of_rels
                id_to_technique = self.new_id_to_technique
                datacomponents = self.new_datacomponents
                id_to_datasource = self.new_id_to_datasource

            def placard(item):
                """Get a section list item for the given SDO according to section type"""
                if section == "revocations":
                    revoker = item["revoked_by"]
                    if (
                        "x_mitre_is_subtechnique" in revoker
                        and revoker["x_mitre_is_subtechnique"]
                    ):
                        # get revoking technique's parent for display
                        parentID = list(
                            filter(
                                lambda rel: rel["source_ref"] == revoker["id"],
                                subtechnique_of_rels,
                            )
                        )[0]["target_ref"]
                        parentName = (
                            id_to_technique[parentID]["name"]
                            if parentID in id_to_technique
                            else "ERROR NO PARENT"
                        )
                        return f"{item['name']} (revoked by { parentName}: [{revoker['name']}]({self.site_prefix}/{self.getUrlFromStix(revoker, True)}))"
                    elif (
                        "x_mitre_data_source_ref" in revoker
                        and revoker["x_mitre_data_source_ref"]
                    ):
                        # get revoking technique's parent for display
                        parentID = list(
                            filter(
                                lambda rel: rel["id"] == revoker["id"], datacomponents
                            )
                        )[0]["x_mitre_data_source_ref"]
                        parentName = (
                            id_to_datasource[parentID]["name"]
                            if parentID in id_to_datasource
                            else "ERROR NO PARENT"
                        )
                        return f"{item['name']} (revoked by { parentName}: [{revoker['name']}]({self.site_prefix}/{self.getDataComponentUrl(id_to_datasource[parentID], item)}))"
                    else:
                        return f"{item['name']} (revoked by [{revoker['name']}]({self.site_prefix}/{self.getUrlFromStix(revoker)}))"
                elif section == "deletions":
                    return f"{item['name']}"
                else:
                    is_subtechnique = (
                        item["type"] == "attack-pattern"
                        and "x_mitre_is_subtechnique" in item
                        and item["x_mitre_is_subtechnique"]
                    )
                    if item["type"] == "x-mitre-data-component":
                        parentID = item["x_mitre_data_source_ref"]
                        if id_to_datasource.get(parentID):
                            return f"[{item['name']}]({self.site_prefix}/{self.getDataComponentUrl(id_to_datasource[parentID], item)})"
                    return f"[{item['name']}]({self.site_prefix}/{self.getUrlFromStix(item, is_subtechnique)})"

            groupings = self.get_groupings(
                obj_type=obj_type,
                items=items,
                subtechnique_of_rels=subtechnique_of_rels,
                id_to_technique=id_to_technique,
                datacomponents=datacomponents,
                id_to_datasource=id_to_datasource,
            )

            # build sectionList string
            sectionString = ""
            for grouping in groupings:
                if grouping["parentInSection"]:
                    sectionString += f"* { placard(grouping['parent']) }\n"

                for child in sorted(
                    grouping["children"], key=lambda child: child["name"]
                ):
                    if grouping["parentInSection"]:
                        sectionString += f"  * {placard(child) }\n"
                    else:
                        sectionString += (
                            f"* {grouping['parent']['name']}: { placard(child) }\n"
                        )

            logger.debug(f"finished getting section list for {obj_type}/{section}")
            # logger.debug(sectionString)
            return sectionString

        def getContributorSection():
            # Get contributors markdown
            contribSection = "### Contributors to this release\n\n"
            sorted_contributors = sorted(
                self.release_contributors, key=lambda v: v.lower()
            )

            for contributor in sorted_contributors:
                if contributor == "ATT&CK":
                    continue  # do not include ATT&CK as contributor
                contribSection += f"* {contributor}\n"

            return contribSection

        logger.info("generating markdown string")
        content = ""
        for obj_type in self.data.keys():
            domains = ""
            for domain in self.data[obj_type]:
                logger.debug(
                    f"==== Generating markdown for domain: {domainToDomainLabel[domain]} --- {obj_type} ===="
                )
                domains += f"#### {domainToDomainLabel[domain]}\n\n"  # e.g "Enterprise"
                # Skip mobile sections for data sources
                if domain == "mobile-attack" and obj_type == "datasource":
                    logger.debug(
                        f"Skipping - ATT&CK for Mobile does not support data sources"
                    )
                    domains += "ATT&CK for Mobile does not support data sources\n\n"
                    continue
                domain_sections = ""
                for section, values in self.data[obj_type][domain].items():
                    logger.debug(f"{section}: {len(values)}")

                    if values:  # if there are items in the section
                        section_items = getSectionList(
                            items=values, obj_type=obj_type, section=section
                        )
                    else:  # no items in section
                        section_items = "* No changes\n"

                    header = sectionNameToSectionHeaders[section] + ":"

                    if "{obj_type}" in header:
                        if section == "additions":
                            header = header.replace(
                                "{obj_type}", attackTypeToTitle[obj_type]
                            )
                        else:
                            header = header.replace(
                                "{obj_type}", attackTypeToSectionName[obj_type]
                            )

                    # e.g "added techniques:"
                    domain_sections += f"{header}\n\n{section_items}\n"

                # add domain sections
                domains += f"{domain_sections}"

            # e.g "techniques"
            content += f"### {attackTypeToTitle[obj_type]}\n\n{domains}"

        if self.show_key:
            key_content = self.get_md_key()
            content = f"{key_content}\n\n{content}"

        # Add contributors if requested by argument
        if self.include_contributors:
            content += getContributorSection()

        logger.info("finished generating markdown string")

        return content

    def get_layers_dict(self):
        """Return ATT&CK Navigator layers in dict format summarizing detected differences.

        Returns a dict mapping domain to its layer dict.
        """
        logger.info("generating layers dict")

        layers = {}
        thedate = datetime.datetime.today().strftime("%B %Y")
        # for each layer file in the domains mapping
        for domain in self.domains:
            logger.debug(f"===== Generating layer for domain: {domain} =====")
            # build techniques list
            techniques = []
            used_statuses = set()
            for status in self.data["technique"][domain]:
                logger.debug(f"Parsing: {status}")
                if status == "revocations" or status == "deprecations":
                    continue
                for technique in self.data["technique"][domain][status]:
                    problem_detected = False
                    if "kill_chain_phases" not in technique:
                        logger.error(
                            f"{technique['id']}: technique missing a tactic!! {technique['name']}"
                        )
                        problem_detected = True
                    if "external_references" not in technique:
                        logger.error(
                            f"{technique['id']}: technique missing external references!! {technique['name']}"
                        )
                        problem_detected = True

                    if problem_detected:
                        continue

                    for phase in technique["kill_chain_phases"]:
                        techniques.append(
                            {
                                "techniqueID": technique["external_references"][0][
                                    "external_id"
                                ],
                                "tactic": phase["phase_name"],
                                "enabled": True,
                                "color": statusToColor[status],
                                "comment": status[:-1]
                                if status != "unchanged"
                                else status,  # trim s off end of word
                            }
                        )
                        used_statuses.add(status)

            # build legend based off used_statuses
            legendItems = list(
                map(
                    lambda status: {
                        "color": statusToColor[status],
                        "label": status + ": " + statusDescriptions[status],
                    },
                    used_statuses,
                )
            )

            # build layer structure
            layer_json = {
                "versions": {"layer": "4.1", "navigator": "4.1"},
                "name": f"{thedate} {domainToDomainLabel[domain]} Updates",
                "description": f"{domainToDomainLabel[domain]} updates for the {thedate} release of ATT&CK",
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

        logger.info("finished generating layers dict")
        return layers

    def get_changes_dict(self):
        """Return dict format summarizing detected differences."""
        logger.info("generating changes dict")

        def cleanup_values(items, obj_type, section):
            if section == "deletions":
                subtechnique_of_rels = self.old_subtechnique_of_rels
                id_to_technique = self.old_id_to_technique
                datacomponents = self.old_datacomponents
                id_to_datasource = self.old_id_to_datasource
            else:
                subtechnique_of_rels = self.new_subtechnique_of_rels
                id_to_technique = self.new_id_to_technique
                datacomponents = self.new_datacomponents
                id_to_datasource = self.new_id_to_datasource

            groupings = self.get_groupings(
                obj_type=obj_type,
                items=items,
                subtechnique_of_rels=subtechnique_of_rels,
                id_to_technique=id_to_technique,
                datacomponents=datacomponents,
                id_to_datasource=id_to_datasource,
            )

            new_values = []
            for grouping in groupings:
                if grouping["parentInSection"]:
                    new_values.append(grouping["parent"])

                for child in sorted(
                    grouping["children"], key=lambda child: child["name"]
                ):
                    new_values.append(child)

            return new_values

        changes_dict = {}
        for domain in self.domains:
            changes_dict[domain] = {}

        for obj_type, domains in self.data.items():
            for domain, sections in domains.items():
                logger.debug(
                    f"===== Generating domain: {domainToDomainLabel[domain]} --- {obj_type} ====="
                )
                changes_dict[domain][obj_type] = {}

                for section, values in sections.items():
                    # new_values includes parents & children mixed (e.g. techniques/sub-techniques, data sources/components)
                    new_values = cleanup_values(
                        items=values, obj_type=obj_type, section=section
                    )
                    changes_dict[domain][obj_type][section] = new_values

        # always add contributors
        changes_dict["new-contributors"] = []
        sorted_contributors = sorted(self.release_contributors, key=lambda v: v.lower())
        for contributor in sorted_contributors:
            if contributor == "ATT&CK":
                continue  # do not include ATT&CK as contributor
            changes_dict["new-contributors"].append(contributor)

        logger.info("finished generating changes dict")
        return changes_dict


def markdown_to_index_html(markdown_outfile, content):
    """Convert the markdown string passed in to HTML and store in index.html
    of indicated output file path"""
    logger.info("writing HTML to file")

    # get output file path
    outputfile_path = os.path.split(markdown_outfile)[0]
    outfile = os.path.join(outputfile_path, "index.html")

    # Center content
    html_string = """<div style='max-width: 55em;margin: auto;margin-top:20px;font-family: "Roboto", sans-serif;'>"""
    html_string += "<meta charset='utf-8'>"
    html_string += (
        "<h1 style='text-align:center;'>Changes between ATT&CK STIX bundles</h1>"
    )
    html_string += markdown.markdown(content)
    html_string += "</div>"

    outfile = open(outfile, "w", encoding="utf-8")
    outfile.write(html_string)
    outfile.close()

    logger.info("finished writing HTML to file")


def layers_dict_to_files(outfiles, layers):
    """Print the layers dict passed in to layer files."""
    logger.info("writing layers dict to layer files")

    # write each layer to separate files
    if "enterprise-attack" in layers:
        enterprise_attack_layer_file = outfiles[0]
        Path(enterprise_attack_layer_file).parent.mkdir(parents=True, exist_ok=True)
        json.dump(layers["enterprise-attack"], open(enterprise_attack_layer_file, "w"), indent=4)

    if "mobile-attack" in layers:
        mobile_attack_layer_file = outfiles[1]
        Path(mobile_attack_layer_file).parent.mkdir(parents=True, exist_ok=True)
        json.dump(layers["mobile-attack"], open(mobile_attack_layer_file, "w"), indent=4)

    logger.info("finished writing layers dict to layer files")


def get_parsed_args():
    """Create argument parser and parse arguments"""
    old_dir_default = "old"

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
        metavar="OLD_DIR",
        help=f"the directory of the old content. Default is '{old_dir_default}'",
    )

    parser.add_argument(
        "-new",
        type=str,
        metavar="NEW_DIR",
        default="new",
        help="the directory of the new content. Default is '%(default)s'",
    )

    parser.add_argument(
        "-types",
        type=str,
        nargs="+",
        metavar=("OBJ_TYPE", "OBJ_TYPE"),
        choices=["technique", "software", "group", "mitigation", "datasource"],
        default=["technique", "software", "group", "mitigation", "datasource"],
        help="which types of objects to report on. Choices (and defaults) are %(choices)s",
    )

    parser.add_argument(
        "-domains",
        type=str,
        nargs="+",
        metavar="DOMAIN",
        choices=["enterprise-attack", "mobile-attack"],
        default=["enterprise-attack", "mobile-attack"],
        help="which domains to report on. Choices (and defaults) are %(choices)s",
    )

    parser.add_argument(
        "-markdown",
        type=str,
        nargs="?",
        metavar="MARKDOWN_FILE",
        const=md_default,
        help="create a markdown file reporting changes. If value is unspecified, defaults to %(const)s",
    )

    parser.add_argument(
        "-json-output",
        type=str,
        nargs="?",
        metavar="JSON_FILE",
        const=json_default,
        help="create a JSON file reporting changes. If value is unspecified, defaults to %(const)s",
    )

    parser.add_argument(
        "--create-html",
        action="store_true",
        help="create index.html page of markdown file that reported changes. Does not do anything unless -markdown is provided",
    )

    parser.add_argument(
        "-layers",
        type=str,
        nargs="*",
        # metavar=("ENTERPRISE", "MOBILE", "PRE"),
        help=f"""
            create layer files showing changes in each domain
            expected order of filenames is 'enterprise', 'mobile', 'pre attack'. 
            If values are unspecified, defaults to {", ".join(layer_defaults)}
            """,
    )

    parser.add_argument(
        "-site_prefix",
        type=str,
        default="",
        help="prefix links in markdown output, e.g. [prefix]/techniques/T1484",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print status messages",
    )

    parser.add_argument(
        "--minor-changes",
        action="store_true",
        help="show changes to objects which didn't increment the version number",
    )

    parser.add_argument(
        "--unchanged",
        action="store_true",
        help="show objects without changes in the markdown output",
    )

    parser.add_argument(
        "--use-taxii",
        action="store_true",
        help="Use content from the ATT&CK TAXII server for the -old data",
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
        help="show new contributors between releases",
    )

    args = parser.parse_args()

    # the default loguru logger logs up to Debug by default
    logger.remove()
    if args.verbose:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True)
    else:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True, level="INFO")

    if args.use_taxii and args.old is not None:
        parser.error("--use-taxii and -old cannot be used together")

    if args.use_mitre_cti and args.old is not None:
        parser.error("--use-mitre-cti and -old cannot be used together")

    if not args.markdown and args.layers is None:
        logger.error(
            "Script doesn't output anything unless -markdown and/or -layers are specified."
        )
        logger.error("Run 'python3 diff_stix.py -h' for usage instructions")
        exit()

    if args.old is None:
        args.old = old_dir_default

    if args.layers is not None:
        if len(args.layers) not in [0, 3]:
            parser.error(
                "-layers requires exactly three files to be specified or none at all"
            )

    return args


# Used by attack-website script to generate changelog
def get_new_changelog_md(
    domains: List[str] = ["enterprise-attack", "mobile-attack"],
    layers: List[str] = layer_defaults,
    markdown_file: str = md_default,
    minor_changes: bool = False,
    unchanged: bool = False,
    new: str = "new",
    old: str = None,
    show_key: bool = False,
    site_prefix: str = "",
    types: List[str] = ["technique", "software", "group", "mitigation", "datasource"],
    use_taxii: bool = False,
    use_mitre_cti: bool = False,
    verbose: bool = False,
    include_contributors: bool = False,
    create_html: bool = False,
    json_output: str = json_default,
):
    # the default loguru logger logs up to Debug by default
    logger.remove()
    if verbose:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True)
    else:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True, level="INFO")

    # if old:
    #     if use_mitre_cti or use_taxii:
    #         logger.error("Multiple sources selected as base STIX to compare against.")
    #         logger.error("When calling get_new_changelog_md(), 'old' is mutually exclusive with 'use_taxii' and 'use_mitre_cti'")
    #         return ""

    diffStix = DiffStix(
        domains=domains,
        layers=layers,
        markdown=markdown_file,
        minor_changes=minor_changes,
        unchanged=unchanged,
        new=new,
        old=old,
        show_key=show_key,
        site_prefix=site_prefix,
        types=types,
        use_taxii=use_taxii,
        use_mitre_cti=use_mitre_cti,
        verbose=verbose,
        include_contributors=include_contributors,
    )

    md_string = None
    if markdown_file:
        md_string = diffStix.get_markdown_string()

        logger.info("writing markdown to file")
        Path(markdown_file).parent.mkdir(parents=True, exist_ok=True)
        with open(markdown_file, "w") as file:
            file.write(md_string)
        logger.info("finished writing markdown to file")

        if create_html:
            markdown_to_index_html(markdown_file, md_string)

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

    if json_output:
        changes_dict = diffStix.get_changes_dict()

        logger.info("writing JSON updates to file")
        Path(json_output).parent.mkdir(parents=True, exist_ok=True)
        json.dump(changes_dict, open(json_output, "w"), indent=4)
        logger.info("finished writing JSON updates to file")

    return md_string


def main():
    args = get_parsed_args()

    get_new_changelog_md(
        domains=args.domains,
        layers=args.layers,
        markdown_file=args.markdown,
        minor_changes=args.minor_changes,
        unchanged=args.unchanged,
        new=args.new,
        old=args.old,
        show_key=args.show_key,
        site_prefix=args.site_prefix,
        types=args.types,
        use_taxii=args.use_taxii,
        use_mitre_cti=args.use_mitre_cti,
        verbose=args.verbose,
        include_contributors=args.contributors,
        create_html=args.create_html,
        json_output=args.json_output,
    )


if __name__ == "__main__":
    main()
