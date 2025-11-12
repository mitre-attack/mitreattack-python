"""Data loader for ATT&CK STIX content."""

import os
import sys

import requests
import stix2
from loguru import logger
from requests.adapters import HTTPAdapter, Retry
from stix2 import Filter, MemoryStore

from mitreattack import release_info
from mitreattack.diffStix.utils.stix_utils import deep_copy_stix


class DataLoader:
    """Loads and parses ATT&CK STIX data from files or GitHub."""

    def __init__(self, diff_stix_instance):
        """Initialize DataLoader with a DiffStix instance.

        Parameters
        ----------
        diff_stix_instance : DiffStix
            The DiffStix instance containing data and helper methods
        """
        self.diff_stix = diff_stix_instance

    def load_domain(self, domain: str):
        """Load data from directory according to domain.

        Parameters
        ----------
        domain : str
            An ATT&CK domain from the following list ["enterprise-attack", "mobile-attack", "ics-attack"]
        """
        for datastore_version in ["old", "new"]:
            # only allow github.com/mitre/cti to be used for the old STIX domain
            if self.diff_stix.use_mitre_cti and datastore_version == "old":
                data_store = self.get_datastore_from_mitre_cti(domain=domain, datastore_version=datastore_version)
            else:
                directory = self.diff_stix.old if datastore_version == "old" else self.diff_stix.new
                if directory is None:
                    raise ValueError(
                        f"Directory path for {datastore_version} data cannot be None when not using MITRE CTI"
                    )
                stix_file = os.path.join(directory, f"{domain}.json")

                attack_version = release_info.get_attack_version(domain=domain, stix_file=stix_file)
                self.diff_stix.data[datastore_version][domain]["attack_release_version"] = attack_version

                data_store = MemoryStore()
                data_store.load_from_file(stix_file)

            self.diff_stix.data[datastore_version][domain]["stix_datastore"] = data_store
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
        self.diff_stix.data[datastore_version][domain]["attack_release_version"] = attack_version

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
            "detectionstrategies": [Filter("type", "=", "x-mitre-detection-strategy")],
            "analytics": [Filter("type", "=", "x-mitre-analytic")],
        }
        for object_type, stix_filters in attack_type_to_stix_filter.items():
            raw_data = []
            for stix_filter in stix_filters:
                temp_filtered_list = data_store.query(stix_filter)
                raw_data.extend(temp_filtered_list)

            raw_data = deep_copy_stix(raw_data)
            self.diff_stix.data[datastore_version][domain]["attack_objects"][object_type] = {
                attack_object["id"]: attack_object for attack_object in raw_data
            }

        subtechnique_relationships = data_store.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "subtechnique-of"),
            ]
        )
        self.diff_stix.data[datastore_version][domain]["relationships"]["subtechniques"] = {
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
            if source_id not in self.diff_stix.data[datastore_version][domain]["relationships"]["revoked-by"]:
                self.diff_stix.data[datastore_version][domain]["relationships"]["revoked-by"][source_id] = []
            self.diff_stix.data[datastore_version][domain]["relationships"]["revoked-by"][source_id].append(
                relationship
            )

        mitigating_relationships = data_store.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "mitigates"),
            ]
        )
        self.diff_stix.data[datastore_version][domain]["relationships"]["mitigations"] = {
            relationship["id"]: relationship for relationship in mitigating_relationships
        }

        detection_relationships = data_store.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "detects"),
            ]
        )
        self.diff_stix.data[datastore_version][domain]["relationships"]["detections"] = {
            relationship["id"]: relationship for relationship in detection_relationships
        }
