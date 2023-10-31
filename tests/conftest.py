import os
import shutil

import pytest
from loguru import logger
from stix2 import MemoryStore

from mitreattack.download_stix import download_domains
from mitreattack.navlayers import Layer
from mitreattack.release_info import LATEST_VERSION
from mitreattack.stix20 import MitreAttackData

from .resources.testing_data import example_layer_v3_all, example_layer_v43_dict

STIX_LOCATION_ENTERPRISE = os.getenv("STIX_LOCATION_ENTERPRISE")
STIX_LOCATION_MOBILE = os.getenv("STIX_LOCATION_MOBILE")
STIX_LOCATION_ICS = os.getenv("STIX_LOCATION_ICS")


@pytest.fixture(autouse=True, scope="session")
def attack_stix_dir():
    logger.debug("Downloading the ATT&CK STIX 2.0!!!")
    download_dir = "attack-releases"
    download_domains(
        domains=["enterprise", "mobile", "ics"],
        download_dir=download_dir,
        all_versions=False,
        stix_version="2.0",
    )

    yield download_dir

    shutil.rmtree(download_dir)


@pytest.fixture(scope="session")
def stix_file_enterprise_latest(attack_stix_dir):
    if STIX_LOCATION_ENTERPRISE:
        return STIX_LOCATION_ENTERPRISE
    return f"{attack_stix_dir}/v{LATEST_VERSION}/enterprise-attack.json"


@pytest.fixture(scope="session")
def stix_file_mobile_latest(attack_stix_dir):
    if STIX_LOCATION_MOBILE:
        return STIX_LOCATION_MOBILE
    return f"{attack_stix_dir}/v{LATEST_VERSION}/mobile-attack.json"


@pytest.fixture(scope="session")
def stix_file_ics_latest(attack_stix_dir):
    if STIX_LOCATION_ICS:
        return STIX_LOCATION_ICS
    return f"{attack_stix_dir}/v{LATEST_VERSION}/ics-attack.json"


@pytest.fixture(scope="session")
def memstore_enterprise_latest(stix_file_enterprise_latest):
    logger.debug("Loading STIX memstore for Enterprise ATT&CK")
    mem_store = MemoryStore()
    mem_store.load_from_file(stix_file_enterprise_latest)
    return mem_store


@pytest.fixture(scope="session")
def memstore_mobile_latest(stix_file_mobile_latest):
    logger.debug("Loading STIX memstore for Mobile ATT&CK")
    mem_store = MemoryStore()
    mem_store.load_from_file(stix_file_mobile_latest)
    return mem_store


@pytest.fixture(scope="session")
def memstore_ics_latest(stix_file_ics_latest):
    logger.debug("Loading STIX memstore for ICS ATT&CK")
    mem_store = MemoryStore()
    mem_store.load_from_file(stix_file_ics_latest)
    return mem_store


@pytest.fixture(scope="session")
def mitre_attack_data_enterprise(memstore_enterprise_latest):
    logger.debug("Creating MitreAttackData() for Enterprise ATT&CK")
    mitre_attack_data = MitreAttackData(src=memstore_enterprise_latest)
    return mitre_attack_data


@pytest.fixture(scope="session")
def mitre_attack_data_mobile(memstore_mobile_latest):
    logger.debug("Creating MitreAttackData() for Mobile ATT&CK")
    mitre_attack_data = MitreAttackData(src=memstore_mobile_latest)
    return mitre_attack_data


@pytest.fixture(scope="session")
def mitre_attack_data_ics(memstore_ics_latest):
    logger.debug("Creating MitreAttackData() for ICS ATT&CK")
    mitre_attack_data = MitreAttackData(src=memstore_ics_latest)
    return mitre_attack_data


@pytest.fixture()
def layer_v3_all():
    layer = Layer()
    layer.from_str(example_layer_v3_all)
    return layer


@pytest.fixture()
def layer_v43():
    layer = Layer()
    layer.from_dict(example_layer_v43_dict)
    return layer
