import os

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


def _parse_version_param(versions_param):
    """Parse version parameter into versions list and STIX version.

    Parameters
    ----------
    versions_param : None, str, list, or dict
        Version parameter from pytest parametrize. Can be:
        - None: Use latest version with STIX 2.0
        - str: Single ATT&CK version with STIX 2.0 (e.g., "15.1")
        - list: Multiple ATT&CK versions with STIX 2.0 (e.g., ["15.0", "15.1"])
        - dict: Specify both ATT&CK and STIX versions (e.g., {"attack_version": "15.1", "stix_version": "2.1"})

    Returns
    -------
    tuple
        (versions_list, stix_version) where versions_list is None for latest
        or list of version strings, and stix_version is STIX version string
        (default "2.0")
    """
    if versions_param is None:
        return None, "2.0"

    if isinstance(versions_param, dict):
        attack_version = versions_param.get("attack_version")
        stix_version = versions_param.get("stix_version", "2.0")
        if attack_version is None:
            return None, stix_version
        return [attack_version], stix_version

    if isinstance(versions_param, str):
        return [versions_param], "2.0"

    if isinstance(versions_param, list):
        return versions_param, "2.0"

    return None, "2.0"


def _get_stix_file_path(attack_stix_dir, domain, version_key="latest"):
    """Get STIX file path for a domain from attack_stix_dir.

    Parameters
    ----------
    attack_stix_dir : dict
        Dictionary from attack_stix_dir fixture
    domain : str
        Domain name ("enterprise", "mobile", "ics")
    version_key : str, optional
        Key to use from attack_stix_dir (default "latest")

    Returns
    -------
    str
        Path to STIX file
    """
    if version_key in attack_stix_dir:
        return f"{attack_stix_dir[version_key]}/{domain}-attack.json"
    else:
        # Use first available version as fallback
        first_version = list(attack_stix_dir.keys())[0]
        return f"{attack_stix_dir[first_version]}/{domain}-attack.json"


def _download_attack_stix_data(versions_param, tmp_path_factory):
    """Download ATT&CK STIX data and return paths.

    This is the core download logic shared by multiple fixtures.

    Parameters
    ----------
    versions_param : None, str, list, or dict
        Version parameter to parse
    tmp_path_factory : pytest.TempPathFactory
        Pytest temp path factory

    Returns
    -------
    dict
        Dictionary mapping version to download directory path
    """
    versions, stix_version = _parse_version_param(versions_param)

    logger.debug(f"Downloading the ATT&CK STIX {stix_version} data for versions: {versions}")
    download_dir = tmp_path_factory.mktemp("attack-releases") / f"stix-{stix_version}"

    download_domains(
        domains=["enterprise", "mobile", "ics"],
        download_dir=download_dir,
        all_versions=False,
        stix_version=stix_version,
        attack_versions=versions,
    )

    # Build return dictionary
    result_paths = {}
    if versions is None:
        result_paths["latest"] = download_dir / f"v{LATEST_VERSION}"
    else:
        # Return paths for each requested version
        for version in versions:
            result_paths[version] = download_dir / f"v{version}"

    return result_paths


@pytest.fixture(autouse=True, scope="session")
def attack_stix_dir(request, tmp_path_factory):
    """Download ATT&CK STIX data and return paths.

    Can be parametrized to download specific versions:
    - Single version: @pytest.mark.parametrize("attack_stix_dir", ["14.0"], indirect=True)
    - Multiple versions: @pytest.mark.parametrize("attack_stix_dir", [["14.0", "14.1"]], indirect=True)
    - STIX version: @pytest.mark.parametrize("attack_stix_dir", ["14.0:2.1"], indirect=True)

    Parameters
    ----------
    request : pytest.FixtureRequest
        Pytest fixture request object containing parametrized values

    Returns
    -------
    dict
        Dictionary mapping version to download directory path.
        Directory structure: attack-releases/stix-{version}/v{attack_version}/
        For single/default: {"latest": "attack-releases/stix-2.0"} or {"14.0": "attack-releases/stix-2.0"}
        For multiple: {"14.0": "attack-releases/stix-2.0", "14.1": "attack-releases/stix-2.0"}

    Yields
    ------
    dict
        Directory paths for requested ATT&CK versions
    """
    versions_param = getattr(request, "param", None)
    result_paths = _download_attack_stix_data(versions_param, tmp_path_factory)
    yield result_paths


@pytest.fixture(scope="session")
def stix_file_enterprise_latest(attack_stix_dir):
    """Get path to Enterprise ATT&CK STIX file.

    Uses environment variable STIX_LOCATION_ENTERPRISE if set,
    otherwise constructs path from attack_stix_dir.

    Parameters
    ----------
    attack_stix_dir : dict
        Dictionary mapping version keys to download directory paths

    Returns
    -------
    str
        Path to Enterprise ATT&CK STIX file
    """
    if STIX_LOCATION_ENTERPRISE:
        return STIX_LOCATION_ENTERPRISE

    return _get_stix_file_path(attack_stix_dir, "enterprise")


@pytest.fixture(scope="session")
def stix_file_mobile_latest(attack_stix_dir):
    """Get path to Mobile ATT&CK STIX file.

    Uses environment variable STIX_LOCATION_MOBILE if set,
    otherwise constructs path from attack_stix_dir.

    Parameters
    ----------
    attack_stix_dir : dict
        Dictionary mapping version keys to download directory paths

    Returns
    -------
    str
        Path to Mobile ATT&CK STIX file
    """
    if STIX_LOCATION_MOBILE:
        return STIX_LOCATION_MOBILE

    return _get_stix_file_path(attack_stix_dir, "mobile")


@pytest.fixture(scope="session")
def stix_file_ics_latest(attack_stix_dir):
    """Get path to ICS ATT&CK STIX file.

    Uses environment variable STIX_LOCATION_ICS if set,
    otherwise constructs path from attack_stix_dir.

    Parameters
    ----------
    attack_stix_dir : dict
        Dictionary mapping version keys to download directory paths

    Returns
    -------
    str
        Path to ICS ATT&CK STIX file
    """
    if STIX_LOCATION_ICS:
        return STIX_LOCATION_ICS

    return _get_stix_file_path(attack_stix_dir, "ics")


@pytest.fixture(scope="session")
def memstore_enterprise_latest(stix_file_enterprise_latest):
    """Create STIX MemoryStore for Enterprise ATT&CK data.

    Parameters
    ----------
    stix_file_enterprise_latest : str
        Path to Enterprise ATT&CK STIX file

    Returns
    -------
    stix2.MemoryStore
        Loaded MemoryStore containing Enterprise ATT&CK STIX objects
    """
    logger.debug("Loading STIX memstore for Enterprise ATT&CK")
    mem_store = MemoryStore()
    mem_store.load_from_file(stix_file_enterprise_latest)
    return mem_store


@pytest.fixture(scope="session")
def memstore_mobile_latest(stix_file_mobile_latest):
    """Create STIX MemoryStore for Mobile ATT&CK data.

    Parameters
    ----------
    stix_file_mobile_latest : str
        Path to Mobile ATT&CK STIX file

    Returns
    -------
    stix2.MemoryStore
        Loaded MemoryStore containing Mobile ATT&CK STIX objects
    """
    logger.debug("Loading STIX memstore for Mobile ATT&CK")
    mem_store = MemoryStore()
    mem_store.load_from_file(stix_file_mobile_latest)
    return mem_store


@pytest.fixture(scope="session")
def memstore_ics_latest(stix_file_ics_latest):
    """Create STIX MemoryStore for ICS ATT&CK data.

    Parameters
    ----------
    stix_file_ics_latest : str
        Path to ICS ATT&CK STIX file

    Returns
    -------
    stix2.MemoryStore
        Loaded MemoryStore containing ICS ATT&CK STIX objects
    """
    logger.debug("Loading STIX memstore for ICS ATT&CK")
    mem_store = MemoryStore()
    mem_store.load_from_file(stix_file_ics_latest)
    return mem_store


@pytest.fixture(scope="session")
def mitre_attack_data_enterprise(memstore_enterprise_latest):
    """Create MitreAttackData instance for Enterprise ATT&CK.

    Parameters
    ----------
    memstore_enterprise_latest : stix2.MemoryStore
        MemoryStore containing Enterprise ATT&CK STIX objects

    Returns
    -------
    mitreattack.stix20.MitreAttackData
        MitreAttackData instance for querying Enterprise ATT&CK data
    """
    logger.debug("Creating MitreAttackData() for Enterprise ATT&CK")
    mitre_attack_data = MitreAttackData(src=memstore_enterprise_latest)
    return mitre_attack_data


@pytest.fixture(scope="session")
def mitre_attack_data_mobile(memstore_mobile_latest):
    """Create MitreAttackData instance for Mobile ATT&CK.

    Parameters
    ----------
    memstore_mobile_latest : stix2.MemoryStore
        MemoryStore containing Mobile ATT&CK STIX objects

    Returns
    -------
    mitreattack.stix20.MitreAttackData
        MitreAttackData instance for querying Mobile ATT&CK data
    """
    logger.debug("Creating MitreAttackData() for Mobile ATT&CK")
    mitre_attack_data = MitreAttackData(src=memstore_mobile_latest)
    return mitre_attack_data


@pytest.fixture(scope="session")
def mitre_attack_data_ics(memstore_ics_latest):
    """Create MitreAttackData instance for ICS ATT&CK.

    Parameters
    ----------
    memstore_ics_latest : stix2.MemoryStore
        MemoryStore containing ICS ATT&CK STIX objects

    Returns
    -------
    mitreattack.stix20.MitreAttackData
        MitreAttackData instance for querying ICS ATT&CK data
    """
    logger.debug("Creating MitreAttackData() for ICS ATT&CK")
    mitre_attack_data = MitreAttackData(src=memstore_ics_latest)
    return mitre_attack_data


@pytest.fixture()
def layer_v3_all():
    """Create Navigator Layer from example v3 layer data.

    Returns
    -------
    mitreattack.navlayers.Layer
        Layer object populated with example v3 layer data
    """
    layer = Layer()
    layer.from_str(example_layer_v3_all)
    return layer


@pytest.fixture()
def layer_v43():
    """Create Navigator Layer from example v4.3 layer data.

    Returns
    -------
    mitreattack.navlayers.Layer
        Layer object populated with example v4.3 layer data
    """
    layer = Layer()
    layer.from_dict(example_layer_v43_dict)
    return layer
