"""A helper script to download ATT&CK releases in STIX/JSON format."""

import pathlib
from typing import List

import pooch
import typer
from loguru import logger

from mitreattack import release_info

app = typer.Typer(add_completion=False)


def download_stix(stix_version: str, domain: str, download_dir: str, release: str, known_hash: str):
    """Download an ATT&CK STIX release file.

    Parameters
    ----------
    stix_version : str
        Version of STIX to download. Options are "2.0" or "2.1"
    domain : str
        An ATT&CK domain from the following list ["enterprise", "mobile", "ics"]
    download_dir : str
        Directory to download the STIX files to.
    release : str
        ATT&CK release to download.
    known_hash : str
        SHA256 hash of the ATT&CK release.
    """
    release_download_dir = pathlib.Path(f"{download_dir}/v{release}")
    release_download_dir.mkdir(parents=True, exist_ok=True)
    fname = f"{domain}-attack.json"

    if stix_version == "2.0":
        download_url = f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{release}/{domain}-attack/{fname}"
    elif stix_version == "2.1":
        download_url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}-attack/{domain}-attack-{release}.json"

    pooch.retrieve(download_url, known_hash=known_hash, fname=fname, path=str(release_download_dir))


def download_domains(
    domains: List[str], download_dir: str, all_versions: bool, stix_version: str, specific_versions: List[str] = None
):
    """Download ATT&CK domains specified.

    Parameters
    ----------
    domains : List[str]
        List of domains to download.
    download_dir : str
        Directory to download the STIX files to.
    all_versions : bool
        Whether or not to download all versions of the domains.
    stix_version : str
        Version of STIX to download. Options are "2.0" or "2.1"
    specific_versions : List[str], optional
        List of specific versions to download. If provided, overrides all_versions behavior.
    """
    for domain in domains:
        if domain == "pre" and stix_version == "2.1":
            # there is no STIX 2.1 data for the PRE domain
            continue

        if stix_version == "2.0":
            stix_hash_data = release_info.STIX20
        elif stix_version == "2.1":
            stix_hash_data = release_info.STIX21

        releases = {}
        if domain == "enterprise":
            releases = stix_hash_data["enterprise"]
        elif domain == "mobile":
            releases = stix_hash_data["mobile"]
        elif domain == "ics":
            releases = stix_hash_data["ics"]
        elif domain == "pre":
            if stix_version == "2.0":
                releases = stix_hash_data["pre"]

        if specific_versions:
            # Download specific versions
            logger.info(f"Downloading STIX {stix_version} specific versions for the {domain} domain to {download_dir}")
            for version in specific_versions:
                if version in releases:
                    known_hash = releases[version]
                    download_stix(
                        stix_version=stix_version,
                        domain=domain,
                        download_dir=download_dir,
                        release=version,
                        known_hash=known_hash,
                    )
                else:
                    logger.warning(f"Version {version} not available for {domain} domain in STIX {stix_version}")
        elif all_versions:
            logger.info(f"Downloading STIX {stix_version} bundles for the {domain} domain to {download_dir}")
            for release, known_hash in releases.items():
                download_stix(
                    stix_version=stix_version,
                    domain=domain,
                    download_dir=download_dir,
                    release=release,
                    known_hash=known_hash,
                )
        else:
            if release_info.LATEST_VERSION in releases:
                logger.info(f"Downloading STIX {stix_version} bundle for the {domain} domain to {download_dir}")
                release = release_info.LATEST_VERSION
                known_hash = releases[release]
                download_stix(
                    stix_version=stix_version,
                    domain=domain,
                    download_dir=download_dir,
                    release=release,
                    known_hash=known_hash,
                )


def _validate_versions(versions: List[str], stix20: bool, stix21: bool):
    """Validate that specified versions exist in the available data.

    Parameters
    ----------
    versions : List[str]
        List of versions to validate
    stix20 : bool
        Whether STIX 2.0 is being downloaded
    stix21 : bool
        Whether STIX 2.1 is being downloaded
    """
    domains = ["enterprise", "mobile", "ics", "pre"]
    invalid_versions = []

    for version in versions:
        version_exists = False

        # Check STIX 2.0 if enabled
        if stix20:
            for domain in domains:
                if domain == "pre":
                    domain_releases = release_info.STIX20.get("pre", {})
                else:
                    domain_releases = release_info.STIX20.get(domain, {})

                if version in domain_releases:
                    version_exists = True
                    break

        # Check STIX 2.1 if enabled
        if stix21 and not version_exists:
            for domain in domains:
                if domain == "pre":
                    # PRE domain not available in STIX 2.1
                    continue

                domain_releases = release_info.STIX21.get(domain, {})
                if version in domain_releases:
                    version_exists = True
                    break

        if not version_exists:
            invalid_versions.append(version)

    if invalid_versions:
        logger.error(f"Invalid version(s): {', '.join(invalid_versions)}")
        logger.info(f"Latest available version: {release_info.LATEST_VERSION}")
        raise typer.Exit(code=1)


@app.command()
def download_attack_stix(
    download_dir: str = typer.Option(
        "attack-releases", "--download-dir", "-d", help="Folder to save downloaded STIX data."
    ),
    all_versions: bool = typer.Option(
        False, "--all", "-a", help="Download all ATT&CK releases. Mutually exclusive with --version."
    ),
    versions: List[str] = typer.Option(
        None,
        "--version",
        "-v",
        help="Download specific ATT&CK version(s). Can be specified multiple times. Mutually exclusive with --all.",
    ),
    stix20: bool = typer.Option(True, help="Download STIX 2.0 data."),
    stix21: bool = typer.Option(False, help="Download STIX 2.1 data."),
):
    """Download the ATT&CK STIX data from GitHub in JSON format.

    By default, only the latest ATT&CK release will be downloaded in STIX 2.0 format.
    Use --version to specify particular versions, or --all to download all versions.
    """
    # Validate mutually exclusive options
    if all_versions and versions:
        logger.error("Cannot specify both --all and --version. Use one or the other.")
        raise typer.Exit(code=1)

    # Validate specified versions exist
    if versions:
        _validate_versions(versions, stix20, stix21)

    domains = ["enterprise", "mobile", "ics", "pre"]

    if stix20:
        stix20_download_dir = f"{download_dir}/stix-2.0"
        pathlib.Path(stix20_download_dir).mkdir(parents=True, exist_ok=True)
        download_domains(
            domains=domains,
            download_dir=stix20_download_dir,
            all_versions=all_versions,
            stix_version="2.0",
            specific_versions=versions,
        )

    if stix21:
        stix21_download_dir = f"{download_dir}/stix-2.1"
        pathlib.Path(stix21_download_dir).mkdir(parents=True, exist_ok=True)
        download_domains(
            domains=domains,
            download_dir=stix21_download_dir,
            all_versions=all_versions,
            stix_version="2.1",
            specific_versions=versions,
        )
