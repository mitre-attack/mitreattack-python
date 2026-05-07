"""Functions to convert ATT&CK STIX data to Excel, as well as entrypoint for attack-to-excel."""

import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import click
import pandas as pd
import requests
import typer
from loguru import logger
from stix2 import MemoryStore
from typing_extensions import Annotated

from mitreattack import release_info

# import mitreattack.attackToExcel.stixToDf as stixToDf
from mitreattack.attackToExcel import stixToDf
from mitreattack.download_stix import download_domains

INVALID_CHARACTERS = ["\\", "/", "*", "[", "]", ":", "?"]
SUB_CHARACTERS = ["\\", "/"]
ATTACK_RELEASES_DIR = Path("attack-releases")


@dataclass(frozen=True)
class DomainConfig:
    """Domain-specific names for STIX downloads and Excel exports."""

    download_name: str


DOMAIN_CONFIGS = {
    "enterprise-attack": DomainConfig(download_name="enterprise"),
    "mobile-attack": DomainConfig(download_name="mobile"),
    "ics-attack": DomainConfig(download_name="ics"),
}
ATTACK_DOMAINS = tuple(DOMAIN_CONFIGS)
VALID_STIX_VERSIONS = ("2.0", "2.1")
app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Download ATT&CK data from MITRE/CTI and convert it to excel spreadsheets.",
)


def normalize_attack_version(version: str) -> str:
    """Return an ATT&CK release version with the leading ``v`` folder prefix."""
    return version if version.startswith("v") else f"v{version}"


def _version_without_prefix(version: str) -> str:
    """Return an ATT&CK release version without the leading ``v`` folder prefix."""
    return normalize_attack_version(version).removeprefix("v")


def _default_release_dir(version: str, stix_version: str) -> Path:
    """Return the default local STIX release directory."""
    return ATTACK_RELEASES_DIR / f"stix-{stix_version}" / normalize_attack_version(version)


def _validate_release_domains(domains: Optional[List[str]]) -> List[str]:
    """Return validated ATT&CK release export domains."""
    if not domains:
        return list(ATTACK_DOMAINS)

    normalized_domains = []
    invalid_domains = []
    for domain in domains:
        if domain not in DOMAIN_CONFIGS:
            if domain not in invalid_domains:
                invalid_domains.append(domain)
            continue

        if domain not in normalized_domains:
            normalized_domains.append(domain)

    if invalid_domains:
        invalid_domains_text = ", ".join(invalid_domains)
        expected_domains_text = ", ".join(ATTACK_DOMAINS)
        raise ValueError(f"Invalid ATT&CK domain(s): {invalid_domains_text}. Expected one of: {expected_domains_text}")

    return normalized_domains


def _release_stix_file(release_dir: Path, domain: str) -> Path:
    """Return the expected STIX bundle path for a domain in a release directory."""
    return release_dir / f"{domain}.json"


def _domain_version_string(domain: str, version: Optional[str]) -> str:
    """Return the folder and filename prefix used for one domain export."""
    return f"{domain}-{version}" if version else domain


def _excel_output_dir(output_dir: Path, domain: str, version: Optional[str]) -> Path:
    """Return the directory that one domain export writes Excel files into."""
    return output_dir / _domain_version_string(domain, version)


def _release_staging_output_dir(output_dir: Path) -> Path:
    """Return the parent directory for staged release Excel files."""
    return output_dir / "tmp" / "staged-excel-files"


def _existing_excel_files(directory: Path) -> List[Path]:
    """Return existing Excel files directly under a generated output directory."""
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.glob("*.xlsx") if path.is_file())


def _raise_if_excel_files_exist(paths: List[Path]):
    """Refuse to continue when generated output would overwrite existing Excel files."""
    if not paths:
        return

    files_text = "\n".join(f"  - {path}" for path in paths)
    raise FileExistsError(
        "Refusing to overwrite existing Excel file(s). "
        "Move or delete these files, choose a different output directory, or pass --overwrite to replace them:\n"
        f"{files_text}"
    )


def _log_excel_overwrite(path: Path | str, overwrite: bool):
    """Log when an existing Excel file is about to be replaced."""
    excel_path = Path(path)
    if overwrite and excel_path.is_file():
        logger.info(f"Overwriting existing Excel file: {excel_path}")


def _log_excel_overwrites(paths: List[Path]):
    """Log a preflight summary of existing Excel files that will be replaced."""
    if not paths:
        return

    logger.info("Existing Excel files will be overwritten:")
    for path in paths:
        logger.info(f"Overwriting existing Excel file: {path}")


def _move_versioned_exports_to_domain_dir(
    output_dir: Path,
    domain: str,
    version: Optional[str],
    overwrite: bool = False,
    staging_output_dir: Optional[Path] = None,
) -> List[Path]:
    """Move versioned Excel exports into the unversioned domain folder."""
    versioned_dir = _excel_output_dir(staging_output_dir or output_dir, domain, version)
    domain_dir = output_dir / domain
    moved_files = []

    if not versioned_dir.is_dir():
        return moved_files

    domain_dir.mkdir(parents=True, exist_ok=True)
    for source_path in versioned_dir.iterdir():
        if not source_path.is_file():
            continue

        target_path = domain_dir / source_path.name
        if target_path.exists():
            if not overwrite:
                _raise_if_excel_files_exist([target_path])
            logger.debug(f"Replacing existing Excel file: {target_path}")
            target_path.unlink()
        source_path.replace(target_path)
        moved_files.append(target_path)

    versioned_dir.rmdir()
    return moved_files


def _download_missing_release_domains(
    *,
    missing_domains: List[str],
    version: str,
    stix_version: str,
    temporary_directory: str,
) -> Path:
    """Download missing STIX domain bundles into a temporary release tree."""
    temp_stix_dir = Path(temporary_directory) / f"stix-{stix_version}"
    download_domains(
        domains=[DOMAIN_CONFIGS[domain].download_name for domain in missing_domains],
        download_dir=str(temp_stix_dir),
        all_versions=False,
        stix_version=stix_version,
        attack_versions=[_version_without_prefix(version)],
    )
    return temp_stix_dir / normalize_attack_version(version)


def export_release(
    version: Optional[str] = None,
    stix_version: str = "2.0",
    output_dir: str = "output",
    stix_base_dir: Optional[str] = None,
    domains: Optional[List[str]] = None,
    versioned_output_dir: bool = False,
    overwrite: bool = False,
):
    """Export one ATT&CK release to Excel for one or more domains."""
    if stix_version not in VALID_STIX_VERSIONS:
        expected_stix_versions = ", ".join(VALID_STIX_VERSIONS)
        raise ValueError(f"Invalid STIX version: {stix_version}. Expected one of: {expected_stix_versions}")

    has_explicit_local_stix_base_dir = stix_base_dir is not None or os.environ.get("STIX_BASE_DIR") is not None
    attack_version = normalize_attack_version(version) if version else None
    release_version = attack_version or normalize_attack_version(release_info.LATEST_VERSION)
    release_domains = _validate_release_domains(domains)
    local_release_dir = Path(
        stix_base_dir or os.environ.get("STIX_BASE_DIR") or _default_release_dir(release_version, stix_version)
    )
    local_release_dir = local_release_dir.resolve()
    release_output_dir = (
        Path(output_dir)
        if has_explicit_local_stix_base_dir and attack_version is None
        else Path(output_dir) / release_version
    )

    local_stix_files = {domain: _release_stix_file(local_release_dir, domain) for domain in release_domains}
    missing_domains = [domain for domain, stix_file in local_stix_files.items() if not stix_file.is_file()]

    existing_release_excel_files = _existing_release_excel_files(
        output_dir=release_output_dir,
        domains=release_domains,
        version=attack_version,
        versioned_output_dir=versioned_output_dir,
    )
    if overwrite:
        _log_excel_overwrites(existing_release_excel_files)
    else:
        _raise_if_excel_files_exist(existing_release_excel_files)

    if not missing_domains:
        _export_release_domains(
            version=attack_version,
            output_dir=release_output_dir,
            stix_files=local_stix_files,
            versioned_output_dir=versioned_output_dir,
            overwrite=overwrite,
        )
        return

    if attack_version is None:
        missing_domains_text = ", ".join(missing_domains)
        raise FileNotFoundError(
            f"Missing local STIX file(s) for domain(s): {missing_domains_text}. "
            "Pass --version to download missing ATT&CK release bundles."
        )

    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary_release_dir = _download_missing_release_domains(
            missing_domains=missing_domains,
            version=attack_version,
            stix_version=stix_version,
            temporary_directory=temporary_directory,
        )
        stix_files = {
            domain: local_stix_files[domain]
            if domain not in missing_domains
            else _release_stix_file(temporary_release_dir, domain)
            for domain in release_domains
        }
        _export_release_domains(
            version=attack_version,
            output_dir=release_output_dir,
            stix_files=stix_files,
            versioned_output_dir=versioned_output_dir,
            overwrite=overwrite,
        )


def _existing_release_excel_files(
    *,
    output_dir: Path,
    domains: List[str],
    version: Optional[str],
    versioned_output_dir: bool,
) -> List[Path]:
    """Return existing Excel files that a release export could overwrite."""
    existing_files = []
    for domain in domains:
        candidate_dirs = [_excel_output_dir(output_dir, domain, version)]
        if not versioned_output_dir:
            candidate_dirs.append(output_dir / domain)

        for candidate_dir in candidate_dirs:
            existing_files.extend(_existing_excel_files(candidate_dir))

    return sorted(set(existing_files))


def _export_release_domains(
    *,
    version: Optional[str],
    output_dir: Path,
    stix_files: Dict[str, Path],
    versioned_output_dir: bool,
    overwrite: bool,
):
    """Export resolved release STIX files to Excel."""
    for domain, stix_file in stix_files.items():
        logger.info(f"Exporting {domain} to Excel from {stix_file}")
        domain_output_dir = output_dir if versioned_output_dir else _release_staging_output_dir(output_dir)
        if not versioned_output_dir:
            logger.info(
                f"Writing staged Excel files for {domain} to {_excel_output_dir(domain_output_dir, domain, version)}"
            )

        export(
            domain=domain,
            version=version,
            output_dir=str(domain_output_dir),
            stix_file=str(stix_file),
            overwrite=overwrite,
            log_written_files=versioned_output_dir,
        )

        if not versioned_output_dir:
            logger.info(f"Moving staged Excel files for {domain} to {output_dir / domain}")
            moved_files = _move_versioned_exports_to_domain_dir(
                output_dir=output_dir,
                domain=domain,
                version=version,
                overwrite=overwrite,
                staging_output_dir=domain_output_dir,
            )
            for moved_file in moved_files:
                logger.info(f"Excel file written: {moved_file}")


def get_stix_data(
    domain: str, version: Optional[str] = None, remote: Optional[str] = None, stix_file: Optional[str] = None
) -> MemoryStore:
    """Download the ATT&CK STIX data for the given domain and version from MITRE/CTI (or just domain if a remote workbench is specified).

    Parameters
    ----------
    domain : str
        The domain of ATT&CK to fetch data from, e.g "enterprise-attack"
    version : str, optional
        The version of attack to fetch data from, e.g "v8.1".
        If omitted, returns the latest version (not used for invocations that use remote), by default None
    remote : str, optional
        Optional url to a ATT&CK workbench instance.
        If specified, data will be retrieved from the target Workbench instead of MITRE/CTI, by default None
    stix_file : str, optional
        Path to a local STIX file containing ATT&CK data for a domain, by default None

    Returns
    -------
    MemoryStore
        A stix2.MemoryStore object containing the domain data

    Raises
    ------
    ValueError
        Raised if both `remote` and `stix_file` are passed
    FileNotFoundError
        Raised if `stix_file` not found
    """
    if remote and stix_file:
        raise ValueError("remote and stix_file are mutually exclusive. Please only use one or the other")

    mem_store = None
    if stix_file:
        if os.path.exists(stix_file):
            logger.info(f"Loading STIX file from: {stix_file}")
            mem_store = MemoryStore()
            mem_store.load_from_file(stix_file)
        else:
            raise FileNotFoundError(f"{stix_file} file does not exist.")
    else:
        if remote:
            logger.info("Downloading ATT&CK data from an ATT&CK Workbench instance")
            if ":" not in remote[6:]:
                remote += ":3000"
            if not remote.startswith("http"):
                remote = "http://" + remote
            url = f"{remote}/api/stix-bundles?domain={domain}&includeRevoked=true&includeDeprecated=true"
            stix_json = requests.get(url).json()
            mem_store = MemoryStore(stix_json)
        else:
            logger.info("Downloading ATT&CK data from github.com/mitre/cti")
            if version:
                url = f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-{version}/{domain}/{domain}.json"
            else:
                url = f"https://raw.githubusercontent.com/mitre/cti/master/{domain}/{domain}.json"

            stix_json = requests.get(url).json()
            mem_store = MemoryStore(stix_data=stix_json["objects"])

    return mem_store


def build_dataframes_pre_v18(src: MemoryStore, domain: str) -> Dict:
    """Build pandas dataframes for each attack type, and return a dictionary lookup for each type to the relevant dataframe.

    This version of the function is used for ATT&CK versions prior to v18, to account for changes to data components/data sources.

    Parameters
    ----------
    src : MemoryStore
        MemoryStore or other stix2 DataSource object
    domain : str
        domain of ATT&CK src corresponds to, e.g "enterprise-attack"

    Returns
    -------
    dict
        A dict lookup of each ATT&CK type to dataframes for the given type to be ingested by write_excel
    """
    df = {
        "techniques": stixToDf.techniquesToDf(src, domain),
        "tactics": stixToDf.tacticsToDf(src),
        "software": stixToDf.softwareToDf(src),
        "groups": stixToDf.groupsToDf(src),
        "campaigns": stixToDf.campaignsToDf(src),
        "assets": stixToDf.assetsToDf(src),
        "mitigations": stixToDf.mitigationsToDf(src),
        "matrices": stixToDf.matricesToDf(src, domain),
        "relationships": stixToDf.relationshipsToDf(src),
        "datasources": stixToDf.datasourcesToDf(src),
        "analytics": stixToDf.analyticsToDf(src),
        "detectionstrategies": stixToDf.detectionstrategiesToDf(src),
    }
    return df


def build_dataframes(src: MemoryStore, domain: str) -> Dict:
    """Build pandas dataframes for each attack type, and return a dictionary lookup for each type to the relevant dataframe.

    Parameters
    ----------
    src : MemoryStore
        MemoryStore or other stix2 DataSource object
    domain : str
        domain of ATT&CK src corresponds to, e.g "enterprise-attack"

    Returns
    -------
    dict
        A dict lookup of each ATT&CK type to dataframes for the given type to be ingested by write_excel
    """
    df = {
        "techniques": stixToDf.techniquesToDf(src, domain),
        "tactics": stixToDf.tacticsToDf(src),
        "software": stixToDf.softwareToDf(src),
        "groups": stixToDf.groupsToDf(src),
        "campaigns": stixToDf.campaignsToDf(src),
        "assets": stixToDf.assetsToDf(src),
        "mitigations": stixToDf.mitigationsToDf(src),
        "matrices": stixToDf.matricesToDf(src, domain),
        "relationships": stixToDf.relationshipsToDf(src),
        "datacomponents": stixToDf.datacomponentsToDf(src),
        "analytics": stixToDf.analyticsToDf(src),
        "detectionstrategies": stixToDf.detectionstrategiesToDf(src),
    }
    return df


def build_ds_an_lg_relationships(dataframes: Dict) -> Dict[str, pd.DataFrame]:
    """Build detection-mappings.xlsx with a single DS → Analytic → LogSource sheet."""
    ds_an = dataframes["detectionstrategies"].get("detectionstrategies-analytic", pd.DataFrame())

    an_ls = dataframes["analytics"].get("analytic-logsource", pd.DataFrame())

    if ds_an.empty or an_ls.empty:
        combined = pd.DataFrame()
    else:
        combined = ds_an.merge(
            an_ls,
            on=["analytic_id", "analytic_name", "platforms"],
            how="left",
        )

    return {"ds_an_ls": combined}


def write_excel(
    dataframes: Dict,
    domain: str,
    src: MemoryStore,
    version: Optional[str] = None,
    output_dir: str = ".",
    overwrite: bool = False,
    log_written_files: bool = True,
) -> List:
    """Given a set of dataframes from build_dataframes, write the ATT&CK dataset to output directory.

    Parameters
    ----------
    dataframes : dict
        A dictionary of pandas dataframes as built by build_dataframes()
    domain : str
        Domain of ATT&CK the dataframes correspond to, e.g "enterprise-attack"
    src : stix2.MemoryStore
        A STIX bundle containing ATT&CK data for a domain already loaded into memory.
        Mutually exclusive with `remote` and `stix_file`.
    version : str, optional
        The version of ATT&CK the dataframes correspond to, e.g "v8.1".
        If omitted, the output files will not be labelled with the version number, by default None
    output_dir : str, optional
        The directory to write the excel files to.
        If omitted writes to a subfolder of the current directory depending on specified domain and version, by default "."
    overwrite : bool, optional
        Whether to replace existing Excel files in the generated output directory, by default False
    log_written_files : bool, optional
        Whether to log each written Excel file path, by default True

    Returns
    -------
    list
        A list of filepaths corresponding to the files written by the function
    """
    logger.info("writing formatted files... ")
    # master list of files that have been written
    written_files = []
    # set up output directory
    domain_version_string = _domain_version_string(domain, version)
    output_directory_path = _excel_output_dir(Path(output_dir), domain, version)
    if not overwrite:
        _raise_if_excel_files_exist(_existing_excel_files(output_directory_path))
    output_directory_path.mkdir(parents=True, exist_ok=True)
    output_directory = str(output_directory_path)
    # master dataset file
    master_fp = os.path.join(output_directory, f"{domain_version_string}.xlsx")
    _log_excel_overwrite(master_fp, overwrite=overwrite)

    ds_an_ls_df = stixToDf.detectionStrategiesAnalyticsLogSourcesDf(src)
    add_ds_an_ls_to = {"detectionstrategies", "analytics", "datacomponents"}

    with pd.ExcelWriter(path=master_fp, engine="xlsxwriter") as master_writer:
        # master list of citations
        citations = pd.DataFrame()

        # write individual dataframes and add to master writer
        for object_type, object_data in dataframes.items():
            fp = os.path.join(output_directory, f"{domain_version_string}-{object_type}.xlsx")

            if object_type != "matrices":
                if not object_data:
                    logger.warning(f"No data for {object_type}. Skipping building an Excel file.")
                    continue

                # write the dataframes for the object type into named sheets
                _log_excel_overwrite(fp, overwrite=overwrite)
                with pd.ExcelWriter(fp) as object_writer:
                    for sheet_name in object_data:
                        logger.debug(f"Writing sheet to {fp}: {sheet_name}")
                        object_data[sheet_name].to_excel(object_writer, sheet_name=sheet_name, index=False)

                    # Write Detection strategy - Analytics - Log sources file
                    if (
                        object_type in add_ds_an_ls_to
                        and isinstance(ds_an_ls_df, pd.DataFrame)
                        and not ds_an_ls_df.empty
                    ):
                        ds_an_ls_df.to_excel(object_writer, sheet_name="defensive mappings", index=False)
                written_files.append(fp)

                # add citations to master citations list
                if "citations" in object_data:
                    citations = pd.concat([citations, object_data["citations"]])

                # add main df to master dataset
                logger.debug(f"Writing sheet to {master_fp}: {object_type}")
                object_data[object_type].to_excel(master_writer, sheet_name=object_type, index=False)

            else:  # handle matrix special formatting
                _log_excel_overwrite(fp, overwrite=overwrite)
                with pd.ExcelWriter(fp, engine="xlsxwriter") as matrix_writer:
                    # Combine both matrix types
                    combined = object_data[0] + object_data[1]

                    # some domains have multiple matrices
                    for matrix in combined:
                        # name them accordingly if there are multiple
                        sheetname = "matrix" if len(combined) == 1 else matrix["name"] + " matrix"
                        for character in INVALID_CHARACTERS:
                            sheetname = sheetname.replace(character, " or " if character in SUB_CHARACTERS else " ")

                        if len(sheetname) > 31:
                            sheetname = sheetname[0:28] + "..."
                        listing = []

                        # avoid printing subtype matrices to the master file
                        if matrix in object_data[0]:
                            # write unformatted matrix data to master file
                            logger.debug(f"Writing sheet to {master_fp}: {sheetname}")
                            matrix["matrix"].to_excel(master_writer, sheet_name=sheetname, index=False)
                            listing.append(master_writer)

                        # write unformatted matrix to matrix file
                        logger.debug(f"Writing sheet to {fp}: {sheetname}")
                        matrix["matrix"].to_excel(matrix_writer, sheet_name=sheetname, index=False)
                        listing.append(matrix_writer)

                        # for each writer, format the matrix for readability
                        for writer in listing:
                            # define column border styles
                            borderleft = writer.book.add_format({"left": 1, "shrink": 1})
                            borderright = writer.book.add_format({"right": 1, "shrink": 1})

                            # formats only need to be defined once: pointers stored here for subsequent uses
                            formats = {}
                            sheet = writer.sheets[sheetname]

                            # set all columns to 20 width, and add text shrinking to fit
                            sheet.set_column(0, matrix["columns"], width=20)

                            # merge supertechniques and tactic headers if sub-techniques are present on a tactic
                            for merge_range in matrix["merge"]:
                                # sometimes merge ranges have formats to add to the merged range
                                if merge_range.format:
                                    # add format to book if not defined
                                    if merge_range.format["name"] not in formats:
                                        formats[merge_range.format["name"]] = writer.book.add_format(
                                            merge_range.format["format"]
                                        )
                                    # get saved format if already added
                                    theformat = formats[merge_range.format["name"]]

                                    # tactic header merge has additional behavior
                                    if merge_range.format["name"] == "tacticHeader":
                                        # also set border for entire column for grouping
                                        sheet.set_column(
                                            merge_range.leftCol - 1,
                                            merge_range.leftCol - 1,
                                            width=20,  # set column widths to make matrix more readable
                                            cell_format=borderleft,  # left border around tactic
                                        )
                                        sheet.set_column(
                                            merge_range.rightCol - 1,
                                            merge_range.rightCol - 1,
                                            width=20,  # set column widths to make matrix more readable
                                            cell_format=borderright,  # right border around tactic
                                        )
                                else:
                                    theformat = None  # no format

                                # apply the merge
                                sheet.merge_range(merge_range.to_excel_format(), merge_range.data, theformat)

                written_files.append(fp)

        if isinstance(ds_an_ls_df, pd.DataFrame) and not ds_an_ls_df.empty:
            ds_an_ls_df.to_excel(master_writer, sheet_name="defensive mappings", index=False)
        # remove duplicate citations and add sheet to master file
        logger.debug(f"Writing sheet to {master_fp}: citations")
        citations.drop_duplicates(subset="reference", ignore_index=True).sort_values("reference").to_excel(
            master_writer, sheet_name="citations", index=False
        )

    written_files.append(master_fp)

    if log_written_files:
        for thefile in written_files:
            logger.info(f"Excel file written: {thefile}")
    return written_files


def export(
    domain: str = "enterprise-attack",
    version: Optional[str] = None,
    output_dir: str = ".",
    remote: Optional[str] = None,
    stix_file: Optional[str] = None,
    mem_store: Optional[MemoryStore] = None,
    overwrite: bool = False,
    log_written_files: bool = True,
):
    """Download ATT&CK data from MITRE/CTI and convert it to Excel spreadsheets.

    Parameters
    ----------
    domain : str, optional
        The domain of ATT&CK to download, e.g "enterprise-attack", by default "enterprise-attack"
    version : str, optional
        The version of ATT&CK to download, e.g "v8.1".
        If omitted will build the current version of ATT&CK, by default None
    output_dir : str, optional
        The directory to write the excel files to.
        If omitted writes to a subfolder of the current directory depending on specified domain and version.
        By default "."
    remote : str, optional
        The URL of a remote ATT&CK Workbench instance to connect to for stix data.
        Mutually exclusive with `stix_file` and `mem_store`.
        By default None
    stix_file : str, optional
        Path to a local STIX file containing ATT&CK data for a domain.
        Mutually exclusive with `remote` and `mem_store`.
        By default None
    mem_store : stix2.MemoryStore, optional
        A STIX bundle containing ATT&CK data for a domain already loaded into memory.
        Mutually exclusive with `remote` and `stix_file`.
        By default None
    overwrite : bool, optional
        Whether to replace existing Excel files in the generated output directory, by default False
    log_written_files : bool, optional
        Whether to log each written Excel file path, by default True

    Raises
    ------
    TypeError
        Raised when missing exactly one of `remote`, `stix_file`, or `mem_store`.
    ValueError
        Raised when `mem_store` fails to load.
    """
    if (
        (remote and stix_file and mem_store)
        or (remote and stix_file)
        or (remote and mem_store)
        or (stix_file and mem_store)
    ):
        raise TypeError("Exactly zero or one of `remote`, `stix_file`, and `mem_store` must be passed in.")

    get_stix_from_github = remote is None and stix_file is None and mem_store is None

    if not overwrite:
        _raise_if_excel_files_exist(_existing_excel_files(_excel_output_dir(Path(output_dir), domain, version)))

    if get_stix_from_github or remote or stix_file:
        mem_store = get_stix_data(domain=domain, version=version, remote=remote, stix_file=stix_file)

    if mem_store is None:
        raise ValueError("`mem_store` is empty - this should not be possible!")

    logger.info(f"************ Exporting {domain} to Excel ************")

    # build dataframes
    if version:
        version_pattern = r"v(\d+)\.(\d+)$"
        match = re.search(version_pattern, version)
        if match:
            major_version = int(match.group(1))
            if major_version < 18:
                dataframes = build_dataframes_pre_v18(src=mem_store, domain=domain)
                write_excel(
                    dataframes=dataframes,
                    domain=domain,
                    src=mem_store,
                    version=version,
                    output_dir=output_dir,
                    overwrite=overwrite,
                    log_written_files=log_written_files,
                )
                return

    dataframes = build_dataframes(src=mem_store, domain=domain)
    write_excel(
        dataframes=dataframes,
        domain=domain,
        src=mem_store,
        version=version,
        output_dir=output_dir,
        overwrite=overwrite,
        log_written_files=log_written_files,
    )


def _validate_cli_value(value: str, allowed_values: tuple[str, ...], label: str) -> str:
    """Return a CLI value after validating it against an allowed set."""
    if value not in allowed_values:
        allowed_values_text = ", ".join(allowed_values)
        raise typer.BadParameter(f"Invalid {label}: {value}. Expected one of: {allowed_values_text}")
    return value


@app.command("from-stix")
def from_stix_cli(
    domain: Annotated[
        str,
        typer.Option(
            "--domain",
            help="ATT&CK domain STIX bundle to convert.",
        ),
    ] = "enterprise-attack",
    version: Annotated[
        Optional[str],
        typer.Option(
            "--version",
            help="Which version of ATT&CK to convert. If omitted, builds the latest version.",
        ),
    ] = None,
    output: Annotated[
        str,
        typer.Option(
            "--output",
            help=(
                "Output directory. If omitted writes to a subfolder of the current directory depending on the domain "
                "and version."
            ),
        ),
    ] = ".",
    remote: Annotated[
        Optional[str],
        typer.Option(
            "--remote",
            help="Remote URL of an ATT&CK Workbench server.",
        ),
    ] = None,
    stix_file: Annotated[
        Optional[str],
        typer.Option(
            "--stix-file",
            help="Path to a local STIX file containing ATT&CK data for a domain.",
        ),
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Replace existing Excel files in the generated output directory.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show debug log messages.",
        ),
    ] = False,
):
    """Convert one ATT&CK domain STIX bundle to Excel."""
    _configure_cli_logging(verbose=verbose)
    domain = _validate_cli_value(domain, ATTACK_DOMAINS, "ATT&CK domain")

    if remote and stix_file:
        raise typer.BadParameter("--remote and --stix-file are mutually exclusive")

    try:
        export(
            domain=domain,
            version=version,
            output_dir=output,
            remote=remote,
            stix_file=stix_file,
            overwrite=overwrite,
        )
    except FileExistsError as error:
        raise click.ClickException(str(error)) from error


@app.command("from-release")
def from_release_cli(
    version: Annotated[
        Optional[str],
        typer.Option(
            "--version",
            help="Which ATT&CK release version to convert. If omitted, builds the latest version.",
        ),
    ] = None,
    domains: Annotated[
        Optional[List[str]],
        typer.Option(
            "--domains",
            help="ATT&CK release domain to include. Can be specified multiple times.",
        ),
    ] = None,
    stix_version: Annotated[
        str,
        typer.Option(
            "--stix-version",
            help="STIX release tree to use.",
        ),
    ] = "2.0",
    stix_base_dir: Annotated[
        Optional[str],
        typer.Option(
            "--stix-base-dir",
            help="Directory containing release STIX files.",
        ),
    ] = None,
    output: Annotated[
        str,
        typer.Option(
            "--output",
            help="Parent output directory.",
        ),
    ] = "output",
    versioned_output_dir: Annotated[
        bool,
        typer.Option(
            "--versioned-output-dir",
            help="Preserve domain-version output folders.",
        ),
    ] = False,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Replace existing Excel files in generated output directories.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show debug log messages.",
        ),
    ] = False,
):
    """Convert ATT&CK release domain bundles to Excel."""
    _configure_cli_logging(verbose=verbose)
    stix_version = _validate_cli_value(stix_version, VALID_STIX_VERSIONS, "STIX version")
    selected_domains = [
        _validate_cli_value(selected_domain, ATTACK_DOMAINS, "ATT&CK domain") for selected_domain in domains or []
    ]

    try:
        export_release(
            version=version,
            stix_version=stix_version,
            output_dir=output,
            stix_base_dir=stix_base_dir,
            domains=selected_domains or None,
            versioned_output_dir=versioned_output_dir,
            overwrite=overwrite,
        )
    except FileExistsError as error:
        raise click.ClickException(str(error)) from error


def _configure_cli_logging(verbose: bool = False):
    """Configure attack-to-excel CLI output for user-facing progress logs."""
    logger.remove()
    logger.add(sys.stderr, level="DEBUG" if verbose else "INFO")


def main(argv=None):
    """Entrypoint for attack-to-excel."""
    app(args=argv, prog_name="attack-to-excel")


if __name__ == "__main__":
    main()
