"""Functions to convert ATT&CK STIX data to Excel, as well as entrypoint for attackToExcel_cli."""

import argparse
import os
from typing import Dict, List

import pandas as pd
import requests
from loguru import logger
from stix2 import MemoryStore

# import mitreattack.attackToExcel.stixToDf as stixToDf
from mitreattack.attackToExcel import stixToDf

INVALID_CHARACTERS = ["\\", "/", "*", "[", "]", ":", "?"]
SUB_CHARACTERS = ["\\", "/"]


def get_stix_data(domain: str, version: str = None, remote: str = None, stix_file: str = None) -> MemoryStore:
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


def build_dataframes(src: MemoryStore, domain: str) -> Dict:
    """Build pandas dataframes for each attack type, and return a dictionary lookup for each type to the relevant dataframe.

    :returns:

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
        "datasources": stixToDf.datasourcesToDf(src)
    }
    return df


def write_excel(dataframes: Dict, domain: str, version: str = None, output_dir: str = ".") -> List:
    """Given a set of dataframes from build_dataframes, write the ATT&CK dataset to output directory.

    Parameters
    ----------
    dataframes : dict
        A dictionary of pandas dataframes as built by build_dataframes()
    domain : str
        Domain of ATT&CK the dataframes correspond to, e.g "enterprise-attack"
    version : str, optional
        The version of ATT&CK the dataframes correspond to, e.g "v8.1".
        If omitted, the output files will not be labelled with the version number, by default None
    output_dir : str, optional
        The directory to write the excel files to.
        If omitted writes to a subfolder of the current directory depending on specified domain and version, by default "."

    Returns
    -------
    list
        A list of filepaths corresponding to the files written by the function
    """
    logger.info("writing formatted files... ")
    # master list of files that have been written
    written_files = []
    # set up output directory
    if version:
        domain_version_string = f"{domain}-{version}"
    else:
        domain_version_string = domain
    output_directory = os.path.join(output_dir, domain_version_string)
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    # master dataset file
    master_fp = os.path.join(output_directory, f"{domain_version_string}.xlsx")
    with pd.ExcelWriter(master_fp, engine="xlsxwriter") as master_writer:
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
                with pd.ExcelWriter(fp) as object_writer:
                    for sheet_name in object_data:
                        logger.debug(f"Writing sheet to {fp}: {sheet_name}")
                        object_data[sheet_name].to_excel(object_writer, sheet_name=sheet_name, index=False)
                written_files.append(fp)

                # add citations to master citations list
                if "citations" in object_data:
                    citations = pd.concat([citations, object_data["citations"]])

                # add main df to master dataset
                logger.debug(f"Writing sheet to {master_fp}: {object_type}")
                object_data[object_type].to_excel(master_writer, sheet_name=object_type, index=False)

            else:  # handle matrix special formatting
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

        # remove duplicate citations and add sheet to master file
        logger.debug(f"Writing sheet to {master_fp}: citations")
        citations.drop_duplicates(subset="reference", ignore_index=True).sort_values("reference").to_excel(
            master_writer, sheet_name="citations", index=False
        )

    written_files.append(master_fp)
    for thefile in written_files:
        logger.info(f"Excel file created: {thefile}")
    return written_files


def export(
    domain: str = "enterprise-attack",
    version: str = None,
    output_dir: str = ".",
    remote: str = None,
    stix_file: str = None,
    mem_store: MemoryStore = None,
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

    Raises
    ------
    TypeError
        Raised when missing exactly one of `remote`, `stix_file`, or `mem_store`.
    """
    if (
        (remote and stix_file and mem_store)
        or (remote and stix_file)
        or (remote and mem_store)
        or (stix_file and mem_store)
    ):
        raise TypeError("Exactly zero or one of `remote`, `stix_file`, and `mem_store` must be passed in.")

    get_stix_from_github = remote is None and stix_file is None and mem_store is None

    if get_stix_from_github or remote or stix_file:
        mem_store = get_stix_data(domain=domain, version=version, remote=remote, stix_file=stix_file)

    logger.info(f"************ Exporting {domain} to Excel ************")

    # build dataframes
    dataframes = build_dataframes(src=mem_store, domain=domain)
    write_excel(dataframes=dataframes, domain=domain, version=version, output_dir=output_dir)


def main():
    """Entrypoint for attackToExcel_cli."""
    parser = argparse.ArgumentParser(
        description="Download ATT&CK data from MITRE/CTI and convert it to excel spreadsheets"
    )
    parser.add_argument(
        "-domain",
        type=str,
        choices=["enterprise-attack", "mobile-attack", "ics-attack"],
        default="enterprise-attack",
        help="which domain of ATT&CK to convert",
    )
    parser.add_argument(
        "-version",
        type=str,
        help="which version of ATT&CK to convert. If omitted, builds the latest version",
    )
    parser.add_argument(
        "-output",
        type=str,
        default=".",
        help="output directory. If omitted writes to a subfolder of the current directory depending on "
        "the domain and version",
    )
    parser.add_argument(
        "-remote",
        type=str,
        default=None,
        help="remote url of an ATT&CK workbench server.",
    )
    parser.add_argument(
        "-stix-file",
        type=str,
        default=None,
        help="Path to a local STIX file containing ATT&CK data for a domain, by default None",
    )
    args = parser.parse_args()

    export(
        domain=args.domain, version=args.version, output_dir=args.output, remote=args.remote, stix_file=args.stix_file
    )


if __name__ == "__main__":
    main()
