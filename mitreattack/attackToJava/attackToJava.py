"""Functions to convert ATT&CK STIX data to Java, as well as entrypoint for attackToJava_cli."""

import argparse
import os
from typing import Dict, List
from sortedcontainers import SortedDict

import pandas as pd
import requests
from loguru import logger
from stix2 import MemoryStore
from pprint import pprint

INVALID_CHARACTERS = ["\\", "/", "*", "[", "]", ":", "?"]
SUB_CHARACTERS = ["\\", "/"]

from mitreattack.attackToExcel import attackToExcel
from mitreattack.attackToJava import stixToJava
from mitreattack.attackToJava import getJavaImports



def export(
    version: str = None,
    output_dir: str = None,
    remote: str = None,
    stix_path: str = None,
    package_name: str = None,
    verbose_class: bool = False,
    ):
    """Download ATT&CK data from MITRE/CTI and convert it to Java class hierarchy

    Parameters
    ----------
    domain : str, optional
        The domain of ATT&CK to download, e.g "enterprise-attack", by default "enterprise-attack"
    version : str, optional
        The version of ATT&CK to download, e.g "v8.1".
        If omitted will build the current version of ATT&CK, by default None
    output_dir : str, optional
        The directory to write the excel files to.
        If omitted writes to a subfolder of the current directory depending on specified domain and version, by default "."
    remote : str, optional
        The URL of a remote ATT&CK Workbench instance to connect to for stix data.
        Mutually exclusive with stix_file.
        by default None
    stix_file : str, optional
        Path to a local STIX file containing ATT&CK data for a domain, by default None

    Raises
    ------
    ValueError
        Raised if both `remote` and `stix_file` are passed
    """

    if not package_name:
        raise ValueError("Package name needs to be specified")

    if not output_dir:
        raise ValueError("Output directory needs to be specified")
    
    if output_dir == ".":
        raise ValueError("Output directory cannot be the current directory, as the output directoty will be deleted and recreated. Please specify a valid directory")

    if remote and stix_path:
        raise ValueError("remote and stix_file are mutually exclusive. Please only use one or the other")
    
    #Verify that if stix path is specified it contains JSONs for all three domains
    if stix_path:
        if os.path.exists(os.path.join(stix_path, "enterprise-attack.json")) and os.path.exists(os.path.join(stix_path, "mobile-attack.json")) and os.path.exists(os.path.join(stix_path, "ics-attack.json")):
            pass
        else:
            raise ValueError("""stix_path must contain JSON files for all three domains: enterprise-attack.json, mobile-attack.json, ics-attack.json.
                             Use download_attack_stix tool to fetch the files""")

    all_data_sources = SortedDict()
    all_defenses_bypassed = SortedDict()
    all_platforms = SortedDict()

    stixToJava.buildOutputDir(package_name=package_name, output_dir=output_dir)
    
    for domain in ["enterprise-attack", "mobile-attack", "ics-attack"]:

        logger.info(f"************ Exporting {domain} to To Java ************")

        if stix_path:
            #Use local files if stix path is specified
            mem_store = attackToExcel.get_stix_data(domain=domain, version=version, remote=remote, stix_file=os.path.join(stix_path, f"{domain}.json"))
        else:
            mem_store = attackToExcel.get_stix_data(domain=domain, version=version, remote=remote)            

        stixToJava.stixToTactics(stix_data=mem_store, package_name=package_name, domain=domain, verbose_class=verbose_class,output_dir=output_dir)

        stixToJava.stixToTechniques(all_data_sources,all_defenses_bypassed,all_platforms,stix_data=mem_store, package_name=package_name, domain=domain, verbose_class=verbose_class,output_dir=output_dir)

    logger.info(f"************ Generating import statements for easy use ************")


    logger.info(f"************ Running Maven to format and test ************")
    
    with open(os.path.join(output_dir, "imports_example.txt"), "w") as f:
        for import_line in getJavaImports.getJavaImports(output_dir,package_name):
            f.write(f"{import_line}\n")
        
    stixToJava.runMaven(output_dir=output_dir)





def main():
    """Entrypoint for attackToExcel_cli."""
    parser = argparse.ArgumentParser(
        description="Download ATT&CK data from MITRE/CTI and convert it to excel spreadsheets"
    )

    parser.add_argument(
        "-version",
        type=str,
        help="which version of ATT&CK to convert. If omitted, builds the latest version",
    )
    parser.add_argument(
        "-output",
        type=str,
        required=True,
        help="output directory. If omitted writes to a subfolder of the current directory depending on "
        "the domain and version",
    )
    parser.add_argument(
        "-remote",
        type=str,
        default=None,
        help="remote url of an ATT&CK workbench server. If omitted, stix data will be acquired from the"
        " official ATT&CK Taxii server (cti-taxii.mitre.org)",
    )
    parser.add_argument(
        "-stix-path",
        type=str,
        default=None,
        help="Path to a local directory containing downlaoded STIX filse containing ATT&CK data for all supported domains (enterprise,mobile,ICS) by default None",
    )

    parser.add_argument(
        "-package",
        type=str,
        default="org.mitre.attack",
        help="Java package name from which to start the class hierarchy. If omitted, will use the org.mitre.attack is used",
    )

    parser.add_argument(
        "-verbose",
        action="store_true",
        help="Populate all fields in Java class, including description and other non-essential. Note this will increase memory usage and file size.",
    )       
    args = parser.parse_args()

    export(version=args.version, output_dir=args.output, remote=args.remote, stix_path=args.stix_path, package_name=args.package, verbose_class=args.verbose
    )


if __name__ == "__main__":
    main()
