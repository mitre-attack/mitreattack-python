"""A helper script to generate changelogs between different versions of ATT&CK."""

import json
from pathlib import Path
from typing import List, Optional

from loguru import logger
from tqdm import tqdm

from mitreattack.diffStix.cli.argument_parser import get_parsed_args
from mitreattack.diffStix.core.attack_changes_encoder import AttackChangesEncoder
from mitreattack.diffStix.core.diff_stix import DiffStix
from mitreattack.diffStix.formatters.html_output import markdown_to_html, write_detailed_html
from mitreattack.diffStix.formatters.layer_output import layers_dict_to_files
from mitreattack.diffStix.utils.constants import LAYER_DEFAULTS as layer_defaults


def get_new_changelog_md(
    domains: Optional[List[str]] = None,
    layers: List[str] = layer_defaults,
    unchanged: bool = False,
    old: Optional[str] = None,
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
    if domains is None:
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
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
