"""Command-line argument parser for changelog_helper."""

import argparse

from loguru import logger
from tqdm import tqdm

from mitreattack.diffStix.utils.constants import LAYER_DEFAULTS as layer_defaults


def get_parsed_args():
    """Create argument parser and parse arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Create changelog reports on the differences between two versions of the ATT&CK content. "
            "Takes STIX bundles as input. For default operation, put "
            "enterprise-attack.json, mobile-attack.json, and ics-attack.json bundles "
            "in 'old' and 'new' folders for the script to compare."
        )
    )

    parser.add_argument(
        "--old",
        type=str,
        # Default is really "old", set below
        default=None,
        help="Directory to load old STIX data from.",
    )

    parser.add_argument(
        "--new",
        type=str,
        default="new",
        help="Directory to load new STIX data from.",
    )

    parser.add_argument(
        "--domains",
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
        "--layers",
        type=str,
        nargs="*",
        help=f"""
            Create layer files showing changes in each domain
            expected order of filenames is 'enterprise', 'mobile', 'ics', 'pre attack'.
            If values are unspecified, defaults to {", ".join(layer_defaults)}
            """,
    )

    parser.add_argument(
        "--site_prefix",
        type=str,
        default="",
        help="Prefix links in markdown output, e.g. [prefix]/techniques/T1484",
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

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print status messages",
    )

    args = parser.parse_args()

    # the default loguru logger logs up to Debug by default
    logger.remove()
    if args.verbose:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True)
    else:
        logger.add(lambda msg: tqdm.write(msg, end=""), colorize=True, level="INFO")

    if args.use_mitre_cti and args.old:
        parser.error("--use-mitre-cti and -old cannot be used together")

    # set a default directory that doesn't conflict with use_mitre_cti
    if not args.old:
        args.old = "old"

    if args.layers is not None:
        if len(args.layers) not in [0, 3]:
            parser.error("-layers requires exactly three files to be specified or none at all")

    return args
