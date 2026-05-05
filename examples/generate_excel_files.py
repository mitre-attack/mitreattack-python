"""Generate ATT&CK Excel exports from local STIX bundles."""

import argparse
from os import environ
from pathlib import Path

from stix2 import MemoryStore

from mitreattack.attackToExcel import attackToExcel

# Pass attack version via the command line or update the variable below
DEFAULT_ATTACK_VERSION = "v19.0"
# Parent directory where ATT&CK version export folders are written.
OUTPUT_DIR = Path("output")
# Set to true if you want the parent subfolder of the excel files to have a version.
# Example - If you want the folder to be named enterprise-attack-v19.0 instead of enterprise-attack, set to True
VERSIONED_OUTPUT_DIR = False


def move_versioned_exports_to_domain_dir(output_dir, domain, version):
    """Move versioned Excel exports into the unversioned domain folder."""
    output_dir = Path(output_dir)
    versioned_dir = output_dir / f"{domain}-{version}"
    domain_dir = output_dir / domain

    if not versioned_dir.is_dir():
        return

    domain_dir.mkdir(parents=True, exist_ok=True)

    for source_path in versioned_dir.iterdir():
        if not source_path.is_file():
            continue

        target_path = domain_dir / source_path.name
        if target_path.exists():
            target_path.unlink()

        source_path.replace(target_path)

    versioned_dir.rmdir()


def format_missing_stix_bundle_error(stix_file, attack_version):
    """Format a concise missing STIX bundle error."""
    message = (
        f"STIX bundle not found: {stix_file}\n"
        "Download the STIX bundles before running this script, or set STIX_BASE_DIR to the directory containing "
        "enterprise-attack.json, mobile-attack.json, and ics-attack.json."
    )

    if attack_version and not attack_version.startswith("v"):
        message = f"{message}\nDid you mean -a v{attack_version}?"

    return message


def validate_stix_files(stix_files, attack_version):
    """Exit with a clean error if any expected STIX bundle is missing."""
    for stix_file in stix_files.values():
        if not stix_file.is_file():
            raise SystemExit(format_missing_stix_bundle_error(stix_file, attack_version))


def parse_args(argv=None):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="generate_excel_files.py",
        description="Generate ATT&CK Excel exports from local STIX bundles.",
    )
    parser.add_argument(
        "-a",
        "--attack-version",
        default=DEFAULT_ATTACK_VERSION,
        help=(f"ATT&CK version to export, such as v19.0. Defaults to {DEFAULT_ATTACK_VERSION}."),
    )
    return parser.parse_args(args=argv)


def main(argv=None):
    """Generate excel files for specific versions of ATT&CK."""
    args = parse_args(argv)
    attack_version = args.attack_version

    # List of domains and version to process
    domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
    output_dir = OUTPUT_DIR / attack_version

    # Path to the STIX bundles for each domain (assumes STIX files are downloaded)
    stix_base_dir = Path(environ.get("STIX_BASE_DIR", Path("attack-releases") / "stix-2.0" / attack_version))
    stix_files = {
        "enterprise-attack": stix_base_dir / "enterprise-attack.json",
        "mobile-attack": stix_base_dir / "mobile-attack.json",
        "ics-attack": stix_base_dir / "ics-attack.json",
    }
    validate_stix_files(stix_files, attack_version)

    for domain in domains:
        stix_file = stix_files[domain]
        print(f"Exporting {domain} to Excel...")

        # Load STIX data into MemoryStore
        mem_store = MemoryStore()
        mem_store.load_from_file(stix_file)

        # Export to Excel
        attackToExcel.export(
            domain=domain,
            version=attack_version,
            output_dir=output_dir,
            mem_store=mem_store,
        )

        if attack_version and not VERSIONED_OUTPUT_DIR:
            move_versioned_exports_to_domain_dir(output_dir=output_dir, domain=domain, version=attack_version)


if __name__ == "__main__":
    main()
