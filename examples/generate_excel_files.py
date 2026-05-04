"""Generate ATT&CK Excel exports from local STIX bundles."""

import argparse
import os

from stix2 import MemoryStore

from mitreattack.attackToExcel import attackToExcel

# Pass attack version via the command line or update the variable below
DEFAULT_ATTACK_VERSION = "v19.0"
# Set to true if you want the parent subfolder of the excel files to have a version.
# Example - If you want the folder to be named enterprise-attack-v19.0 instead of enterprise-attack, set to True
VERSIONED_OUTPUT_DIR = False


def move_versioned_exports_to_domain_dir(output_dir, domain, version):
    """Move versioned Excel exports into the unversioned domain folder."""
    versioned_dir = os.path.join(output_dir, f"{domain}-{version}")
    domain_dir = os.path.join(output_dir, domain)

    if not os.path.isdir(versioned_dir):
        return

    os.makedirs(domain_dir, exist_ok=True)

    for filename in os.listdir(versioned_dir):
        source_path = os.path.join(versioned_dir, filename)
        target_path = os.path.join(domain_dir, filename)

        if not os.path.isfile(source_path):
            continue

        if os.path.exists(target_path):
            os.remove(target_path)

        os.replace(source_path, target_path)

    os.rmdir(versioned_dir)


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
        help=(
            "ATT&CK version to export, such as v19.0. "
            f"Defaults to {DEFAULT_ATTACK_VERSION}."
        ),
    )
    return parser.parse_args(args=argv)


def main(argv=None):
    """Generate excel files for specific versions of ATT&CK."""
    args = parse_args(argv)
    attack_version = args.attack_version

    # List of domains and version to process
    domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
    output_dir = f"{attack_version}/"

    # Path to the STIX bundles for each domain (assumes STIX files are downloaded)
    stix_base_dir = os.environ.get("STIX_BASE_DIR", f"attack-releases/stix-2.0/{attack_version}")
    stix_files = {
        "enterprise-attack": os.path.join(stix_base_dir, "enterprise-attack.json"),
        "mobile-attack": os.path.join(stix_base_dir, "mobile-attack.json"),
        "ics-attack": os.path.join(stix_base_dir, "ics-attack.json"),
    }

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
