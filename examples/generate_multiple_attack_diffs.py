"""Generate ATT&CK changelog outputs for multiple release pairs."""

import argparse

from mitreattack.diffStix.attack_changelog import generate_attack_changelog

DOMAINS = ["enterprise-attack", "mobile-attack", "ics-attack"]
VERSION_PAIRS = [
    ("17.1", "18.0"),
    ("18.0", "18.1"),
]



def get_parsed_args():
    """Parse command line arguments for the example script."""
    parser = argparse.ArgumentParser(description="Generate ATT&CK changelog outputs for multiple release pairs.")
    parser.add_argument(
        "-w",
        "--attack-website-links",
        action="store_true",
        help="Use ATT&CK website paths for links to generated layers and changelog JSON.",
    )
    return parser.parse_args()


def generate_diff(old_version: str, new_version: str, *, attack_website_links: bool = False):
    """Generate changelog outputs for a single ATT&CK release pair."""
    output_folder = f"output/v{old_version}-v{new_version}"
    print(f"Generating ATT&CK Diffs between {old_version}-{new_version}: {output_folder}")

    generate_attack_changelog(
        old_version=old_version,
        new_version=new_version,
        domains=DOMAINS,
        output_dir=output_folder,
        verbose=True,
        markdown_file=True,
        html_file=True,
        attack_website_links=attack_website_links,
    )


def main():
    """Generate changelog outputs for all configured ATT&CK release pairs."""
    args = get_parsed_args()
    for old_version, new_version in VERSION_PAIRS:
        generate_diff(old_version, new_version, attack_website_links=args.attack_website_links)


if __name__ == "__main__":
    main()
