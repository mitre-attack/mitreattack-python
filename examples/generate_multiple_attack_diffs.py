"""Generate ATT&CK changelog outputs for multiple release pairs."""

import argparse

from mitreattack.diffStix.changelog_helper import get_new_changelog_md

DOMAINS = ["enterprise-attack", "mobile-attack", "ics-attack"]
VERSION_PAIRS = [
    ("17.1", "18.0"),
    ("18.0", "18.1"),
]


def get_release_output_folder(old_version: str, new_version: str) -> str:
    """Return the output folder for a release comparison."""
    return f"output/v{old_version}-v{new_version}"


def get_artifact_link_prefix(old_version: str, new_version: str, *, attack_website_links: bool = False) -> str:
    """Return the link prefix for generated layers and changelog JSON."""
    if not attack_website_links:
        return ""
    return f"/docs/changelogs/v{old_version}-v{new_version}"


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
    output_folder = get_release_output_folder(old_version, new_version)
    print(f"Generating ATT&CK Diffs between {old_version}-{new_version}: {output_folder}")

    get_new_changelog_md(
        domains=DOMAINS,
        layers=[
            f"{output_folder}/layer-enterprise.json",
            f"{output_folder}/layer-mobile.json",
            f"{output_folder}/layer-ics.json",
        ],
        old=f"attack-releases/stix-2.0/v{old_version}",
        new=f"attack-releases/stix-2.0/v{new_version}",
        show_key=True,
        # site_prefix: str = "",
        verbose=True,
        include_contributors=True,
        markdown_file=f"{output_folder}/changelog.md",
        html_file=f"{output_folder}/index.html",
        html_file_detailed=f"{output_folder}/changelog-detailed.html",
        additional_formats_prefix=get_artifact_link_prefix(
            old_version,
            new_version,
            attack_website_links=attack_website_links,
        ),
        json_file=f"{output_folder}/changelog.json",
    )


def main():
    """Generate changelog outputs for all configured ATT&CK release pairs."""
    args = get_parsed_args()
    for old_version, new_version in VERSION_PAIRS:
        generate_diff(old_version, new_version, attack_website_links=args.attack_website_links)


if __name__ == "__main__":
    main()
