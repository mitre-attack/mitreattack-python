"""Generate ATT&CK changelog artifacts for a single release pair."""

import argparse
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Optional

from mitreattack.diffStix.changelog_helper import get_new_changelog_md
from mitreattack.download_stix import download_domains

ATTACK_RELEASES_DIR = Path("attack-releases")


@dataclass(frozen=True)
class DomainConfig:
    """Domain-specific names used by STIX downloads and changelog artifacts."""

    download_name: str
    layer_file: str


DOMAIN_CONFIGS = {
    "enterprise-attack": DomainConfig(download_name="enterprise", layer_file="layer-enterprise.json"),
    "mobile-attack": DomainConfig(download_name="mobile", layer_file="layer-mobile.json"),
    "ics-attack": DomainConfig(download_name="ics", layer_file="layer-ics.json"),
}
DEFAULT_DOMAINS = list(DOMAIN_CONFIGS)
VALID_STIX_VERSIONS = ["2.0", "2.1"]


@dataclass(frozen=True)
class ChangelogRequest:
    """Normalized options for one ATT&CK release changelog generation run."""

    old_version: str
    new_version: str
    stix_version: str = "2.0"
    output_dir: str = ""
    domains: list[str] = field(default_factory=list)
    markdown_file: bool = False
    html_file: bool = False
    attack_website_links: bool = False
    verbose: bool = False

    @classmethod
    def create(
        cls,
        *,
        old_version: str,
        new_version: str,
        stix_version: str = "2.0",
        output_dir: Optional[str] = None,
        domains: Optional[list[str]] = None,
        markdown_file: bool = False,
        html_file: bool = False,
        attack_website_links: bool = False,
        verbose: bool = False,
    ) -> "ChangelogRequest":
        """Return a request with normalized versions and resolved defaults."""
        if stix_version not in VALID_STIX_VERSIONS:
            expected_stix_versions = ", ".join(VALID_STIX_VERSIONS)
            raise ValueError(f"Invalid STIX version: {stix_version}. Expected one of: {expected_stix_versions}")

        old_version = normalize_release_version(old_version)
        new_version = normalize_release_version(new_version)
        return cls(
            old_version=old_version,
            new_version=new_version,
            stix_version=stix_version,
            output_dir=output_dir or _default_output_dir(old_version, new_version),
            domains=normalize_domains(domains),
            markdown_file=markdown_file,
            html_file=html_file,
            attack_website_links=attack_website_links,
            verbose=verbose,
        )


@dataclass(frozen=True)
class ChangelogArtifacts:
    """Output artifact paths for one ATT&CK release changelog generation run."""

    layers: list[str]
    markdown_file: Optional[str]
    html_file: Optional[str]
    html_file_detailed: str
    json_file: str
    additional_formats_prefix: str

    @classmethod
    def from_request(cls, request: ChangelogRequest) -> "ChangelogArtifacts":
        """Return all generated artifact paths for a normalized request."""
        output_dir = Path(request.output_dir)
        return cls(
            layers=[str(output_dir / DOMAIN_CONFIGS[domain].layer_file) for domain in DEFAULT_DOMAINS],
            markdown_file=str(output_dir / "changelog.md") if request.markdown_file else None,
            html_file=str(output_dir / "index.html") if request.html_file else None,
            html_file_detailed=str(output_dir / "changelog-detailed.html"),
            json_file=str(output_dir / "changelog.json"),
            additional_formats_prefix=get_artifact_link_prefix(
                request.old_version,
                request.new_version,
                attack_website_links=request.attack_website_links,
            ),
        )


def normalize_release_version(version: str) -> str:
    """Return an ATT&CK release version with the leading ``v`` folder prefix."""
    return version if version.startswith("v") else f"v{version}"


def normalize_domains(domains: Optional[list[str]]) -> list[str]:
    """Return validated ATT&CK domains with duplicates removed in first-seen order."""
    if not domains:
        return list(DEFAULT_DOMAINS)

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
        expected_domains_text = ", ".join(DEFAULT_DOMAINS)
        raise ValueError(f"Invalid ATT&CK domain(s): {invalid_domains_text}. Expected one of: {expected_domains_text}")

    return normalized_domains


def _version_without_prefix(version: str) -> str:
    """Return an ATT&CK release version without the leading ``v`` folder prefix."""
    return normalize_release_version(version).removeprefix("v")


def _default_output_dir(old_version: str, new_version: str) -> str:
    """Return the default output directory for a release comparison."""
    return f"output/{normalize_release_version(old_version)}-{normalize_release_version(new_version)}"


def _get_release_dir(version: str, stix_version: str, base_dir: Path = ATTACK_RELEASES_DIR) -> Path:
    """Return the local release directory for an ATT&CK/STIX version pair."""
    return (base_dir / f"stix-{stix_version}" / normalize_release_version(version)).resolve()


def get_artifact_link_prefix(old_version: str, new_version: str, *, attack_website_links: bool = False) -> str:
    """Return the link prefix for generated layers and changelog JSON."""
    if not attack_website_links:
        return ""
    return f"/docs/changelogs/{normalize_release_version(old_version)}-{normalize_release_version(new_version)}"


def get_parsed_args():
    """Parse command line arguments for the attack-changelog command."""
    parser = argparse.ArgumentParser(
        description="Generate ATT&CK changelog artifacts for a single ATT&CK release pair."
    )
    parser.add_argument("--old-version", required=True, help="Old ATT&CK release version, e.g. 17.1 or v17.1.")
    parser.add_argument("--new-version", required=True, help="New ATT&CK release version, e.g. 18.0 or v18.0.")
    parser.add_argument(
        "--stix-version",
        choices=["2.0", "2.1"],
        default="2.0",
        help="STIX release tree to use.",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for generated changelog artifacts. Defaults to output/v{old_version}-v{new_version}.",
    )
    parser.add_argument(
        "--domains",
        type=str,
        nargs="+",
        choices=DEFAULT_DOMAINS,
        default=DEFAULT_DOMAINS,
        help="Which ATT&CK domains to compare. Choices and defaults are %(choices)s.",
    )
    parser.add_argument(
        "--markdown-file",
        action="store_true",
        default=False,
        help="Persist markdown output as changelog.md under --output-dir.",
    )
    parser.add_argument(
        "--html-file",
        action="store_true",
        default=False,
        help="Persist HTML output as index.html under --output-dir.",
    )
    parser.add_argument(
        "-w",
        "--attack-website-links",
        action="store_true",
        help="Use ATT&CK website paths for links to generated layers and changelog JSON.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Print status messages.")

    args = parser.parse_args()
    request = ChangelogRequest.create(
        old_version=args.old_version,
        new_version=args.new_version,
        stix_version=args.stix_version,
        output_dir=args.output_dir,
        domains=args.domains,
        markdown_file=args.markdown_file,
        html_file=args.html_file,
        attack_website_links=args.attack_website_links,
        verbose=args.verbose,
    )
    args.old_version = request.old_version
    args.new_version = request.new_version
    args.output_dir = request.output_dir
    args.domains = request.domains
    return args


def _download_missing_releases(
    *,
    missing_versions: list[str],
    domains: list[str],
    stix_version: str,
    temporary_directory: str,
) -> Path:
    """Download missing ATT&CK releases into a temporary STIX directory."""
    temp_stix_dir = Path(temporary_directory) / f"stix-{stix_version}"
    download_domains(
        domains=[DOMAIN_CONFIGS[domain].download_name for domain in domains],
        download_dir=str(temp_stix_dir),
        all_versions=False,
        stix_version=stix_version,
        attack_versions=[_version_without_prefix(version) for version in missing_versions],
    )
    return temp_stix_dir


def _resolve_release_dirs(
    *,
    old_version: str,
    new_version: str,
    stix_version: str,
    domains: list[str],
    temporary_directory: Optional[str],
) -> tuple[Path, Path]:
    """Return old and new release directories, downloading missing releases when needed."""
    old_dir = _get_release_dir(old_version, stix_version)
    new_dir = _get_release_dir(new_version, stix_version)
    missing_versions = list(
        dict.fromkeys(
            version
            for version, release_dir in [(old_version, old_dir), (new_version, new_dir)]
            if not release_dir.is_dir()
        )
    )

    if not missing_versions:
        return old_dir, new_dir

    if temporary_directory is None:
        raise ValueError("temporary_directory is required when release directories are missing")

    temp_stix_dir = _download_missing_releases(
        missing_versions=missing_versions,
        domains=domains,
        stix_version=stix_version,
        temporary_directory=temporary_directory,
    )

    if old_version in missing_versions:
        old_dir = temp_stix_dir / normalize_release_version(old_version)
    if new_version in missing_versions:
        new_dir = temp_stix_dir / normalize_release_version(new_version)

    return old_dir, new_dir


@contextmanager
def resolved_release_dirs(request: ChangelogRequest) -> Generator[tuple[Path, Path], None, None]:
    """Yield old and new release directories, using a temporary download tree if needed."""
    old_dir = _get_release_dir(request.old_version, request.stix_version)
    new_dir = _get_release_dir(request.new_version, request.stix_version)

    if old_dir.is_dir() and new_dir.is_dir():
        yield old_dir, new_dir
        return

    with tempfile.TemporaryDirectory() as temporary_directory:
        yield _resolve_release_dirs(
            old_version=request.old_version,
            new_version=request.new_version,
            stix_version=request.stix_version,
            domains=request.domains,
            temporary_directory=temporary_directory,
        )


def _generate_with_release_dirs(
    *,
    old_dir: Path,
    new_dir: Path,
    request: ChangelogRequest,
) -> str:
    """Generate changelog artifacts with resolved old and new release directories."""
    artifacts = ChangelogArtifacts.from_request(request)
    return get_new_changelog_md(
        domains=request.domains,
        layers=artifacts.layers,
        old=str(old_dir),
        new=str(new_dir),
        show_key=True,
        verbose=request.verbose,
        include_contributors=True,
        markdown_file=artifacts.markdown_file,
        html_file=artifacts.html_file,
        html_file_detailed=artifacts.html_file_detailed,
        additional_formats_prefix=artifacts.additional_formats_prefix,
        json_file=artifacts.json_file,
    )


def generate_attack_changelog(
    *,
    old_version: str,
    new_version: str,
    stix_version: str = "2.0",
    output_dir: Optional[str] = None,
    domains: Optional[list[str]] = None,
    markdown_file: bool = False,
    html_file: bool = False,
    attack_website_links: bool = False,
    verbose: bool = False,
) -> str:
    """Generate ATT&CK changelog artifacts for a single release pair."""
    request = ChangelogRequest.create(
        old_version=old_version,
        new_version=new_version,
        stix_version=stix_version,
        output_dir=output_dir,
        domains=domains,
        markdown_file=markdown_file,
        html_file=html_file,
        attack_website_links=attack_website_links,
        verbose=verbose,
    )

    with resolved_release_dirs(request) as (old_dir, new_dir):
        return _generate_with_release_dirs(
            old_dir=old_dir,
            new_dir=new_dir,
            request=request,
        )


def main():
    """Entrypoint for the attack-changelog console command."""
    args = get_parsed_args()
    generate_attack_changelog(
        old_version=args.old_version,
        new_version=args.new_version,
        stix_version=args.stix_version,
        output_dir=args.output_dir,
        domains=args.domains,
        markdown_file=args.markdown_file,
        html_file=args.html_file,
        attack_website_links=args.attack_website_links,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
