"""Update ATT&CK release hash metadata in mitreattack/release_info.py."""

from __future__ import annotations

import argparse
import ast
import json
import pprint
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DOMAINS = ("enterprise", "mobile", "ics")
SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[1]
RELEASE_INFO_DISPLAY_PATH = Path("mitreattack/release_info.py")
RELEASE_INFO_PATH = REPO_ROOT / RELEASE_INFO_DISPLAY_PATH
REQUIRED_ASSIGNMENTS = ("LATEST_VERSION", "STIX20", "STIX21")


@dataclass(frozen=True)
class ReleaseSource:
    """GitHub release source for an ATT&CK STIX version."""

    stix_version: str
    owner: str
    repo: str
    tag_prefix: str
    assignment_name: str


RELEASE_SOURCES = (
    ReleaseSource(
        stix_version="2.0",
        owner="mitre",
        repo="cti",
        tag_prefix="ATT&CK-v",
        assignment_name="STIX20",
    ),
    ReleaseSource(
        stix_version="2.1",
        owner="mitre-attack",
        repo="attack-stix-data",
        tag_prefix="v",
        assignment_name="STIX21",
    ),
)


def main() -> None:
    """Parse arguments and update release_info.py."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="ATT&CK release version, for example 19.1")
    parser.add_argument("--dry-run", action="store_true", help="Print a summary of updates instead of writing.")
    args = parser.parse_args()

    version = args.version or fetch_latest_common_version()
    hashes = fetch_release_hashes(version=version)
    source = RELEASE_INFO_PATH.read_text()
    updated = update_release_info_source(source, version=version, release_hashes=hashes)

    if args.dry_run:
        print(format_dry_run_summary(source, version=version, release_hashes=hashes))
        return

    RELEASE_INFO_PATH.write_text(updated)
    subprocess.run(["uv", "run", "--extra", "dev", "ruff", "format", str(RELEASE_INFO_PATH)], check=True, cwd=REPO_ROOT)

    print(f"Updated {RELEASE_INFO_DISPLAY_PATH} for ATT&CK v{version}")


def fetch_latest_common_version() -> str:
    """Fetch the latest non-prerelease version present in both STIX release repos."""
    latest_versions = {source.stix_version: fetch_latest_version(source) for source in RELEASE_SOURCES}
    if latest_versions["2.0"] != latest_versions["2.1"]:
        raise SystemExit(
            "Latest STIX release versions do not match: "
            f"STIX 2.0={latest_versions['2.0']}, STIX 2.1={latest_versions['2.1']}. "
            "Pass the desired ATT&CK version explicitly."
        )
    return latest_versions["2.0"]


def fetch_latest_version(source: ReleaseSource) -> str:
    """Fetch the latest GitHub release version for one STIX source."""
    release = github_json(f"https://api.github.com/repos/{source.owner}/{source.repo}/releases/latest")
    return version_from_tag(release["tag_name"], source.tag_prefix)


def fetch_release_hashes(version: str) -> dict[str, dict[str, str]]:
    """Fetch SHA256 hashes for every required STIX source and domain."""
    release_hashes: dict[str, dict[str, str]] = {}
    for source in RELEASE_SOURCES:
        release_hashes[source.assignment_name] = fetch_source_hashes(source, version=version)
    return release_hashes


def fetch_source_hashes(source: ReleaseSource, version: str) -> dict[str, str]:
    """Fetch SHA256 hashes for one STIX release source."""
    tag = f"{source.tag_prefix}{version}"
    url = f"https://api.github.com/repos/{source.owner}/{source.repo}/releases/tags/{quote_tag(tag)}"
    release = github_json(url)
    assets = release.get("assets", [])
    hashes: dict[str, str] = {}

    for domain in DOMAINS:
        asset = find_domain_asset(assets, domain=domain, version=version)
        digest = asset.get("digest")
        if isinstance(digest, str) and digest.startswith("sha256:"):
            hashes[domain] = digest.removeprefix("sha256:")
            continue

        browser_download_url = asset.get("browser_download_url")
        if not isinstance(browser_download_url, str):
            raise SystemExit(f"Missing browser_download_url for {source.owner}/{source.repo} {tag} {asset.get('name')}")
        hashes[domain] = fetch_sha256(browser_download_url)

    return hashes


def update_release_info_source(source: str, version: str, release_hashes: dict[str, dict[str, str]]) -> str:
    """Return release_info.py source updated with the given ATT&CK version and hashes."""
    tree = ast.parse(source)
    assignments = find_assignments(tree)

    stix20 = ast.literal_eval(assignments["STIX20"].value)
    stix21 = ast.literal_eval(assignments["STIX21"].value)

    for assignment_name, stix_hashes in (("STIX20", stix20), ("STIX21", stix21)):
        for domain in DOMAINS:
            stix_hashes[domain][version] = release_hashes[assignment_name][domain]

    replacements = {
        "LATEST_VERSION": f'LATEST_VERSION = "{version}"',
        "STIX20": format_assignment("STIX20", stix20),
        "STIX21": format_assignment("STIX21", stix21),
    }

    return replace_assignments(source, assignments, replacements)


def format_dry_run_summary(source: str, version: str, release_hashes: dict[str, dict[str, str]]) -> str:
    """Return a targeted summary of release_info.py changes without printing the full file."""
    tree = ast.parse(source)
    assignments = find_assignments(tree)
    latest_version = ast.literal_eval(assignments["LATEST_VERSION"].value)
    stix_values = {
        "STIX20": ast.literal_eval(assignments["STIX20"].value),
        "STIX21": ast.literal_eval(assignments["STIX21"].value),
    }

    lines = [f"Would update {RELEASE_INFO_DISPLAY_PATH} for ATT&CK v{version}", "LATEST_VERSION:"]
    if latest_version == version:
        lines.append(f'  unchanged LATEST_VERSION = "{version}"')
    else:
        lines.append(f'- LATEST_VERSION = "{latest_version}"')
        lines.append(f'+ LATEST_VERSION = "{version}"')

    for assignment_name, domain_hashes in release_hashes.items():
        lines.append(f"{assignment_name}:")
        for domain in DOMAINS:
            current_hash = stix_values[assignment_name].get(domain, {}).get(version)
            new_hash = domain_hashes[domain]
            if current_hash is None:
                lines.append(f"+ {assignment_name}.{domain}[{version!r}] = {new_hash!r}")
            elif current_hash == new_hash:
                lines.append(f"  unchanged {assignment_name}.{domain}[{version!r}] = {new_hash!r}")
            else:
                lines.append(f"- {assignment_name}.{domain}[{version!r}] = {current_hash!r}")
                lines.append(f"+ {assignment_name}.{domain}[{version!r}] = {new_hash!r}")

    return "\n".join(lines)


def find_assignments(tree: ast.Module) -> dict[str, ast.Assign]:
    """Find required top-level assignment nodes."""
    assignments: dict[str, ast.Assign] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in REQUIRED_ASSIGNMENTS:
                assignments[target.id] = node

    missing = sorted(set(REQUIRED_ASSIGNMENTS) - set(assignments))
    if missing:
        raise SystemExit(f"Missing required assignment(s): {', '.join(missing)}")
    return assignments


def replace_assignments(source: str, assignments: dict[str, ast.Assign], replacements: dict[str, str]) -> str:
    """Replace assignment source ranges using AST line numbers."""
    lines = source.splitlines()
    for name, replacement in sorted(replacements.items(), key=lambda item: assignments[item[0]].lineno, reverse=True):
        node = assignments[name]
        if node.end_lineno is None:
            raise SystemExit(f"Could not determine source range for {name}")
        lines[node.lineno - 1 : node.end_lineno] = replacement.splitlines()
    return "\n".join(lines) + "\n"


def format_assignment(name: str, value: Any) -> str:
    """Format a Python assignment for release hash data."""
    return f"{name} = {pprint.pformat(value, width=120, sort_dicts=False)}"


def find_domain_asset(assets: list[dict[str, Any]], domain: str, version: str) -> dict[str, Any]:
    """Find the GitHub release asset for a domain."""
    candidate_names = {
        f"{domain}-attack.json",
        f"{domain}-attack-{version}.json",
    }
    for asset in assets:
        if asset.get("name") in candidate_names:
            return asset
    raise SystemExit(
        f"Could not find release asset for {domain}. Expected one of: {', '.join(sorted(candidate_names))}"
    )


def github_json(url: str) -> Any:
    """Fetch JSON from the GitHub API."""
    request = urllib.request.Request(url, headers=github_headers())
    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise SystemExit(f"GitHub API request failed for {url}: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise SystemExit(f"GitHub API request failed for {url}: {error.reason}") from error


def fetch_sha256(url: str) -> str:
    """Download an asset and return its SHA256 hash."""
    import hashlib

    request = urllib.request.Request(url, headers=github_headers())
    sha256_hash = hashlib.sha256()
    try:
        with urllib.request.urlopen(request) as response:
            while chunk := response.read(1024 * 1024):
                sha256_hash.update(chunk)
    except urllib.error.HTTPError as error:
        raise SystemExit(f"Asset download failed for {url}: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise SystemExit(f"Asset download failed for {url}: {error.reason}") from error
    return sha256_hash.hexdigest()


def github_headers() -> dict[str, str]:
    """Build GitHub request headers."""
    return {
        "Accept": "application/vnd.github+json",
        "User-Agent": "mitreattack-python-release-info-updater",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def version_from_tag(tag: str, tag_prefix: str) -> str:
    """Extract an ATT&CK version from a release tag."""
    if not tag.startswith(tag_prefix):
        raise SystemExit(f"Release tag {tag!r} does not start with expected prefix {tag_prefix!r}")
    version = tag.removeprefix(tag_prefix)
    if not re.fullmatch(r"\d+\.\d+(?:[-.][A-Za-z0-9]+)?", version):
        raise SystemExit(f"Could not parse ATT&CK release version from tag {tag!r}")
    return version


def quote_tag(tag: str) -> str:
    """URL-quote a release tag for GitHub API paths."""
    return urllib.parse.quote(tag, safe="")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
