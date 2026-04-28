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
RELEASE_INFO_PATH = Path("mitreattack/release_info.py")
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
    parser.add_argument(
        "--release-info",
        type=Path,
        default=RELEASE_INFO_PATH,
        help=f"Path to release_info.py. Defaults to {RELEASE_INFO_PATH}",
    )
    parser.add_argument("--token", default=None, help="GitHub token. Defaults to GITHUB_TOKEN if set.")
    parser.add_argument("--dry-run", action="store_true", help="Print the updated file instead of writing it.")
    parser.add_argument("--no-format", action="store_true", help="Skip running ruff format after writing.")
    args = parser.parse_args()

    version = args.version or fetch_latest_common_version(token=args.token)
    hashes = fetch_release_hashes(version=version, token=args.token)
    updated = update_release_info_source(args.release_info.read_text(), version=version, release_hashes=hashes)

    if args.dry_run:
        print(updated)
        return

    args.release_info.write_text(updated)
    if not args.no_format:
        subprocess.run(["uv", "run", "--extra", "dev", "ruff", "format", str(args.release_info)], check=True)

    print(f"Updated {args.release_info} for ATT&CK v{version}")


def fetch_latest_common_version(token: str | None = None) -> str:
    """Fetch the latest non-prerelease version present in both STIX release repos."""
    latest_versions = {source.stix_version: fetch_latest_version(source, token=token) for source in RELEASE_SOURCES}
    if latest_versions["2.0"] != latest_versions["2.1"]:
        raise SystemExit(
            "Latest STIX release versions do not match: "
            f"STIX 2.0={latest_versions['2.0']}, STIX 2.1={latest_versions['2.1']}. "
            "Pass the desired ATT&CK version explicitly."
        )
    return latest_versions["2.0"]


def fetch_latest_version(source: ReleaseSource, token: str | None = None) -> str:
    """Fetch the latest GitHub release version for one STIX source."""
    release = github_json(f"https://api.github.com/repos/{source.owner}/{source.repo}/releases/latest", token=token)
    return version_from_tag(release["tag_name"], source.tag_prefix)


def fetch_release_hashes(version: str, token: str | None = None) -> dict[str, dict[str, str]]:
    """Fetch SHA256 hashes for every required STIX source and domain."""
    release_hashes: dict[str, dict[str, str]] = {}
    for source in RELEASE_SOURCES:
        release_hashes[source.assignment_name] = fetch_source_hashes(source, version=version, token=token)
    return release_hashes


def fetch_source_hashes(source: ReleaseSource, version: str, token: str | None = None) -> dict[str, str]:
    """Fetch SHA256 hashes for one STIX release source."""
    tag = f"{source.tag_prefix}{version}"
    url = f"https://api.github.com/repos/{source.owner}/{source.repo}/releases/tags/{quote_tag(tag)}"
    release = github_json(url, token=token)
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
        hashes[domain] = fetch_sha256(browser_download_url, token=token)

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


def github_json(url: str, token: str | None = None) -> Any:
    """Fetch JSON from the GitHub API."""
    request = urllib.request.Request(url, headers=github_headers(token))
    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise SystemExit(f"GitHub API request failed for {url}: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise SystemExit(f"GitHub API request failed for {url}: {error.reason}") from error


def fetch_sha256(url: str, token: str | None = None) -> str:
    """Download an asset and return its SHA256 hash."""
    import hashlib

    request = urllib.request.Request(url, headers=github_headers(token))
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


def github_headers(token: str | None = None) -> dict[str, str]:
    """Build GitHub request headers."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "mitreattack-python-release-info-updater",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = token or env_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def env_github_token() -> str | None:
    """Return GITHUB_TOKEN from the environment without importing os at module import time."""
    import os

    return os.environ.get("GITHUB_TOKEN")


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
