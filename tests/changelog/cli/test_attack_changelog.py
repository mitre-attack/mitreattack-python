"""Tests for the attack_changelog CLI wrapper."""

import argparse
import sys
from pathlib import Path

import pytest

from mitreattack.diffStix import attack_changelog


def test_normalize_release_version_accepts_plain_and_prefixed_versions():
    """Release versions should resolve to the folder naming convention."""
    assert attack_changelog.normalize_release_version("17.1") == "v17.1"
    assert attack_changelog.normalize_release_version("v18.0") == "v18.0"


def test_get_parsed_args_requires_release_versions(monkeypatch):
    """The command requires exactly one old and one new ATT&CK release version."""
    monkeypatch.setattr(sys, "argv", ["attack_changelog"])

    with pytest.raises(SystemExit):
        attack_changelog.get_parsed_args()


def test_get_parsed_args_defaults_and_options(monkeypatch):
    """Parse default and opt-in output arguments."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "attack_changelog",
            "--old-version",
            "17.1",
            "--new-version",
            "v18.0",
            "--stix-version",
            "2.1",
            "--output-dir",
            "custom-output",
            "--domains",
            "enterprise-attack",
            "mobile-attack",
            "--markdown-file",
            "--html-file",
            "--attack-website-links",
            "--verbose",
        ],
    )

    args = attack_changelog.get_parsed_args()

    assert args.old_version == "v17.1"
    assert args.new_version == "v18.0"
    assert args.stix_version == "2.1"
    assert args.output_dir == "custom-output"
    assert args.domains == ["enterprise-attack", "mobile-attack"]
    assert args.markdown_file is True
    assert args.html_file is True
    assert args.attack_website_links is True
    assert args.verbose is True


def test_get_parsed_args_allows_markdown_and_html_flags_without_values(monkeypatch):
    """Markdown and HTML flags can be used as booleans with default filenames."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "attack_changelog",
            "--old-version",
            "17.1",
            "--new-version",
            "18.0",
            "--markdown-file",
            "--html-file",
        ],
    )

    args = attack_changelog.get_parsed_args()

    assert args.markdown_file is True
    assert args.html_file is True


def test_get_parsed_args_defaults_output_dir_and_omits_optional_outputs(monkeypatch):
    """Default output directory should use the normalized release pair."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["attack_changelog", "--old-version", "17.1", "--new-version", "18.0"],
    )

    args = attack_changelog.get_parsed_args()

    assert args.output_dir == "output/v17.1-v18.0"
    assert args.stix_version == "2.0"
    assert args.domains == ["enterprise-attack", "mobile-attack", "ics-attack"]
    assert args.markdown_file is False
    assert args.html_file is False


def test_changelog_request_normalizes_versions_and_defaults():
    """Request normalization should be shared by the CLI and Python API."""
    request = attack_changelog.ChangelogRequest.create(old_version="17.1", new_version="v18.0")

    assert request.old_version == "v17.1"
    assert request.new_version == "v18.0"
    assert request.output_dir == "output/v17.1-v18.0"
    assert request.domains == ["enterprise-attack", "mobile-attack", "ics-attack"]


def test_changelog_request_uses_default_domains_for_empty_domain_list():
    """An empty domain list should resolve to the default domain set."""
    request = attack_changelog.ChangelogRequest.create(old_version="17.1", new_version="18.0", domains=[])

    assert request.domains == ["enterprise-attack", "mobile-attack", "ics-attack"]


def test_changelog_request_deduplicates_domains_while_preserving_order():
    """Duplicate domains should be removed without reordering the caller's choices."""
    request = attack_changelog.ChangelogRequest.create(
        old_version="17.1",
        new_version="18.0",
        domains=["mobile-attack", "enterprise-attack", "mobile-attack"],
    )

    assert request.domains == ["mobile-attack", "enterprise-attack"]


def test_changelog_request_rejects_invalid_domains():
    """Invalid API domains should fail with a clear request-level error."""
    with pytest.raises(ValueError) as exc_info:
        attack_changelog.ChangelogRequest.create(
            old_version="17.1",
            new_version="18.0",
            domains=["bad-domain", "mobile-attack", "other-domain", "bad-domain"],
        )

    assert (
        str(exc_info.value)
        == "Invalid ATT&CK domain(s): bad-domain, other-domain. Expected one of: enterprise-attack, mobile-attack, "
        "ics-attack"
    )


def test_changelog_request_rejects_invalid_stix_version():
    """Invalid API STIX versions should fail with a clear request-level error."""
    with pytest.raises(ValueError) as exc_info:
        attack_changelog.ChangelogRequest.create(old_version="17.1", new_version="18.0", stix_version="2.x")

    assert str(exc_info.value) == "Invalid STIX version: 2.x. Expected one of: 2.0, 2.1"


def test_changelog_artifacts_resolve_output_paths():
    """Artifact planning should keep output filename rules in one place."""
    request = attack_changelog.ChangelogRequest.create(
        old_version="17.1",
        new_version="18.0",
        output_dir="custom",
        markdown_file=True,
        html_file=True,
        attack_website_links=True,
    )

    artifacts = attack_changelog.ChangelogArtifacts.from_request(request)

    assert artifacts.layers == [
        "custom/layer-enterprise.json",
        "custom/layer-mobile.json",
        "custom/layer-ics.json",
    ]
    assert artifacts.markdown_file == "custom/changelog.md"
    assert artifacts.html_file == "custom/index.html"
    assert artifacts.html_file_detailed == "custom/changelog-detailed.html"
    assert artifacts.json_file == "custom/changelog.json"
    assert artifacts.additional_formats_prefix == "/docs/changelogs/v17.1-v18.0"


def test_generate_attack_changelog_uses_existing_local_release_dirs(tmp_path, monkeypatch):
    """Existing release directories should be used without downloading."""
    local_root = tmp_path / "attack-releases"
    old_dir = local_root / "stix-2.0" / "v17.1"
    new_dir = local_root / "stix-2.0" / "v18.0"
    old_dir.mkdir(parents=True)
    new_dir.mkdir(parents=True)
    calls = {}

    def fake_get_new_changelog_md(**kwargs):
        calls["changelog"] = kwargs
        return "markdown"

    def fake_download_domains(**kwargs):
        calls.setdefault("downloads", []).append(kwargs)

    monkeypatch.setattr(attack_changelog, "get_new_changelog_md", fake_get_new_changelog_md)
    monkeypatch.setattr(attack_changelog, "download_domains", fake_download_domains)
    monkeypatch.chdir(tmp_path)

    result = attack_changelog.generate_attack_changelog(old_version="17.1", new_version="18.0")

    assert result == "markdown"
    assert "downloads" not in calls
    assert calls["changelog"]["old"] == str(old_dir)
    assert calls["changelog"]["new"] == str(new_dir)
    assert calls["changelog"]["markdown_file"] is None
    assert calls["changelog"]["html_file"] is None
    assert calls["changelog"]["html_file_detailed"] == "output/v17.1-v18.0/changelog-detailed.html"
    assert calls["changelog"]["json_file"] == "output/v17.1-v18.0/changelog.json"
    assert calls["changelog"]["layers"] == [
        "output/v17.1-v18.0/layer-enterprise.json",
        "output/v17.1-v18.0/layer-mobile.json",
        "output/v17.1-v18.0/layer-ics.json",
    ]
    assert calls["changelog"]["show_key"] is True
    assert calls["changelog"]["include_contributors"] is True


def test_generate_attack_changelog_downloads_missing_release_to_temporary_directory(tmp_path, monkeypatch):
    """Missing releases should be downloaded into a temporary STIX tree and cleaned up after use."""
    local_root = tmp_path / "attack-releases"
    old_dir = local_root / "stix-2.0" / "v17.1"
    old_dir.mkdir(parents=True)
    calls = {}

    def fake_download_domains(**kwargs):
        calls["download"] = kwargs
        release_dir = Path(kwargs["download_dir"]) / "v18.0"
        release_dir.mkdir(parents=True)

    def fake_get_new_changelog_md(**kwargs):
        calls["changelog"] = kwargs
        assert Path(kwargs["new"]).exists()
        return "markdown"

    monkeypatch.setattr(attack_changelog, "download_domains", fake_download_domains)
    monkeypatch.setattr(attack_changelog, "get_new_changelog_md", fake_get_new_changelog_md)
    monkeypatch.chdir(tmp_path)

    result = attack_changelog.generate_attack_changelog(old_version="v17.1", new_version="v18.0")

    assert result == "markdown"
    assert calls["download"]["domains"] == ["enterprise", "mobile", "ics"]
    assert calls["download"]["all_versions"] is False
    assert calls["download"]["stix_version"] == "2.0"
    assert calls["download"]["attack_versions"] == ["18.0"]
    assert calls["changelog"]["old"] == str(old_dir)
    assert calls["changelog"]["new"].endswith("stix-2.0/v18.0")
    assert not Path(calls["changelog"]["new"]).exists()


def test_generate_attack_changelog_passes_opt_in_markdown_html_and_website_links(tmp_path, monkeypatch):
    """Markdown, simple HTML, and website links should be configurable."""
    (tmp_path / "attack-releases" / "stix-2.0" / "v17.1").mkdir(parents=True)
    (tmp_path / "attack-releases" / "stix-2.0" / "v18.0").mkdir(parents=True)
    calls = {}

    def fake_get_new_changelog_md(**kwargs):
        calls["changelog"] = kwargs
        return "markdown"

    monkeypatch.setattr(attack_changelog, "get_new_changelog_md", fake_get_new_changelog_md)
    monkeypatch.chdir(tmp_path)

    attack_changelog.generate_attack_changelog(
        old_version="17.1",
        new_version="18.0",
        output_dir="custom",
        markdown_file=True,
        html_file=True,
        attack_website_links=True,
    )

    assert calls["changelog"]["markdown_file"] == "custom/changelog.md"
    assert calls["changelog"]["html_file"] == "custom/index.html"
    assert calls["changelog"]["additional_formats_prefix"] == "/docs/changelogs/v17.1-v18.0"


def test_generate_attack_changelog_uses_default_optional_output_filenames(tmp_path, monkeypatch):
    """Boolean-style markdown and HTML flags should resolve under the output directory."""
    (tmp_path / "attack-releases" / "stix-2.0" / "v17.1").mkdir(parents=True)
    (tmp_path / "attack-releases" / "stix-2.0" / "v18.0").mkdir(parents=True)
    calls = {}

    def fake_get_new_changelog_md(**kwargs):
        calls["changelog"] = kwargs
        return "markdown"

    monkeypatch.setattr(attack_changelog, "get_new_changelog_md", fake_get_new_changelog_md)
    monkeypatch.chdir(tmp_path)

    attack_changelog.generate_attack_changelog(
        old_version="17.1",
        new_version="18.0",
        markdown_file=True,
        html_file=True,
    )

    assert calls["changelog"]["markdown_file"] == "output/v17.1-v18.0/changelog.md"
    assert calls["changelog"]["html_file"] == "output/v17.1-v18.0/index.html"


def test_generate_attack_changelog_maps_selected_domains_for_download_and_generation(tmp_path, monkeypatch):
    """Selected domains should control downloads and changelog generation."""
    calls = {}

    def fake_download_domains(**kwargs):
        calls["download"] = kwargs
        for version in kwargs["attack_versions"]:
            release_dir = Path(kwargs["download_dir"]) / f"v{version}"
            release_dir.mkdir(parents=True)

    def fake_get_new_changelog_md(**kwargs):
        calls["changelog"] = kwargs
        return "markdown"

    monkeypatch.setattr(attack_changelog, "download_domains", fake_download_domains)
    monkeypatch.setattr(attack_changelog, "get_new_changelog_md", fake_get_new_changelog_md)
    monkeypatch.chdir(tmp_path)

    attack_changelog.generate_attack_changelog(
        old_version="17.1",
        new_version="18.0",
        domains=["mobile-attack"],
    )

    assert calls["download"]["domains"] == ["mobile"]
    assert calls["download"]["attack_versions"] == ["17.1", "18.0"]
    assert calls["changelog"]["domains"] == ["mobile-attack"]
    assert calls["changelog"]["layers"] == [
        "output/v17.1-v18.0/layer-enterprise.json",
        "output/v17.1-v18.0/layer-mobile.json",
        "output/v17.1-v18.0/layer-ics.json",
    ]


def test_main_forwards_parsed_arguments(monkeypatch):
    """The console entrypoint should pass parsed options to the generation API."""
    args = argparse.Namespace(
        old_version="v17.1",
        new_version="v18.0",
        stix_version="2.1",
        output_dir="custom-output",
        domains=["mobile-attack", "enterprise-attack"],
        markdown_file=True,
        html_file=True,
        attack_website_links=True,
        verbose=True,
    )
    calls = {}

    def fake_generate_attack_changelog(**kwargs):
        calls["generate"] = kwargs
        return "markdown"

    monkeypatch.setattr(attack_changelog, "get_parsed_args", lambda: args)
    monkeypatch.setattr(attack_changelog, "generate_attack_changelog", fake_generate_attack_changelog)

    result = attack_changelog.main()

    assert result is None
    assert calls["generate"] == {
        "old_version": "v17.1",
        "new_version": "v18.0",
        "stix_version": "2.1",
        "output_dir": "custom-output",
        "domains": ["mobile-attack", "enterprise-attack"],
        "markdown_file": True,
        "html_file": True,
        "attack_website_links": True,
        "verbose": True,
    }
