"""Integration test for the encoding of files written by get_new_changelog_md."""

import json
import subprocess
import sys
import textwrap

IDENTITY = {
    "type": "identity",
    "id": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "spec_version": "2.1",
    "name": "The MITRE Corporation",
    "identity_class": "organization",
    "created": "2017-06-01T00:00:00.000Z",
    "modified": "2017-06-01T00:00:00.000Z",
}

MARKING = {
    "type": "marking-definition",
    "id": "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168",
    "spec_version": "2.1",
    "created": "2017-06-01T00:00:00.000Z",
    "definition_type": "statement",
    "definition": {"statement": "Copyright 2017, MITRE."},
}

# Cyrillic and a Turkish dotted lowercase g, neither representable in cp1252 or
# cp950. ATT&CK content does carry non-ASCII, notably in contributor names.
NON_ASCII_NAME = "Обход контроля Türkçe"


def _technique(name, attack_id, stix_id, created, modified):
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "spec_version": "2.1",
        "name": name,
        "description": "test technique",
        "created": created,
        "modified": modified,
        "x_mitre_version": "1.0",
        "x_mitre_domains": ["enterprise-attack"],
        "x_mitre_attack_spec_version": "3.2.0",
        "created_by_ref": IDENTITY["id"],
        "object_marking_refs": [MARKING["id"]],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": attack_id,
                "url": f"https://attack.mitre.org/techniques/{attack_id}",
            }
        ],
    }


def _write_bundles(tmp_path):
    old_technique = _technique(
        "Old Technique",
        "T9999",
        "attack-pattern--1f523a8f-a50f-490a-a0a3-48c8c1f889de",
        "2023-01-01T00:00:00.000Z",
        "2023-01-01T00:00:00.000Z",
    )
    added_technique = _technique(
        NON_ASCII_NAME,
        "T9998",
        "attack-pattern--2f523a8f-a50f-490a-a0a3-48c8c1f889df",
        "2023-06-01T00:00:00.000Z",
        "2023-06-01T00:00:00.000Z",
    )
    for name, objects in [
        ("old", [IDENTITY, MARKING, old_technique]),
        ("new", [IDENTITY, MARKING, old_technique, added_technique]),
    ]:
        directory = tmp_path / name
        directory.mkdir()
        (directory / "enterprise-attack.json").write_text(
            json.dumps({"type": "bundle", "id": f"bundle--{name}", "objects": objects}),
            encoding="utf-8",
        )
    return tmp_path / "old", tmp_path / "new"


def test_markdown_file_is_written_as_utf8(tmp_path):
    """The markdown file must be UTF-8 regardless of the locale encoding.

    Written as a subprocess under PEP 597 rather than a write-then-read-back
    assertion. A round trip passes on an unfixed tree wherever the locale
    encoding already is UTF-8, so on Linux CI it would go green either way and
    pin nothing. `-X warn_default_encoding -W error::EncodingWarning` turns any
    open() that relies on the locale codec into an error, so this fails on every
    platform if the encoding argument goes missing again.

    Only the markdown file is requested. The layer and JSON writers also open
    without an encoding, but they emit through json.dump, whose ensure_ascii
    default keeps their output ASCII, so they are a separate concern.
    """
    old_dir, new_dir = _write_bundles(tmp_path)
    markdown_file = tmp_path / "changelog.md"

    driver = tmp_path / "driver.py"
    driver.write_text(
        textwrap.dedent(
            f"""
            from mitreattack.diffStix.changelog_helper import get_new_changelog_md

            get_new_changelog_md(
                domains=["enterprise-attack"],
                old={str(old_dir)!r},
                new={str(new_dir)!r},
                layers=[],
                json_file=None,
                markdown_file={str(markdown_file)!r},
            )
            """
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-X",
            "warn_default_encoding",
            "-W",
            "error::EncodingWarning",
            str(driver),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert NON_ASCII_NAME in markdown_file.read_text(encoding="utf-8")
