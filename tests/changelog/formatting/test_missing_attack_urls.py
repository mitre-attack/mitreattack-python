"""Markdown fallbacks for ATT&CK objects without website URLs."""

import pytest

from mitreattack.diffStix.changelog_helper import get_relative_data_component_url, get_relative_url_from_stix


def test_later_attack_reference_does_not_supply_url(sample_technique_object):
    """Only the first external reference can supply an object URL."""
    sample_technique_object["external_references"][0].pop("url")
    sample_technique_object["external_references"].extend(
        [
            {"source_name": "citation", "url": "https://example.org/other/T1234"},
            {
                "source_name": "mitre-attack",
                "external_id": "T1234",
                "url": "https://attack.mitre.org/techniques/T1234/",
            },
        ]
    )

    assert get_relative_url_from_stix(sample_technique_object) is None


def test_citation_first_does_not_use_later_attack_url(sample_technique_object):
    """Do not search past a first reference that is a citation."""
    sample_technique_object["external_references"].insert(
        0, {"source_name": "citation", "url": "https://example.org/other/T1234"}
    )

    assert get_relative_url_from_stix(sample_technique_object) is None


@pytest.mark.parametrize("url", [None, "", "https://example.org/techniques/T1234", "https://attack.mitre.org/"])
def test_unusable_attack_url_is_not_linked(sample_technique_object, url):
    """Reject missing, unrelated, and incomplete website URLs."""
    sample_technique_object["external_references"][0]["url"] = url
    assert get_relative_url_from_stix(sample_technique_object) is None


def test_plain_text_placard_when_url_missing(lightweight_diffstix, sample_technique_object):
    """Keep a changed object's placard when its website URL is missing."""
    sample_technique_object["external_references"][0].pop("url")

    result = lightweight_diffstix.placard(sample_technique_object, "additions", "enterprise-attack")

    assert result.startswith(sample_technique_object["name"])
    assert "[" not in result
    assert "/None" not in result

    section = lightweight_diffstix.get_markdown_section_data(
        [{"parent": sample_technique_object, "children": []}], "additions", "enterprise-attack"
    )
    assert f"* {sample_technique_object['name']}" in section


@pytest.mark.parametrize("subtechnique", [False, True])
def test_revoker_without_url_is_plain_text(
    lightweight_diffstix, sample_technique_object, mock_stix_object_factory, subtechnique
):
    """Keep revocation text for both ordinary and subtechnique revokers."""
    revoker = mock_stix_object_factory(name="Replacement Technique", attack_id="T9999")
    revoker["external_references"][0].pop("url")
    revoker["x_mitre_is_subtechnique"] = subtechnique
    sample_technique_object["revoked_by"] = revoker

    result = lightweight_diffstix.placard(sample_technique_object, "revocations", "enterprise-attack")

    assert "revoked by" in result
    assert "Replacement Technique" in result
    assert "[Replacement Technique]" not in result
    assert "/None" not in result


def test_data_component_without_parent_url_is_plain_text(
    lightweight_diffstix, sample_data_source_object, sample_data_component_object
):
    """Keep component text when its parent data source lacks a URL."""
    sample_data_source_object["external_references"][0].pop("url")
    sample_data_component_object["x_mitre_data_source_ref"] = sample_data_source_object["id"]
    lightweight_diffstix.data["new"]["enterprise-attack"]["attack_objects"]["datasources"] = {
        sample_data_source_object["id"]: sample_data_source_object
    }

    assert get_relative_data_component_url(sample_data_source_object, sample_data_component_object) is None
    result = lightweight_diffstix.placard(sample_data_component_object, "additions", "enterprise-attack")

    assert "Test Data Source: Test Data Component" in result
    assert "[Test Data Component]" not in result
    assert "/None" not in result


def test_revoking_data_component_uses_its_name_in_link(
    lightweight_diffstix, sample_technique_object, sample_data_source_object, sample_data_component_object
):
    """Link a revoking component by its own anchor and fall back to text."""
    sample_data_component_object["x_mitre_data_source_ref"] = sample_data_source_object["id"]
    lightweight_diffstix.data["new"]["enterprise-attack"]["attack_objects"]["datasources"] = {
        sample_data_source_object["id"]: sample_data_source_object
    }
    sample_technique_object["revoked_by"] = sample_data_component_object

    result = lightweight_diffstix.placard(sample_technique_object, "revocations", "enterprise-attack")

    assert "#Test%20Data%20Component" in result

    sample_data_source_object["external_references"][0].pop("url")
    result = lightweight_diffstix.placard(sample_technique_object, "revocations", "enterprise-attack")
    assert "Test Data Source: Test Data Component" in result
    assert "[Test Data Component]" not in result
    assert "/None" not in result
