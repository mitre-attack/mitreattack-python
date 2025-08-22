"""Tests for STIX object processing functionality."""

from mitreattack.diffStix.changelog_helper import (
    deep_copy_stix,
    get_attack_id,
    get_relative_url_from_stix,
    has_subtechniques,
)


class TestStixProcessing:
    """Tests for STIX object processing functionality."""

    def test_get_attack_id_with_mitre_reference(self, sample_technique_object):
        """Test extracting ATT&CK ID from STIX object with mitre-attack reference."""
        attack_id = get_attack_id(sample_technique_object)
        # TODO: this only works because the sample_technique_object always has an attack_id of T1234
        assert attack_id == "T1234"

    def test_get_relative_url_from_stix_technique(self, sample_technique_object):
        """Test generating relative URL for technique."""
        url = get_relative_url_from_stix(sample_technique_object)
        assert url == "techniques/T1234"

    def test_deep_copy_stix(self, sample_technique_object):
        """Test deep copying STIX objects."""
        stix_objects = [sample_technique_object]
        copied_objects = deep_copy_stix(stix_objects)
        assert copied_objects is not stix_objects
        assert len(copied_objects) == 1
        copied_obj = copied_objects[0]
        assert copied_obj is not sample_technique_object
        assert copied_obj == sample_technique_object
        original_name = sample_technique_object["name"]
        sample_technique_object["name"] = "Modified"
        assert copied_obj["name"] == original_name

    def test_has_subtechniques_true(
        self, sample_technique_object, sample_subtechnique_object, mock_relationship_factory
    ):
        """Test detection of object with subtechniques."""
        subtechnique_relationship = mock_relationship_factory(
            source_ref=sample_subtechnique_object["id"],
            target_ref=sample_technique_object["id"],
            relationship_type="subtechnique-of",
        )
        subtechnique_relationships = {"T1234.001": subtechnique_relationship}
        assert has_subtechniques(sample_technique_object, subtechnique_relationships) is True
