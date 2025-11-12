"""Tests for markdown output generation and validation."""

import pytest

from mitreattack.diffStix.formatters.html_output import get_placard_version_string
from mitreattack.diffStix.utils.version_utils import AttackObjectVersion


class TestMarkdownOutput:
    """Tests for markdown output generation and validation."""

    def test_get_markdown_string_basic(self, lightweight_diffstix):
        """Test real markdown string generation."""
        # Test actual markdown generation with real DiffStix instance
        result = lightweight_diffstix.get_markdown_string()

        # Verify real markdown content
        assert isinstance(result, str)
        assert len(result) > 0
        assert "# " in result  # Should contain markdown headers
        assert "Techniques" in result  # Should contain technique sections

        # Test with show_key option
        lightweight_diffstix.show_key = True
        result_with_key = lightweight_diffstix.get_markdown_string()
        assert "## Key" in result_with_key  # Should include key section

    def test_markdown_link_formatting(self, lightweight_diffstix, sample_technique_object):
        """Test real markdown link formatting for ATT&CK objects."""
        # Set site prefix to test link generation
        lightweight_diffstix.site_prefix = "https://attack.mitre.org"

        # Test real placard generation which includes links
        result = lightweight_diffstix.markdown_generator.placard(sample_technique_object, "additions", "enterprise-attack")

        # Verify real link formatting
        assert isinstance(result, str)
        assert "[" in result and "]" in result and "(" in result and ")" in result  # Has markdown link format
        assert "https://attack.mitre.org" in result  # Uses site prefix
        assert "T1234" in result  # Contains technique ID

    def test_placard_revoked_by_missing_name_raises_keyerror(
        self, lightweight_diffstix, sample_technique_object, mock_stix_object_factory
    ):
        """Test placard generation for a revoked object with a revoker missing the name attribute raises KeyError."""
        # Create a revoker object that is missing the 'name' attribute
        revoker = mock_stix_object_factory(
            stix_type="attack-pattern",
            attack_id="T9999",
            external_refs=[{"source_name": "mitre-attack", "external_id": "T9999", "url": "https://example.com/T9999"}],
        )
        # Remove the 'name' attribute to test error handling
        del revoker["name"]

        # Ensure the main object has a name for the placard string
        stix_object_with_revoker = sample_technique_object.copy()
        stix_object_with_revoker["revoked_by"] = revoker
        stix_object_with_revoker["name"] = "Revoked Technique"

        # Test real placard generation with missing name - should raise KeyError
        with pytest.raises(KeyError):
            lightweight_diffstix.markdown_generator.placard(stix_object_with_revoker, "revocations", "enterprise-attack")

    def test_get_placard_version_string_basic(self, sample_technique_object):
        """Test real placard version string generation."""
        # Test with real version objects
        sample_technique_object["previous_version"] = AttackObjectVersion(major=0, minor=9)
        result = get_placard_version_string(sample_technique_object, "major_version_changes")

        # Verify real version string formatting
        assert "(v0.9&#8594;v1.0)" in result
        assert 'style="color:#929393"' in result

        # Test different section types
        addition_result = get_placard_version_string(sample_technique_object, "additions")
        assert "(v1.0)" in addition_result  # Additions only show current version

        # Test invalid version (should show red color)
        invalid_technique = sample_technique_object.copy()
        invalid_technique["x_mitre_version"] = "2.0"  # Invalid for additions
        invalid_result = get_placard_version_string(invalid_technique, "additions")
        assert 'style="color:#eb6635"' in invalid_result  # Should be red for invalid version

    def test_markdown_section_data_generation(self, lightweight_diffstix, sample_technique_object):
        """Test real markdown section data generation with groupings."""
        # Create test groupings using real objects
        test_groupings = [
            {
                "parent": sample_technique_object,
                "parentInSection": True,
                "children": [],
            }
        ]

        # Test real markdown section generation
        result = lightweight_diffstix.markdown_generator.get_markdown_section_data(
            groupings=test_groupings, section="additions", domain="enterprise-attack"
        )

        # Verify real markdown section content
        assert isinstance(result, str)
        assert len(result) > 0
        assert "* " in result  # Should contain list items
        assert sample_technique_object["name"] in result  # Should contain technique name

    def test_contributor_section_generation(self, lightweight_diffstix):
        """Test real contributor section generation."""
        # Set up test contributors
        lightweight_diffstix.release_contributors = {
            "John Doe": 3,
            "Jane Smith": 1,
            "ATT&CK": 5,  # Should be excluded
        }

        # Test real contributor section generation
        result = lightweight_diffstix.contributor_tracker.get_contributor_section()

        # Verify real contributor section content
        assert isinstance(result, str)
        assert "## Contributors to this release" in result
        assert "John Doe" in result
        assert "Jane Smith" in result
        assert "ATT&CK" not in result  # Should be excluded from output

    def test_md_key_generation(self, lightweight_diffstix):
        """Test real markdown key generation."""
        result = lightweight_diffstix.markdown_generator.get_md_key()

        # Verify real key content
        assert isinstance(result, str)
        assert "## Key" in result
        assert "New objects" in result
        assert "Major version changes" in result
        assert "Minor version changes" in result
        assert "Object revocations" in result
        assert "Object deprecations" in result
