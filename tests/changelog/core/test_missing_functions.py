"""Tests for previously untested functions in changelog_helper.py."""

import json
from pathlib import Path

from mitreattack.diffStix.core.attack_changes_encoder import AttackChangesEncoder
from mitreattack.diffStix.formatters.html_output import markdown_to_html, write_detailed_html
from mitreattack.diffStix.formatters.layer_output import layers_dict_to_files
from mitreattack.diffStix.utils.url_utils import get_relative_data_component_url
from mitreattack.diffStix.utils.version_utils import AttackObjectVersion


class TestMissingFunctions:
    """Tests for functions that were missing comprehensive coverage."""

    def test_attack_changes_encoder_real_serialization(self, sample_technique_object):
        """Test real JSON encoding with AttackChangesEncoder."""
        # Create test data with AttackObjectVersion objects
        test_data = {
            "old_version": AttackObjectVersion(major=1, minor=0),
            "new_version": AttackObjectVersion(major=1, minor=1),
            "technique": sample_technique_object,
            "regular_string": "test",
            "regular_number": 42,
        }

        # Test real JSON encoding
        result = json.dumps(test_data, cls=AttackChangesEncoder, indent=2)

        # Verify real encoding worked
        assert isinstance(result, str)
        assert '"old_version": "1.0"' in result  # AttackObjectVersion should be encoded as string
        assert '"new_version": "1.1"' in result
        assert '"regular_string": "test"' in result  # Regular objects should work normally
        assert '"regular_number": 42' in result

        # Verify it can be decoded back
        decoded = json.loads(result)
        assert decoded["old_version"] == "1.0"
        assert decoded["new_version"] == "1.1"
        assert decoded["regular_string"] == "test"
        assert decoded["regular_number"] == 42

    def test_get_relative_data_component_url_real_generation(self, mock_stix_object_factory):
        """Test real data component URL generation."""
        # Create datasource object manually since factory doesn't handle datasources correctly
        datasource = {
            "id": "x-mitre-data-source--test-id",
            "type": "x-mitre-data-source",
            "name": "Test Data Source",
            "description": "Test data source description",
            "x_mitre_version": "1.0",
            "created": "2023-01-01T00:00:00.000Z",
            "modified": "2023-01-01T00:00:00.000Z",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "DS1234",
                    "url": "https://attack.mitre.org/datasources/DS1234",
                }
            ],
        }

        datacomponent = {
            "id": "x-mitre-data-component--test-id",
            "type": "x-mitre-data-component",
            "name": "Test Data Component",
            "description": "Test data component description",
            "x_mitre_version": "1.0",
            "created": "2023-01-01T00:00:00.000Z",
            "modified": "2023-01-01T00:00:00.000Z",
        }

        # Test real URL generation
        result = get_relative_data_component_url(datasource, datacomponent)

        # Verify real URL structure
        assert isinstance(result, str)
        assert "datasources/DS1234/" in result
        assert "Test%20Data%20Component" in result  # Spaces should be URL encoded
        assert result.startswith("datasources/")
        assert result.endswith("#Test%20Data%20Component")

    def test_markdown_to_html_real_conversion(self, lightweight_diffstix, tmp_path):
        """Test real markdown to HTML conversion."""
        # Generate real markdown content
        markdown_content = lightweight_diffstix.get_markdown_string()
        output_file = tmp_path / "test_output.html"

        # Test real HTML conversion
        markdown_to_html(str(output_file), markdown_content, lightweight_diffstix)

        # Verify real HTML file was created
        assert output_file.exists()
        html_content = output_file.read_text(encoding="utf-8")

        # Verify HTML structure
        assert isinstance(html_content, str)
        assert len(html_content) > 0
        assert "<h1 style='text-align:center;'>" in html_content  # Header should be present
        assert "ATT&CK Changes Between" in html_content  # Title should be present
        assert "<div style='max-width: 55em;" in html_content  # CSS styling should be present
        assert "</div>" in html_content  # Closing div should be present

        # Verify markdown was converted to HTML
        if "# " in markdown_content:
            # when the python markdown Table of Contents plugin is enabled, it changes the <h1> and <h2> tags
            # to include id attributes and maybe a style attribute (at least to <h1>) so this assert statement
            # looks a little funny, but is good enough
            # https://python-markdown.github.io/extensions/toc/
            assert "<h1" in html_content or "<h2" in html_content  # Headers should be converted

    def test_layers_dict_to_files_real_file_writing(self, mock_layers_dict, tmp_path):
        """Test real layer files generation."""
        # Set up output file paths
        outfiles = [
            str(tmp_path / "enterprise_layer.json"),
            str(tmp_path / "mobile_layer.json"),
            str(tmp_path / "ics_layer.json"),
        ]

        # Test real layer file writing
        layers_dict_to_files(outfiles, mock_layers_dict)

        # Verify real files were created
        for i, outfile in enumerate(outfiles):
            file_path = Path(outfile)
            assert file_path.exists()

            # Verify file content
            with open(file_path) as f:
                layer_data = json.load(f)

            # Verify real layer structure
            assert isinstance(layer_data, dict)
            assert "name" in layer_data
            assert "domain" in layer_data
            assert "techniques" in layer_data
            assert "versions" in layer_data

            # Verify correct domain mapping
            expected_domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
            assert layer_data["domain"] == expected_domains[i]

    def test_write_detailed_html_real_generation(self, complex_diffstix_with_all_changes, tmp_path):
        """Test real detailed HTML report generation."""
        output_file = tmp_path / "detailed_report.html"

        # Test real detailed HTML generation
        write_detailed_html(str(output_file), complex_diffstix_with_all_changes)

        # Verify real HTML file was created
        assert output_file.exists()
        html_content = output_file.read_text(encoding="utf-8", errors="xmlcharrefreplace")

        # Verify HTML structure and content
        assert isinstance(html_content, str)
        assert len(html_content) > 0
        assert "<!DOCTYPE html>" in html_content  # Valid HTML document
        assert "<html>" in html_content and "</html>" in html_content
        assert "<head>" in html_content and "</head>" in html_content
        assert "<body>" in html_content and "</body>" in html_content

        # Verify ATT&CK-specific content
        assert "ATT&CK Changes Between" in html_content  # Title should be present
        assert "<h2>" in html_content  # Should have section headers
        assert "Techniques" in html_content  # Should have technique sections

        # Verify styling
        assert "table.diff" in html_content  # CSS styles should be present
        assert ".diff_add" in html_content  # Diff styles should be present

        # Verify navigation links
        assert "layer-enterprise.json" in html_content  # Layer file links
        assert "changelog.json" in html_content  # JSON file link

    def test_layers_dict_to_files_missing_domains(self, tmp_path):
        """Test layer file generation with missing domains."""
        # Test with layer dict missing some domains
        partial_layers = {
            "enterprise-attack": {
                "name": "Enterprise Only",
                "domain": "enterprise-attack",
                "techniques": [],
                "versions": {"layer": "4.5", "navigator": "5.0.0", "attack": "17.0"},
            }
        }

        outfiles = [
            str(tmp_path / "enterprise.json"),
            str(tmp_path / "mobile.json"),  # This won't be created
            str(tmp_path / "ics.json"),  # This won't be created
        ]

        # Should not raise error for missing domains
        layers_dict_to_files(outfiles, partial_layers)

        # Verify only enterprise file was created
        assert Path(outfiles[0]).exists()
        assert not Path(outfiles[1]).exists()
        assert not Path(outfiles[2]).exists()

    def test_markdown_to_html_version_handling(self, tmp_path, diffstix_with_version_scenarios):
        """Test HTML generation with different version scenarios."""
        # Create DiffStix with None new version scenario
        old_version = "17.1"
        diffstix = diffstix_with_version_scenarios(old_version, None)

        output_file = tmp_path / "version_test.html"
        test_content = "# Test Content"

        # Test with None new version
        markdown_to_html(str(output_file), test_content, diffstix)

        html_content = output_file.read_text(encoding="utf-8")
        assert f"ATT&CK Changes Between v{old_version} and new content" in html_content

        # Test with both versions present
        old_version = "17.1"
        new_version = "18.0"
        diffstix_both_versions = diffstix_with_version_scenarios(old_version, new_version)
        output_file2 = tmp_path / "version_test2.html"

        markdown_to_html(str(output_file2), test_content, diffstix_both_versions)

        html_content2 = output_file2.read_text(encoding="utf-8")
        assert f"ATT&CK Changes Between v{old_version} and v{new_version}" in html_content2
