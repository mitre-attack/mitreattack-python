"""Tests for DiffStix output generation methods using real functionality."""

import json
from pathlib import Path

from mitreattack.diffStix.changelog_helper import get_new_changelog_md


class TestDiffStixOutputGeneration:
    """Tests for DiffStix output generation methods using real instances."""

    def test_get_markdown_string_comprehensive(self, lightweight_diffstix):
        """Test comprehensive markdown string generation with real DiffStix."""
        # Test basic markdown generation
        result = lightweight_diffstix.get_markdown_string()

        # Verify structure and content
        assert isinstance(result, str)
        assert len(result) > 0
        assert "## Techniques" in result  # Should have technique section

        # Test with show_key enabled
        lightweight_diffstix.show_key = True
        result_with_key = lightweight_diffstix.get_markdown_string()
        assert "## Key" in result_with_key
        assert "New objects:" in result_with_key
        assert "Major version changes:" in result_with_key

        # Test with contributors enabled
        lightweight_diffstix.include_contributors = True
        lightweight_diffstix.release_contributors = {"Test Contributor": 1}
        result_with_contributors = lightweight_diffstix.get_markdown_string()
        assert "## Contributors to this release" in result_with_contributors
        assert "Test Contributor" in result_with_contributors

    def test_get_changes_dict_comprehensive_structure(self, lightweight_diffstix):
        """Test comprehensive changes dictionary structure with real DiffStix."""
        # Test real changes dict generation
        result = lightweight_diffstix.get_changes_dict()

        # Verify top-level structure
        assert isinstance(result, dict)
        assert "enterprise-attack" in result
        assert "new-contributors" in result

        # Verify domain structure
        domain_data = result["enterprise-attack"]
        assert isinstance(domain_data, dict)

        # Verify all object types are present
        expected_types = [
            "techniques",
            "software",
            "groups",
            "campaigns",
            "assets",
            "mitigations",
            "datasources",
            "datacomponents",
            "detectionstrategies",
            "logsources",
            "analytics",
        ]
        for obj_type in expected_types:
            assert obj_type in domain_data, f"Missing object type: {obj_type}"

            # Verify change categories for each type
            type_data = domain_data[obj_type]
            assert isinstance(type_data, dict)

            expected_categories = [
                "additions",
                "major_version_changes",
                "minor_version_changes",
                "other_version_changes",
                "patches",
                "revocations",
                "deprecations",
                "deletions",
            ]
            for category in expected_categories:
                assert category in type_data, f"Missing category {category} in {obj_type}"
                assert isinstance(type_data[category], list), f"Category {category} should be list"

    def test_get_layers_dict_comprehensive_structure(self, lightweight_diffstix):
        """Test comprehensive layer dictionary generation with real DiffStix."""
        # Test real layer generation
        result = lightweight_diffstix.get_layers_dict()

        # Verify overall structure
        assert isinstance(result, dict)
        assert "enterprise-attack" in result

        # Verify layer structure
        layer = result["enterprise-attack"]
        assert isinstance(layer, dict)

        # Verify required fields
        required_fields = {
            "versions": dict,
            "name": str,
            "description": str,
            "domain": str,
            "techniques": list,
            "sorting": int,
            "hideDisabled": bool,
            "legendItems": list,
            "showTacticRowBackground": bool,
            "tacticRowBackground": str,
            "selectTechniquesAcrossTactics": bool,
        }

        for field, expected_type in required_fields.items():
            assert field in layer, f"Missing required field: {field}"
            assert isinstance(layer[field], expected_type), f"Field {field} should be {expected_type.__name__}"

        # Verify versions structure
        versions = layer["versions"]
        assert "layer" in versions
        assert "navigator" in versions
        assert "attack" in versions

        # Verify domain matches
        assert layer["domain"] == "enterprise-attack"

    def test_end_to_end_output_generation(self, minimal_stix_bundles, tmp_path, setup_test_directories):
        """Test end-to-end output generation with real data flow."""
        # Set up real directories
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, ["enterprise-attack"])

        # Set up output files
        markdown_file = tmp_path / "changelog.md"
        json_file = tmp_path / "changes.json"
        layer_files = [str(tmp_path / "enterprise.json")]

        # Test end-to-end generation
        markdown_result = get_new_changelog_md(
            domains=["enterprise-attack"],
            old=old_dir,
            new=new_dir,
            markdown_file=str(markdown_file),
            json_file=str(json_file),
            layers=layer_files,
            show_key=True,
            include_contributors=True,
            verbose=False,
        )

        # Verify markdown return value
        assert isinstance(markdown_result, str)
        assert len(markdown_result) > 0

        # Verify files were created
        assert markdown_file.exists()
        assert json_file.exists()
        assert Path(layer_files[0]).exists()

        # Verify markdown file content
        markdown_content = markdown_file.read_text()
        assert markdown_content == markdown_result
        assert "## Key" in markdown_content

        # Verify JSON file content
        with open(json_file) as f:
            json_data = json.load(f)
        assert isinstance(json_data, dict)
        assert "enterprise-attack" in json_data

        # Verify layer file content
        with open(layer_files[0]) as f:
            layer_data = json.load(f)
        assert isinstance(layer_data, dict)
        assert layer_data["domain"] == "enterprise-attack"

    def test_output_consistency_across_formats(self, lightweight_diffstix, validate_format_consistency):
        """Test that outputs are consistent across different formats."""
        # Use shared comprehensive validation utility
        validate_format_consistency(lightweight_diffstix, lightweight_diffstix.domains)

    def test_output_with_empty_changes(self, empty_changes_diffstix):
        """Test output generation when there are no changes between versions."""
        diffstix = empty_changes_diffstix

        # Test outputs with no changes
        markdown = diffstix.get_markdown_string()
        changes_dict = diffstix.get_changes_dict()
        layers_dict = diffstix.get_layers_dict()

        # All outputs should be generated successfully even with no changes
        assert isinstance(markdown, str)
        assert isinstance(changes_dict, dict)
        assert isinstance(layers_dict, dict)

        # Verify no changes detected
        domain_changes = changes_dict["enterprise-attack"]["techniques"]
        assert len(domain_changes["additions"]) == 0
        assert len(domain_changes["major_version_changes"]) == 0
        assert len(domain_changes["minor_version_changes"]) == 0

    def test_large_data_handling(self, large_dataset_diffstix):
        """Test output generation with larger datasets."""
        diffstix = large_dataset_diffstix

        # Test that outputs are generated successfully
        markdown = diffstix.get_markdown_string()
        changes_dict = diffstix.get_changes_dict()
        layers_dict = diffstix.get_layers_dict()

        # Verify outputs were generated
        assert isinstance(markdown, str) and len(markdown) > 1000  # Should be substantial
        assert isinstance(changes_dict, dict)
        assert isinstance(layers_dict, dict)

        # Verify expected changes were detected - testing that large datasets generate substantial changes
        domain_changes = changes_dict["enterprise-attack"]["techniques"]
        # From fixture: should have many additions (total 60 objects in new version)
        assert len(domain_changes["additions"]) >= 50  # Should have substantial additions
        # Main point is that large datasets work, not exact counts
