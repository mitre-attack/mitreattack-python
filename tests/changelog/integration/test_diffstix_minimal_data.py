"""Integration tests for DiffStix class with minimal test data."""

import json

from mitreattack.diffStix.changelog_helper import DiffStix


class TestDiffStixWithMinimalData:
    """Integration tests for DiffStix class with minimal test data."""

    def test_diffstix_change_detection(
        self, tmp_path, mock_stix_object_factory, mitre_identity, mitre_marking_definition
    ):
        """Test DiffStix can detect changes in minimal test data."""
        # Create minimal old STIX bundle using factory
        old_technique = mock_stix_object_factory(
            name="Test Technique",
            attack_id="T9999",
            version="1.0",
            created="2023-01-01T00:00:00.000Z",
            modified="2023-01-01T00:00:00.000Z",
            stix_type="attack-pattern",
            stix_id="attack-pattern--1f523a8f-a50f-490a-a0a3-48c8c1f889de",
        )
        old_technique["description"] = "Original description"

        old_bundle = {
            "type": "bundle",
            "id": "bundle--old",
            "objects": [mitre_identity, mitre_marking_definition, old_technique],
        }

        # Create minimal new STIX bundle using factory
        # Modified technique (same ID, updated version)
        new_technique = old_technique.copy()
        new_technique["modified"] = "2023-06-01T00:00:00.000Z"
        new_technique["description"] = "Updated description"
        new_technique["x_mitre_version"] = "1.1"

        # New technique
        added_technique = mock_stix_object_factory(
            name="New Technique",
            attack_id="T9998",
            version="1.0",
            created="2023-06-01T00:00:00.000Z",
            modified="2023-06-01T00:00:00.000Z",
            stix_type="attack-pattern",
            stix_id="attack-pattern--2a8e3b7c-9d1f-4e5a-b6c7-8f9e0d1a2b3c",
            kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}],
        )
        added_technique["description"] = "Brand new technique"

        new_bundle = {
            "type": "bundle",
            "id": "bundle--new",
            "objects": [mitre_identity, mitre_marking_definition, new_technique, added_technique],
        }

        # Write files
        old_file = tmp_path / "old" / "enterprise-attack.json"
        old_file.parent.mkdir(exist_ok=True)
        with open(old_file, "w") as f:
            json.dump(old_bundle, f, indent=2)

        new_file = tmp_path / "new" / "enterprise-attack.json"
        new_file.parent.mkdir(exist_ok=True)
        with open(new_file, "w") as f:
            json.dump(new_bundle, f, indent=2)

        # Test DiffStix
        diffStix = DiffStix(
            domains=["enterprise-attack"], old=str(old_file.parent), new=str(new_file.parent), verbose=False
        )

        changes = diffStix.get_changes_dict()

        # Should detect one addition and one minor version change
        enterprise_techniques = changes["enterprise-attack"]["techniques"]

        assert len(enterprise_techniques["additions"]) == 1, "Should detect one new technique"
        assert len(enterprise_techniques["minor_version_changes"]) == 1, "Should detect one minor version change"
        assert enterprise_techniques["additions"][0]["name"] == "New Technique"
        assert enterprise_techniques["minor_version_changes"][0]["name"] == "Test Technique"

    def test_diffstix_markdown_generation(
        self, tmp_path, mock_stix_object_factory, mitre_identity, mitre_marking_definition
    ):
        """Test DiffStix generates markdown output."""
        # Create minimal test data using factory
        old_technique = mock_stix_object_factory(
            name="Test Technique",
            attack_id="T9999",
            version="1.0",
            created="2023-01-01T00:00:00.000Z",
            modified="2023-01-01T00:00:00.000Z",
            stix_type="attack-pattern",
            stix_id="attack-pattern--9681e520-b4a5-4b66-803a-0c414b629dd1",
        )
        old_technique["description"] = "Original description"

        old_bundle = {
            "type": "bundle",
            "id": "bundle--9681e520-b4a5-4b66-803a-0c414b629dd1",
            "objects": [mitre_identity, mitre_marking_definition, old_technique],
        }

        # Modified technique (same ID, updated version)
        new_technique = old_technique.copy()
        new_technique["modified"] = "2023-06-01T00:00:00.000Z"
        new_technique["description"] = "Updated description"
        new_technique["x_mitre_version"] = "1.1"

        # New technique
        added_technique = mock_stix_object_factory(
            name="New Technique",
            attack_id="T9998",
            version="1.0",
            created="2023-06-01T00:00:00.000Z",
            modified="2023-06-01T00:00:00.000Z",
            stix_type="attack-pattern",
        )
        added_technique["description"] = "Brand new technique"

        new_bundle = {
            "type": "bundle",
            "id": "bundle--8c1fd915-c856-4f1d-832c-7b1981040099",
            "objects": [mitre_identity, mitre_marking_definition, new_technique, added_technique],
        }

        # Write files
        old_file = tmp_path / "old" / "enterprise-attack.json"
        old_file.parent.mkdir(exist_ok=True)
        with open(old_file, "w") as f:
            json.dump(old_bundle, f, indent=2)

        new_file = tmp_path / "new" / "enterprise-attack.json"
        new_file.parent.mkdir(exist_ok=True)
        with open(new_file, "w") as f:
            json.dump(new_bundle, f, indent=2)

        # Test DiffStix
        diffStix = DiffStix(
            domains=["enterprise-attack"], old=str(old_file.parent), new=str(new_file.parent), verbose=False
        )

        markdown = diffStix.get_markdown_string()

        assert "## Techniques" in markdown, "Should have techniques section"
        assert "### Enterprise" in markdown, "Should have enterprise domain"
        assert "New Technique" in markdown, "Should mention new technique"
        assert "Test Technique" in markdown, "Should mention updated technique"
