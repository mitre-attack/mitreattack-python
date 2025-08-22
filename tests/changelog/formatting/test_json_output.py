"""Tests for JSON output generation and validation."""

import json

from mitreattack.diffStix.changelog_helper import AttackChangesEncoder, AttackObjectVersion


class TestJsonOutput:
    """Tests for JSON output generation and validation."""

    def test_attack_changes_encoder_version_object(self):
        """Test AttackChangesEncoder for AttackObjectVersion serialization."""
        encoder = AttackChangesEncoder()
        version = AttackObjectVersion(major=1, minor=2)
        result = encoder.default(version)
        assert result == "1.2"

    def test_get_changes_dict_structure(self, mock_diffstix, sample_technique_object):
        """Test changes dictionary structure generation."""
        mock_diffstix.data["changes"]["techniques"] = {
            "additions": {sample_technique_object["external_references"][0]["external_id"]: sample_technique_object},
            "major_version_changes": {},
            "minor_version_changes": {},
            "patches": {},
            "revocations": {},
            "deprecations": {},
        }

        def mock_get_changes():
            return {
                "techniques": {
                    "additions": [sample_technique_object],
                    "major_version_changes": [],
                    "minor_version_changes": [],
                    "patches": [],
                    "revocations": [],
                    "deprecations": [],
                }
            }

        mock_diffstix.get_changes_dict = mock_get_changes
        result = mock_diffstix.get_changes_dict()
        assert "techniques" in result
        assert "additions" in result["techniques"]
        assert len(result["techniques"]["additions"]) == 1
        assert result["techniques"]["additions"][0]["id"] == sample_technique_object["id"]

    def test_json_file_creation(self, tmp_path, sample_technique_object):
        """Test JSON file creation and writing."""
        json_file = tmp_path / "test_output.json"
        test_data = {"enterprise-attack": {"techniques": {"additions": [sample_technique_object]}}}
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(test_data, f, indent=2, cls=AttackChangesEncoder)
        assert json_file.exists()
        with open(json_file, "r", encoding="utf-8") as f:
            loaded_data = json.load(f)
        assert loaded_data == test_data
