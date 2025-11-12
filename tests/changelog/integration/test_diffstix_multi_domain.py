"""Integration tests for multi-domain DiffStix operations."""

import json
import uuid

from mitreattack.diffStix.core.diff_stix import DiffStix


class TestDiffStixMultiDomain:
    """Integration tests for multi-domain DiffStix operations."""

    def test_diffstix_multiple_domains(self, tmp_path):
        """Test DiffStix with multiple domains."""
        domains = ["enterprise-attack", "mobile-attack"]
        test_technique_stix_id = f"attack-pattern--{uuid.uuid4()}"

        # Create test data for each domain
        for domain in domains:
            old_bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "objects": [
                    {
                        "type": "attack-pattern",
                        "id": test_technique_stix_id,
                        "created": "2023-01-01T00:00:00.000Z",
                        "modified": "2023-01-01T00:00:00.000Z",
                        "name": f"Test {domain.title()} Technique",
                        "description": "Test description",
                        "x_mitre_version": "1.0",
                        "external_references": [
                            {
                                "source_name": "mitre-attack",
                                "external_id": "T9999",
                                "url": "https://attack.mitre.org/techniques/T9999",
                            }
                        ],
                    }
                ],
            }

            new_bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "objects": [
                    {
                        "type": "attack-pattern",
                        "id": test_technique_stix_id,
                        "created": "2023-01-01T00:00:00.000Z",
                        "modified": "2023-06-01T00:00:00.000Z",
                        "name": f"Test {domain.title()} Technique",
                        "description": "Updated description",
                        "x_mitre_version": "1.1",
                        "external_references": [
                            {
                                "source_name": "mitre-attack",
                                "external_id": "T9999",
                                "url": "https://attack.mitre.org/techniques/T9999",
                            }
                        ],
                    }
                ],
            }

            # Write files
            old_file = tmp_path / "old" / f"{domain}.json"
            old_file.parent.mkdir(exist_ok=True)
            with open(old_file, "w") as f:
                json.dump(old_bundle, f, indent=2)

            new_file = tmp_path / "new" / f"{domain}.json"
            new_file.parent.mkdir(exist_ok=True)
            with open(new_file, "w") as f:
                json.dump(new_bundle, f, indent=2)

        # Test DiffStix with multiple domains
        diffStix = DiffStix(domains=domains, old=str(tmp_path / "old"), new=str(tmp_path / "new"), verbose=False)

        changes = diffStix.get_changes_dict()

        # Should have changes for both domains
        for domain in domains:
            assert domain in changes
            assert "techniques" in changes[domain]
            assert len(changes[domain]["techniques"]["minor_version_changes"]) == 1

    def test_diffstix_layer_generation_multiple_domains(self, tmp_path):
        """Test layer generation for multiple domains."""
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]

        # Create minimal test data
        for domain in domains:
            bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "objects": [
                    {
                        "type": "attack-pattern",
                        "id": f"attack-pattern--{uuid.uuid4()}",
                        "created": "2023-01-01T00:00:00.000Z",
                        "modified": "2023-01-01T00:00:00.000Z",
                        "name": f"Test {domain} Technique",
                        "description": f"Test description for {domain}",
                        "x_mitre_version": "1.0",
                        "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
                    }
                ],
            }

            for version in ["old", "new"]:
                file_path = tmp_path / version / f"{domain}.json"
                file_path.parent.mkdir(exist_ok=True)
                with open(file_path, "w") as f:
                    json.dump(bundle, f)

        # Test layer generation
        diffStix = DiffStix(domains=domains, old=str(tmp_path / "old"), new=str(tmp_path / "new"), verbose=False)

        layers = diffStix.get_layers_dict()

        # Should have layers for all domains
        for domain in domains:
            assert domain in layers
            assert "name" in layers[domain]
            assert "domain" in layers[domain]
            assert layers[domain]["domain"] == domain
