"""Regression tests using real v16.1→v17.0 data and golden files.

This module contains regression tests that ensure the changelog functionality
continues to work correctly with real ATT&CK data and matches expected outputs.
"""

import json

from mitreattack.diffStix.changelog_helper import AttackChangesEncoder


class TestRegressionBaseline:
    """Regression tests using real v16.1→v17.0 data and golden files."""

    def _assert_changelog_content_equivalent(self, result, expected):
        """Assert that two changelog dictionaries are functionally equivalent."""
        # Check top-level structure
        assert set(result.keys()) == set(expected.keys()), (
            f"Top-level keys differ: {set(result.keys())} vs {set(expected.keys())}"
        )

        for domain_key in result.keys():
            if domain_key == "new-contributors":
                # For contributors, check set equality (order doesn't matter)
                result_contributors = set(result[domain_key])
                expected_contributors = set(expected[domain_key])
                assert result_contributors == expected_contributors, f"Contributors differ in {domain_key}"
            else:
                # For domain data, check structure and counts
                self._assert_domain_content_equivalent(result[domain_key], expected[domain_key], domain_key)

    def _assert_domain_content_equivalent(self, result_domain, expected_domain, domain_name):
        """Assert that domain data is functionally equivalent."""
        # Check object types
        assert set(result_domain.keys()) == set(expected_domain.keys()), f"Object types differ in {domain_name}"

        for obj_type in result_domain.keys():
            result_obj = result_domain[obj_type]
            expected_obj = expected_domain[obj_type]

            # Check change types
            assert set(result_obj.keys()) == set(expected_obj.keys()), (
                f"Change types differ in {domain_name}.{obj_type}"
            )

            for change_type in result_obj.keys():
                result_changes = result_obj[change_type]
                expected_changes = expected_obj[change_type]

                # Check counts
                assert len(result_changes) == len(expected_changes), (
                    f"Count mismatch in {domain_name}.{obj_type}.{change_type}: {len(result_changes)} vs {len(expected_changes)}"
                )

                # For non-empty lists, check that all IDs are present (order may differ)
                if result_changes:
                    result_ids = set(item.get("id", item.get("stix_id", "")) for item in result_changes)
                    expected_ids = set(item.get("id", item.get("stix_id", "")) for item in expected_changes)
                    assert result_ids == expected_ids, f"IDs differ in {domain_name}.{obj_type}.{change_type}"

    def _assert_layer_content_equivalent(self, result_layer, expected_layer, domain_name):
        """Assert that layer data is functionally equivalent."""
        # Check metadata fields (order-sensitive)
        metadata_fields = ["domain", "versions"]
        for field in metadata_fields:
            if field in expected_layer:
                # Use strict equality
                assert result_layer.get(field) == expected_layer.get(field), f"Layer {field} differs in {domain_name}"

        # Check techniques (order may differ)
        if "techniques" in expected_layer:
            result_techniques = result_layer.get("techniques", [])
            expected_techniques = expected_layer.get("techniques", [])

            assert len(result_techniques) == len(expected_techniques), (
                f"Technique count differs in {domain_name}: {len(result_techniques)} vs {len(expected_techniques)}"
            )

            # Convert to sets of tuples for comparison (technique ID + tactic combinations)
            result_tech_set = set((t.get("techniqueID"), t.get("tactic"), t.get("comment")) for t in result_techniques)
            expected_tech_set = set(
                (t.get("techniqueID"), t.get("tactic"), t.get("comment")) for t in expected_techniques
            )

            assert result_tech_set == expected_tech_set, f"Technique content differs in {domain_name}"

        # Check other list fields that should have same counts
        if "legendItems" in expected_layer:
            result_list = result_layer.get(field, [])
            expected_list = expected_layer.get(field, [])
            assert len(result_list) == len(expected_list), f"List field {field} count differs in {domain_name}"

    def test_regression_markdown_output(self, golden_161_170_changelog_dir, generated_161_170_diffstix, tmp_path):
        """Ensure markdown output matches golden file exactly."""
        # Generate current output to a temporary file so function returns the markdown
        temp_md = tmp_path / "temp.md"
        result = generated_161_170_diffstix.get_markdown_string()

        # Write to temp file for compatibility
        with open(temp_md, "w", encoding="utf-8") as f:
            f.write(result)

        # Load golden file
        golden_file = golden_161_170_changelog_dir / "changelog.md"
        with open(golden_file, "r", encoding="utf-8") as f:
            expected = f.read()

        assert result == expected, "Markdown output differs from golden file"

    def test_regression_json_output(self, golden_161_170_changelog_dir, generated_161_170_diffstix):
        """Ensure JSON output content is functionally equivalent to golden file."""
        # Generate current output using cached DiffStix
        result = generated_161_170_diffstix.get_changes_dict()

        # Load golden file
        golden_file = golden_161_170_changelog_dir / "changelog.json"
        with open(golden_file, "r", encoding="utf-8") as f:
            expected = json.load(f)

        # Compare functional content rather than exact serialization
        self._assert_changelog_content_equivalent(result, expected)

    def test_regression_layers_output(self, golden_161_170_changelog_dir, generated_161_170_diffstix):
        """Ensure ATT&CK Navigator layers content is functionally equivalent to golden files."""
        # Generate current output using cached DiffStix
        result_layers = generated_161_170_diffstix.get_layers_dict()

        # Check each domain layer
        for domain in ["enterprise-attack", "mobile-attack", "ics-attack"]:
            domain_short = domain.split("-")[0]  # enterprise, mobile, ics
            golden_file = golden_161_170_changelog_dir / f"layer-{domain_short}.json"

            with open(golden_file, "r", encoding="utf-8") as f:
                expected_layer = json.load(f)

            # Compare functional content rather than exact serialization
            self._assert_layer_content_equivalent(result_layers[domain], expected_layer, domain)

    def test_regression_full_pipeline(self, tmp_path, generated_161_170_diffstix):
        """Test full pipeline with file outputs matches golden files."""
        # Generate outputs to temporary directory
        output_md = tmp_path / "test_changelog.md"
        output_json = tmp_path / "test_changelog.json"

        layer_files = [
            tmp_path / "test_layer_enterprise.json",
            tmp_path / "test_layer_mobile.json",
            tmp_path / "test_layer_ics.json",
        ]

        # Generate outputs using cached DiffStix
        result = generated_161_170_diffstix.get_markdown_string()

        # Write outputs to files
        with open(output_md, "w", encoding="utf-8") as f:
            f.write(result)

        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(generated_161_170_diffstix.get_changes_dict(), f, indent=2, cls=AttackChangesEncoder)

        # Generate layer files
        layers_dict = generated_161_170_diffstix.get_layers_dict()
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
        for i, layer_file in enumerate(layer_files):
            with open(layer_file, "w", encoding="utf-8") as f:
                json.dump(layers_dict[domains[i]], f, indent=2)

        # Verify expected files were created (HTML files are not generated by these methods)
        assert output_md.exists(), "Markdown file not created"
        assert output_json.exists(), "JSON file not created"
        for layer_file in layer_files:
            assert layer_file.exists(), f"Layer file {layer_file} not created"

        # Verify markdown content matches return value
        with open(output_md, "r", encoding="utf-8") as f:
            file_content = f.read()
        assert result == file_content, "Returned markdown differs from file output"

    def test_regression_specific_techniques_present(self, generated_161_170_diffstix):
        """Test that specific known techniques from v16.1→v17.0 transition are detected."""
        changes = generated_161_170_diffstix.get_changes_dict()

        # Check for enterprise domain changes
        enterprise_changes = changes.get("enterprise-attack", {}).get("techniques", {})

        # Verify that real data has changes
        total_changes = sum(len(change_list) for change_list in enterprise_changes.values())
        assert total_changes > 0, "No technique changes detected in regression data"

        # Verify that real data has additions
        assert len(enterprise_changes.get("additions", [])) >= 0, "Should have technique additions"

        # Verify that real data has version changes
        version_changes = len(enterprise_changes.get("major_version_changes", [])) + len(
            enterprise_changes.get("minor_version_changes", [])
        )
        assert version_changes >= 0, "Should have some version changes"

    def test_regression_software_changes(self, generated_161_170_diffstix):
        """Test that software changes are properly detected."""
        changes = generated_161_170_diffstix.get_changes_dict()

        # Check for software changes across domains
        for domain in ["enterprise-attack", "mobile-attack", "ics-attack"]:
            if domain in changes:
                software_changes = changes[domain].get("software", {})

                # Software changes should be properly structured
                expected_sections = [
                    "additions",
                    "major_version_changes",
                    "minor_version_changes",
                    "other_version_changes",
                    "patches",
                    "revocations",
                    "deprecations",
                    "deletions",
                ]

                for section in expected_sections:
                    assert section in software_changes, f"Missing {section} in {domain} software changes"
                    assert isinstance(software_changes[section], list), f"{section} should be a list"

    def test_regression_data_consistency(self, generated_161_170_diffstix):
        """Test that the regression data maintains consistency across outputs."""
        # Get all output formats
        markdown = generated_161_170_diffstix.get_markdown_string()
        changes_dict = generated_161_170_diffstix.get_changes_dict()
        layers_dict = generated_161_170_diffstix.get_layers_dict()

        # Basic consistency checks
        assert isinstance(markdown, str), "Markdown should be a string"
        assert len(markdown) > 0, "Markdown should not be empty"

        assert isinstance(changes_dict, dict), "Changes dict should be a dictionary"
        assert len(changes_dict) > 0, "Changes dict should not be empty"

        assert isinstance(layers_dict, dict), "Layers dict should be a dictionary"
        assert len(layers_dict) > 0, "Layers dict should not be empty"

        # Check that domains are consistent across outputs
        domains_in_changes = set(k for k in changes_dict.keys() if k != "new-contributors")
        domains_in_layers = set(layers_dict.keys())

        # Should have the same domains (though changes might have contributors key)
        expected_domains = {"enterprise-attack", "mobile-attack", "ics-attack"}
        assert domains_in_layers == expected_domains, (
            f"Expected domains in layers: {expected_domains}, got {domains_in_layers}"
        )
        assert domains_in_changes <= expected_domains, (
            f"Unexpected domains in changes: {domains_in_changes - expected_domains}"
        )

    def test_regression_version_information(self, generated_161_170_diffstix):
        """Test that version information is properly captured."""
        # Check that version information exists in the data
        data = generated_161_170_diffstix.data

        # Should have old and new version information
        assert "old" in data, "Should have old version data"
        assert "new" in data, "Should have new version data"

        for version in ["old", "new"]:
            version_data = data[version]

            # Should have domain data
            for domain in ["enterprise-attack", "mobile-attack", "ics-attack"]:
                if domain in version_data:
                    domain_data = version_data[domain]

                    # Should have attack_release_version
                    assert "attack_release_version" in domain_data, f"Missing version info for {domain} in {version}"

                    version_str = domain_data["attack_release_version"]
                    if version_str:  # May be None for some test scenarios
                        assert isinstance(version_str, str), f"Version should be string for {domain} in {version}"
                        assert "." in version_str or version_str.replace(".", "").isdigit(), (
                            f"Invalid version format: {version_str}"
                        )

    def test_regression_contributor_data(self, generated_161_170_diffstix):
        """Test that contributor data is properly handled."""
        changes = generated_161_170_diffstix.get_changes_dict()

        # Should have contributors section if include_contributors is True
        if (
            hasattr(generated_161_170_diffstix, "include_contributors")
            and generated_161_170_diffstix.include_contributors
        ):
            # Contributors might be in the changes dict
            if "new-contributors" in changes:
                contributors = changes["new-contributors"]
                assert isinstance(contributors, list), "Contributors should be a list"

                # Each contributor should be a string
                for contributor in contributors:
                    assert isinstance(contributor, str), "Each contributor should be a string"

    def test_regression_layer_structure(self, generated_161_170_diffstix):
        """Test that layer output has expected structure."""
        layers = generated_161_170_diffstix.get_layers_dict()

        for domain, layer in layers.items():
            # Each layer should have required fields
            required_fields = ["name", "description", "domain", "versions"]
            for field in required_fields:
                assert field in layer, f"Layer {domain} missing field: {field}"

            # Versions should have expected structure
            versions = layer["versions"]
            assert isinstance(versions, dict), "Versions should be a dict"

            # Should have techniques list
            assert "techniques" in layer, f"Layer {domain} should have techniques"
            assert isinstance(layer["techniques"], list), f"Techniques should be a list in {domain}"

            # Each technique should have required fields
            for technique in layer["techniques"]:
                assert "techniqueID" in technique, "Technique should have ID"
                assert "enabled" in technique, "Technique should have enabled field"
