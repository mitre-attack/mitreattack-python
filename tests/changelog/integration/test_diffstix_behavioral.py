"""Behavioral tests that focus on DiffStix outputs rather than internal structure."""

import uuid

from mitreattack.diffStix.changelog_helper import DiffStix


class TestDiffStixBehavioralTesting:
    """Behavioral tests that focus on DiffStix outputs rather than internal structure."""

    def test_change_detection_behavior(self, lightweight_diffstix):
        """Test that DiffStix correctly detects and categorizes changes.

        This test validates behavior: what changes are detected and how they're categorized,
        rather than testing internal data structure organization.
        """
        # Act: Get changes using public interface
        changes_dict = lightweight_diffstix.get_changes_dict()

        assert isinstance(changes_dict, dict), f"Changes should be dict, got {type(changes_dict)}"

        expected_domains = ["enterprise-attack"]
        expected_types = ["techniques"]

        for domain in expected_domains:
            assert domain in changes_dict, f"Expected domain '{domain}' in changes, got: {list(changes_dict.keys())}"

        # Validate structure for each domain (skip new-contributors which is a list)
        for domain, domain_changes in changes_dict.items():
            if domain == "new-contributors":
                assert isinstance(domain_changes, list), f"New contributors should be list, got {type(domain_changes)}"
                continue

            assert isinstance(domain_changes, dict), (
                f"Domain '{domain}' changes should be dict, got {type(domain_changes)}"
            )

            for obj_type in expected_types:
                assert obj_type in domain_changes, (
                    f"Expected object type '{obj_type}' in domain '{domain}', got: {list(domain_changes.keys())}"
                )

                # Validate change categories
                change_categories = [
                    "additions",
                    "major_version_changes",
                    "minor_version_changes",
                    "other_version_changes",
                    "patches",
                    "revocations",
                    "deprecations",
                    "deletions",
                ]
                changes_obj = domain_changes[obj_type]
                assert isinstance(changes_obj, dict), (
                    f"Changes for {domain}.{obj_type} should be dict, got {type(changes_obj)}"
                )

                for category in change_categories:
                    assert category in changes_obj, (
                        f"Missing change category '{category}' in {domain}.{obj_type}, got: {list(changes_obj.keys())}"
                    )
                    assert isinstance(changes_obj[category], list), (
                        f"Change category '{category}' should be list in {domain}.{obj_type}, "
                        f"got {type(changes_obj[category])}"
                    )

    def test_output_format_consistency(self, lightweight_diffstix, validate_format_consistency):
        """Test that all output formats are consistent and properly structured.

        This validates the public API contracts rather than internal implementation.
        """
        # Use shared comprehensive validation utility
        validate_format_consistency(lightweight_diffstix, lightweight_diffstix.domains)

    def test_error_resilience_behavior(self, tmp_path, setup_test_directories):
        """Test that DiffStix handles edge cases gracefully.

        This tests error handling behavior rather than specific internal error states.
        """
        # Create invalid STIX data to test error handling
        bundle_id = str(uuid.uuid4())
        object_id = str(uuid.uuid4())

        invalid_bundle = {
            "type": "bundle",
            "id": f"bundle--{bundle_id}",
            "objects": [
                # Missing required fields
                {
                    "type": "attack-pattern",
                    "id": f"attack-pattern--{object_id}",
                    # Missing created, modified, name, etc.
                }
            ],
        }

        # Create directory structure with invalid bundles
        custom_bundles = {"old": invalid_bundle, "new": invalid_bundle}
        old_dir, new_dir = setup_test_directories(tmp_path, None, ["enterprise-attack"], custom_bundles=custom_bundles)

        # DiffStix should handle this gracefully (not crash)
        try:
            diffstix = DiffStix(domains=["enterprise-attack"], old=old_dir, new=new_dir, verbose=False)
            # Should be able to get outputs even with problematic data
            changes = diffstix.get_changes_dict()
            assert isinstance(changes, dict), "Should return dict even with invalid data"
        except Exception as e:
            # If it does raise an exception, it should be informative
            assert len(str(e)) > 10, f"Error message should be descriptive: {e}"
