"""Tests for the main CLI entry point function."""

import json

import pytest

from mitreattack.diffStix.changelog_helper import get_new_changelog_md


class TestMainFunction:
    """Tests for the main CLI entry point."""

    def test_main_no_arguments(self, minimal_stix_bundles, tmp_path, setup_test_directories, assert_markdown_structure):
        """Test main function execution with default CLI arguments."""
        # Set up real directories with test data
        old_dir, new_dir = setup_test_directories(
            tmp_path, minimal_stix_bundles, ["enterprise-attack", "mobile-attack", "ics-attack"]
        )

        # Test real changelog generation with default arguments
        result = get_new_changelog_md(
            domains=["enterprise-attack", "mobile-attack", "ics-attack"],
            old=old_dir,
            new=new_dir,
            verbose=False,
        )

        # Use shared assertion helper
        assert_markdown_structure(result)

    def test_main_basic_execution(self, minimal_stix_bundles, tmp_path, setup_test_directories):
        """Test basic main function execution with single domain."""
        # Set up real directories with test data
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, ["enterprise-attack"])

        # Test real changelog generation with single domain
        result = get_new_changelog_md(domains=["enterprise-attack"], old=old_dir, new=new_dir, verbose=False)

        # Verify we get real markdown content
        assert isinstance(result, str)
        assert len(result) > 0
        assert "Enterprise" in result  # Should contain enterprise domain content

    def test_main_with_all_options(
        self,
        minimal_stix_bundles,
        tmp_path,
        setup_test_directories,
        create_output_paths,
        create_layer_paths,
        validate_comprehensive_outputs,
    ):
        """Test main function with comprehensive CLI options."""
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]

        # Set up real directories with test data
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, domains)

        # Use shared helper to create output file paths
        file_paths = create_output_paths(tmp_path, prefix="test")
        layer_files = create_layer_paths(tmp_path, domains, prefix="layer")

        # Test real changelog generation with comprehensive options
        result = get_new_changelog_md(
            domains=domains,
            old=old_dir,
            new=new_dir,
            layers=layer_files,
            unchanged=True,
            show_key=True,
            site_prefix="https://example.com",
            include_contributors=False,
            markdown_file=file_paths["markdown"],
            html_file=file_paths["html"],
            html_file_detailed=file_paths["html_detailed"],
            json_file=file_paths["json"],
            verbose=False,
        )

        # Use shared comprehensive validation
        validate_comprehensive_outputs(result, file_paths, domains, layer_files)

    def test_main_handles_get_changelog_exception(self, tmp_path, setup_test_directories):
        """Test main function handles real exceptions from invalid data."""
        # Set up directories with invalid JSON to trigger real error
        invalid_json = "invalid json {["  # Malformed JSON
        custom_bundles = {"old": invalid_json, "new": invalid_json}
        old_dir, new_dir = setup_test_directories(tmp_path, None, ["enterprise-attack"], custom_bundles=custom_bundles)

        # Test real exception handling with invalid JSON
        with pytest.raises(json.JSONDecodeError):
            get_new_changelog_md(domains=["enterprise-attack"], old=old_dir, new=new_dir, verbose=False)

    def test_main_handles_argument_parsing_exception(self):
        """Test main function handles real argument parsing exceptions."""
        # For this test, we'll test actual argument validation
        # by calling get_new_changelog_md with invalid parameters
        with pytest.raises(ValueError):
            # Pass string instead of list for domains, and no directories
            get_new_changelog_md(domains="invalid_type")  # type: ignore

    def test_main_invalid_file_paths(self):
        """Test main function with real invalid file paths."""
        # Test with nonexistent directories - this should raise real FileNotFoundError
        with pytest.raises((FileNotFoundError, OSError)):
            get_new_changelog_md(
                domains=["enterprise-attack"], old="/nonexistent/old_dir", new="/nonexistent/new_dir", verbose=False
            )

    def test_main_return_behavior(self, minimal_stix_bundles, tmp_path, setup_test_directories):
        """Test main function return behavior with real execution."""
        # Set up real directories with test data
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, ["enterprise-attack"])

        # Test real function return behavior
        result = get_new_changelog_md(domains=["enterprise-attack"], old=old_dir, new=new_dir, verbose=False)

        # Verify function returns markdown string, not None
        assert isinstance(result, str)
        assert len(result) > 0
