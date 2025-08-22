"""Tests for the high-level API functions and parameter validation."""

import pytest

from mitreattack.diffStix.changelog_helper import get_new_changelog_md


class TestCliApi:
    """Tests for the high-level API functions and parameter validation."""

    def test_get_new_changelog_md_basic(
        self, minimal_stix_bundles, tmp_path, setup_test_directories, assert_markdown_structure
    ):
        """Test basic changelog generation with real DiffStix."""
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, ["enterprise-attack"])

        result = get_new_changelog_md(domains=["enterprise-attack"], old=old_dir, new=new_dir, verbose=False)

        assert_markdown_structure(result)

    def test_get_new_changelog_md_layers_default(
        self, minimal_stix_bundles, tmp_path, setup_test_directories, assert_markdown_structure
    ):
        """Test layer generation with default empty list."""
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, ["enterprise-attack"])

        result = get_new_changelog_md(
            domains=["enterprise-attack"],
            layers=[],  # Empty list should trigger default layer generation
            old=old_dir,
            new=new_dir,
            verbose=False,
        )

        assert_markdown_structure(result)

    def test_get_new_changelog_md_with_options(
        self, minimal_stix_bundles, tmp_path, setup_test_directories, assert_markdown_structure
    ):
        """Test get_new_changelog_md with various options."""
        old_dir, new_dir = setup_test_directories(
            tmp_path, minimal_stix_bundles, ["enterprise-attack", "mobile-attack"]
        )

        site_prefix = "https://example.com"

        result = get_new_changelog_md(
            domains=["enterprise-attack", "mobile-attack"],
            old=old_dir,
            new=new_dir,
            show_key=True,  # Should add key to markdown
            site_prefix=site_prefix,  # Should affect link generation
            unchanged=True,  # Should include unchanged objects
            verbose=False,  # Keep false for test speed
            include_contributors=False,
        )

        assert_markdown_structure(result)
        assert "## Key" in result  # show_key=True should add key section
        assert "Enterprise" in result  # Should have enterprise domain
        assert "Mobile" in result  # Should have mobile domain
        assert site_prefix in result  # Should have site prefix in links

    def test_get_new_changelog_md_markdown_file_only(
        self, minimal_stix_bundles, tmp_path, setup_test_directories, validate_markdown_file
    ):
        """Test generating only markdown file with real content."""
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, ["enterprise-attack"])

        markdown_file = tmp_path / "test_markdown.md"

        result = get_new_changelog_md(
            domains=["enterprise-attack"],
            markdown_file=str(markdown_file),
            old=old_dir,
            new=new_dir,
            verbose=False,
        )

        # Use shared validation utility
        file_content = validate_markdown_file(markdown_file)
        assert result == file_content  # Return value should match file content

    def test_get_new_changelog_md_json_file_only(
        self, minimal_stix_bundles, tmp_path, setup_test_directories, validate_json_file, assert_markdown_structure
    ):
        """Test generating only JSON file with real content."""
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, ["enterprise-attack"])

        json_file = tmp_path / "test_changes.json"

        result = get_new_changelog_md(
            domains=["enterprise-attack"], json_file=str(json_file), old=old_dir, new=new_dir, verbose=False
        )

        # Use shared validation utilities
        validate_json_file(json_file, ["enterprise-attack"])
        assert_markdown_structure(result)  # Should still return markdown

    def test_get_new_changelog_md_layer_files_only(
        self,
        minimal_stix_bundles,
        tmp_path,
        setup_test_directories,
        create_layer_paths,
        validate_layer_file,
        assert_markdown_structure,
    ):
        """Test generating only layer files with real content."""
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, domains)

        # Use shared helper to create layer file paths
        layer_files = create_layer_paths(tmp_path, domains, prefix="test")

        result = get_new_changelog_md(
            domains=domains,
            layers=layer_files,
            old=old_dir,
            new=new_dir,
            verbose=False,
        )

        # Use shared validation utilities
        for i, domain in enumerate(domains):
            validate_layer_file(layer_files[i], domain)
        assert_markdown_structure(result)  # Should still return markdown

    def test_get_new_changelog_md_single_domain(
        self, minimal_stix_bundles, tmp_path, setup_test_directories, assert_markdown_structure
    ):
        """Test get_new_changelog_md with single domain."""
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, ["enterprise-attack"])

        result = get_new_changelog_md(domains=["enterprise-attack"], old=old_dir, new=new_dir, verbose=False)

        assert_markdown_structure(result)
        assert "Enterprise" in result  # Should only have enterprise section
        assert "Mobile" not in result  # Should not have mobile section

    def test_get_new_changelog_md_all_domains(
        self, minimal_stix_bundles, tmp_path, setup_test_directories, assert_markdown_structure
    ):
        """Test get_new_changelog_md with all domains."""
        old_dir, new_dir = setup_test_directories(
            tmp_path, minimal_stix_bundles, ["enterprise-attack", "mobile-attack", "ics-attack"]
        )

        result = get_new_changelog_md(
            domains=["enterprise-attack", "mobile-attack", "ics-attack"],
            old=old_dir,
            new=new_dir,
            verbose=False,
        )

        assert_markdown_structure(result)
        assert "Enterprise" in result
        assert "Mobile" in result
        assert "ICS" in result

    def test_get_new_changelog_md_error_handling(self):
        """Test error handling in get_new_changelog_md with real error conditions."""
        # Test with nonexistent directories
        with pytest.raises((FileNotFoundError, OSError)):
            get_new_changelog_md(
                domains=["enterprise-attack"], old="/nonexistent/old_dir", new="/nonexistent/new_dir", verbose=False
            )

    def test_get_new_changelog_md_file_write_error(self, minimal_stix_bundles, tmp_path, setup_test_directories):
        """Test handling of file write errors with real file operations."""
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, ["enterprise-attack"])

        # Create readonly directory
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)
        markdown_file = readonly_dir / "test.md"

        with pytest.raises(PermissionError):
            get_new_changelog_md(
                domains=["enterprise-attack"],
                markdown_file=str(markdown_file),
                old=old_dir,
                new=new_dir,
                verbose=False,
            )
