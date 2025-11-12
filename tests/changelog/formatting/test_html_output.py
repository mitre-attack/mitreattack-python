"""Tests for HTML output generation and validation."""

import json

from mitreattack.diffStix.formatters.html_output import markdown_to_html, write_detailed_html


class TestHtmlOutput:
    """Tests for HTML output generation and validation."""

    def test_markdown_to_html_basic(self, tmp_path, lightweight_diffstix):
        """Test basic markdown to HTML conversion."""
        outfile = tmp_path / "test.html"
        content = "# Test Header\n\nThis is **bold** text."
        old_version = "16.1"
        new_version = "17.0"

        # Set version data for testing version display
        lightweight_diffstix.data["old"]["enterprise-attack"]["attack_release_version"] = old_version
        lightweight_diffstix.data["new"]["enterprise-attack"]["attack_release_version"] = new_version

        markdown_to_html(str(outfile), content, lightweight_diffstix)
        assert outfile.exists()
        html_content = outfile.read_text(encoding="utf-8")
        assert f"ATT&CK Changes Between v{old_version} and v{new_version}" in html_content
        assert "<strong>bold</strong>" in html_content
        assert "charset='utf-8'" in html_content
        # it might be nice to add this back in, but when using the python markdown TOC extension,
        # it modifies the <h1> and <h2> tags, giving them additional attributes, like id (and maybe style?)
        # https://python-markdown.github.io/extensions/toc/
        # assert "<h1>Test Header</h1>" in html_content

    def test_write_detailed_html_basic(
        self, tmp_path, lightweight_diffstix, sample_deepdiff_data, minimal_stix_bundles
    ):
        """Test basic detailed HTML generation."""
        html_file = tmp_path / "detailed.html"
        old_version = "16.1"
        new_version = "17.0"

        # Set up version data
        lightweight_diffstix.data["old"]["enterprise-attack"]["attack_release_version"] = old_version
        lightweight_diffstix.data["new"]["enterprise-attack"]["attack_release_version"] = new_version

        # Add some test data to generate meaningful HTML output
        test_technique = (
            minimal_stix_bundles["expected_changes"]["additions"][0]
            if minimal_stix_bundles["expected_changes"]["additions"]
            else {
                "name": "Test Addition Technique",
                "external_references": [{"external_id": "T1001"}],
                "detailed_diff": json.dumps(sample_deepdiff_data),
            }
        )
        test_technique["detailed_diff"] = json.dumps(sample_deepdiff_data)

        # Add test changes to the DiffStix data structure
        lightweight_diffstix.data["changes"] = {
            "techniques": {
                "enterprise-attack": {
                    "additions": [test_technique],
                    "major_version_changes": [],
                    "minor_version_changes": [],
                    "other_version_changes": [],
                    "patches": [],
                    "revocations": [],
                    "deprecations": [],
                    "deletions": [],
                    "unchanged": [],
                }
            }
        }

        write_detailed_html(str(html_file), lightweight_diffstix)
        assert html_file.exists()
        html_content = html_file.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html_content
        assert f"ATT&CK Changes Between v{old_version} and v{new_version}" in html_content
        assert "<h2>Techniques</h2>" in html_content or "<h1>" in html_content  # Should have some header structure

    def test_html_document_structure(self):
        """Test basic HTML document structure."""
        title = "ATT&CK Changes"
        content = "<h1>Test Content</h1>"
        html_doc = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>{title}</title>
</head>
<body>
    {content}
</body>
</html>"""
        assert "<!DOCTYPE html>" in html_doc
        assert "<meta charset='utf-8'>" in html_doc
        assert f"<title>{title}</title>" in html_doc
        assert content in html_doc
