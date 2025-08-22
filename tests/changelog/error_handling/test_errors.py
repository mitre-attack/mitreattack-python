"""Tests for error handling scenarios."""

import json

import pytest

from mitreattack.diffStix.changelog_helper import (
    DiffStix,
    get_attack_object_version,
)


class TestErrorHandling:
    """Tests for error handling scenarios."""

    def test_diffstix_invalid_path(self):
        """Test DiffStix with invalid file paths."""
        with pytest.raises((FileNotFoundError, OSError)):
            DiffStix(domains=["enterprise-attack"], old="/nonexistent/path", new="/another/nonexistent/path")

    def test_malformed_json_handling(self, sample_technique_object):
        """Test handling of malformed JSON in DeepDiff data."""
        technique = sample_technique_object.copy()
        technique["detailed_diff"] = "invalid json {[ "
        with pytest.raises(json.JSONDecodeError):
            json.loads(technique["detailed_diff"])

    def test_get_attack_object_version_malformed(self):
        """Test version parsing with malformed version string."""
        stix_obj = {"x_mitre_version": "invalid"}
        with pytest.raises(ValueError):
            get_attack_object_version(stix_obj)
