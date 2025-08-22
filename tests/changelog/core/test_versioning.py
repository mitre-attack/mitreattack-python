"""Tests for versioning functionality."""

import pytest

from mitreattack.diffStix.changelog_helper import (
    AttackObjectVersion,
    get_attack_object_version,
    is_major_version_change,
    is_minor_version_change,
    is_other_version_change,
    version_increment_is_valid,
)


class TestVersioning:
    """Tests for versioning functionality."""

    def test_creation_and_representation(self):
        """Test AttackObjectVersion creation and string representation."""
        version = AttackObjectVersion(major=1, minor=2)
        assert version.major == 1
        assert version.minor == 2
        assert str(version) == "1.2"

    def test_creation_with_different_values(self):
        """Test creating versions with various values."""
        version_zero = AttackObjectVersion(major=0, minor=0)
        assert str(version_zero) == "0.0"

        version_large = AttackObjectVersion(major=10, minor=25)
        assert str(version_large) == "10.25"

    def test_normal_version_extraction(self):
        """Test getting version from normal STIX object."""
        stix_obj = {"x_mitre_version": "2.1"}
        version = get_attack_object_version(stix_obj)
        assert version.major == 2
        assert version.minor == 1

    def test_missing_version_defaults_to_zero(self):
        """Test getting version from STIX object without version (defaults to 0.0)."""
        stix_obj = {"name": "Test Object"}
        version = get_attack_object_version(stix_obj)
        assert version.major == 0
        assert version.minor == 0

    def test_malformed_version_raises_error(self):
        """Test version parsing with malformed version string."""
        stix_obj = {"x_mitre_version": "invalid"}

        with pytest.raises(ValueError):
            get_attack_object_version(stix_obj)

    @pytest.mark.parametrize(
        "version_string,expected_major,expected_minor",
        [
            ("1.0", 1, 0),
            ("2.5", 2, 5),
            ("0.1", 0, 1),
            ("10.15", 10, 15),
        ],
    )
    def test_various_valid_version_formats(self, version_string, expected_major, expected_minor):
        """Test parsing various valid version string formats."""
        stix_obj = {"x_mitre_version": version_string}
        version = get_attack_object_version(stix_obj)
        assert version.major == expected_major
        assert version.minor == expected_minor

    @pytest.mark.parametrize(
        "old_version,new_version,expected_major,expected_minor,expected_other,description",
        [
            (AttackObjectVersion(1, 0), AttackObjectVersion(2, 0), True, False, False, "Major increment"),
            (AttackObjectVersion(1, 0), AttackObjectVersion(1, 1), False, True, False, "Minor increment"),
            (AttackObjectVersion(1, 0), AttackObjectVersion(1, 0), False, False, False, "Same version"),
            (AttackObjectVersion(1, 0), AttackObjectVersion(1, 3), False, False, True, "Skip minor versions"),
            (AttackObjectVersion(2, 0), AttackObjectVersion(1, 0), False, False, True, "Version downgrade"),
            (AttackObjectVersion(1, 0), AttackObjectVersion(3, 0), False, False, True, "Skip major versions"),
        ],
    )
    def test_comprehensive_version_comparison(
        self, old_version, new_version, expected_major, expected_minor, expected_other, description
    ):
        """Test all version comparison functions with comprehensive scenarios."""
        assert is_major_version_change(old_version, new_version) == expected_major, (
            f"Major check failed for {description}"
        )
        assert is_minor_version_change(old_version, new_version) == expected_minor, (
            f"Minor check failed for {description}"
        )
        assert is_other_version_change(old_version, new_version) == expected_other, (
            f"Other check failed for {description}"
        )

    def test_additions_must_be_version_one_zero(self):
        """Test version validation for new additions (must be 1.0)."""
        new_version = AttackObjectVersion(major=1, minor=0)
        assert version_increment_is_valid(None, new_version, "additions") is True

        invalid_version = AttackObjectVersion(major=2, minor=0)
        assert version_increment_is_valid(None, invalid_version, "additions") is False

    def test_revocations_always_valid(self):
        """Test version validation for revocations (always valid)."""
        old_version = AttackObjectVersion(major=1, minor=0)
        new_version = AttackObjectVersion(major=5, minor=7)
        assert version_increment_is_valid(old_version, new_version, "revocations") is True
