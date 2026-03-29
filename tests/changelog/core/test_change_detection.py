"""Tests for change detection and grouping logic."""

from mitreattack.diffStix.changelog_helper import (
    cleanup_values,
    is_patch_change,
)


class TestChangeDetection:
    """Tests for change detection and grouping logic."""

    def test_is_patch_change_basic(self, sample_technique_object):
        """Test basic patch change detection."""
        old_obj = sample_technique_object.copy()
        new_obj = sample_technique_object.copy()
        old_obj["modified"] = "2023-01-01T00:00:00.000Z"
        new_obj["modified"] = "2023-01-02T00:00:00.000Z"
        assert is_patch_change(old_obj, new_obj) is True

    def test_cleanup_values_grouping(self):
        """Test cleanup values grouping functionality."""
        test_groupings = [
            {
                "name": "Test1",
                "parent": {"name": "Parent1", "id": "T1001"},
                "children": [{"name": "Child1", "id": "T1001.001"}],
            },
            {
                "name": "Test2",
                "parent": None,
                "children": [{"name": "Child2", "id": "T1002.001"}],
            },
        ]
        result = cleanup_values(test_groupings)
        assert isinstance(result, list)
        assert len(result) == 3
        assert result[0]["name"] == "Parent1"
        assert result[1]["name"] == "Child1"
        assert result[2]["name"] == "Child2"
