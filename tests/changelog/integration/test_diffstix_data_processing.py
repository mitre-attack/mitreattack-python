"""Integration tests for DiffStix data processing methods."""


class TestDiffStixDataProcessing:
    """Integration tests for DiffStix data processing methods."""

    def test_get_parent_stix_object(self, mock_diffstix, sample_technique_object, sample_subtechnique_object):
        """Test finding parent STIX objects for subtechniques."""
        # Setup mock data with parent-child relationship
        mock_diffstix.data["old"]["enterprise-attack"]["attack_objects"]["techniques"] = {
            "T1234": sample_technique_object,
            "T1234.001": sample_subtechnique_object,
        }

        # Mock the hierarchy_builder method
        def mock_get_parent(subtechnique, _version, _domain):
            if subtechnique.get("external_references", [{}])[0].get("external_id") == "T1234.001":
                return sample_technique_object
            return None

        mock_diffstix.hierarchy_builder.get_parent_stix_object = mock_get_parent

        # Test finding parent
        parent = mock_diffstix.hierarchy_builder.get_parent_stix_object(sample_subtechnique_object, "old", "enterprise-attack")
        assert parent == sample_technique_object

    def test_find_technique_mitigation_changes(self, mock_diffstix, mock_relationship_factory):
        """Test finding technique-mitigation relationship changes."""
        # Create mock relationships
        old_relationship = mock_relationship_factory(
            source_ref="course-of-action--12345", target_ref="attack-pattern--67890", relationship_type="mitigates"
        )

        # Setup mock data
        mock_diffstix.data["old"]["enterprise-attack"]["relationships"]["mitigations"] = {"T1234": [old_relationship]}
        mock_diffstix.data["new"]["enterprise-attack"]["relationships"]["mitigations"] = {}

        # Mock the method
        def mock_find_changes():
            return {"T1234": {"removed": [old_relationship], "added": []}}

        mock_diffstix.find_technique_mitigation_changes = mock_find_changes

        changes = mock_diffstix.find_technique_mitigation_changes()
        assert "T1234" in changes
        assert len(changes["T1234"]["removed"]) == 1

    def test_find_technique_detection_changes(self, mock_diffstix, mock_relationship_factory):
        """Test finding technique-detection relationship changes."""
        # Create mock relationships
        detection_relationship = mock_relationship_factory(
            source_ref="x-mitre-data-component--12345", target_ref="attack-pattern--67890", relationship_type="detects"
        )

        # Setup mock data
        mock_diffstix.data["new"]["enterprise-attack"]["relationships"]["detections"] = {
            "T1234": [detection_relationship]
        }
        mock_diffstix.data["old"]["enterprise-attack"]["relationships"]["detections"] = {}

        # Mock the method
        def mock_find_changes():
            return {"T1234": {"added": [detection_relationship], "removed": []}}

        mock_diffstix.find_technique_detection_changes = mock_find_changes

        changes = mock_diffstix.find_technique_detection_changes()
        assert "T1234" in changes
        assert len(changes["T1234"]["added"]) == 1
