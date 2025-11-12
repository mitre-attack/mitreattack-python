"""Tests for DiffStix class methods that need real functionality testing."""

import pytest

from mitreattack.diffStix.core.diff_stix import DiffStix


class TestDiffStixMethods:
    """Tests for DiffStix methods using real functionality."""

    def test_get_groupings_real_functionality(
        self, lightweight_diffstix, sample_technique_object, sample_subtechnique_object
    ):
        """Test real groupings generation with parent-child relationships."""
        # Create test objects with parent-child relationship
        parent_technique = sample_technique_object.copy()
        child_subtechnique = sample_subtechnique_object.copy()

        # Create list of test objects
        test_objects = [parent_technique, child_subtechnique]

        # Test real groupings generation
        result = lightweight_diffstix.hierarchy_builder.get_groupings(
            object_type="techniques", stix_objects=test_objects, section="additions", domain="enterprise-attack"
        )

        # Verify real groupings structure
        assert isinstance(result, list)
        assert len(result) > 0

        # Verify grouping structure
        for grouping in result:
            assert isinstance(grouping, dict)
            assert "parent" in grouping
            assert "parentInSection" in grouping
            assert "children" in grouping
            assert isinstance(grouping["children"], list)

    def test_update_contributors_real_functionality(self, lightweight_diffstix, mock_stix_object_factory):
        """Test real contributor tracking."""
        # Create objects with contributors
        old_object = mock_stix_object_factory(name="Old Object", contributors=["John Doe", "Jane Smith"])

        new_object = mock_stix_object_factory(
            name="New Object", contributors=["John Doe", "Jane Smith", "New Contributor"]
        )

        # Clear existing contributors
        lightweight_diffstix.release_contributors = {}

        # Test real contributor update
        lightweight_diffstix.contributor_tracker.update_contributors(old_object, new_object)

        # Verify only new contributors were tracked
        assert "New Contributor" in lightweight_diffstix.release_contributors
        assert lightweight_diffstix.release_contributors["New Contributor"] == 1
        assert "John Doe" not in lightweight_diffstix.release_contributors  # Existing contributor
        assert "Jane Smith" not in lightweight_diffstix.release_contributors  # Existing contributor

    def test_update_contributors_new_object_no_old(self, lightweight_diffstix, mock_stix_object_factory):
        """Test contributor tracking for completely new objects."""
        new_object = mock_stix_object_factory(name="Brand New Object", contributors=["Author One", "Author Two"])

        # Clear existing contributors
        lightweight_diffstix.release_contributors = {}

        # Test with no old object (new addition)
        lightweight_diffstix.contributor_tracker.update_contributors(None, new_object)

        # Verify all contributors were tracked
        assert "Author One" in lightweight_diffstix.release_contributors
        assert "Author Two" in lightweight_diffstix.release_contributors
        assert lightweight_diffstix.release_contributors["Author One"] == 1
        assert lightweight_diffstix.release_contributors["Author Two"] == 1

    def test_get_parent_stix_object_real_functionality(
        self, lightweight_diffstix, mock_stix_object_factory, mock_relationship_factory
    ):
        """Test real parent object resolution."""
        # Create parent technique and subtechnique
        parent_technique = mock_stix_object_factory(
            name="Parent Technique", attack_id="T1234", stix_id="attack-pattern--parent-id"
        )

        subtechnique = mock_stix_object_factory(
            name="Child Subtechnique", attack_id="T1234.001", is_subtechnique=True, stix_id="attack-pattern--child-id"
        )

        # Create subtechnique relationship
        relationship = mock_relationship_factory(
            source_ref=subtechnique["id"], target_ref=parent_technique["id"], relationship_type="subtechnique-of"
        )

        # Set up DiffStix data structures
        lightweight_diffstix.data["new"]["enterprise-attack"]["attack_objects"]["techniques"] = {
            parent_technique["id"]: parent_technique
        }
        lightweight_diffstix.data["new"]["enterprise-attack"]["relationships"]["subtechniques"] = {
            relationship["id"]: relationship
        }

        # Test real parent resolution
        result = lightweight_diffstix.hierarchy_builder.get_parent_stix_object(subtechnique, "new", "enterprise-attack")

        # Verify correct parent was found
        assert result == parent_technique
        assert result["name"] == "Parent Technique"
        assert result["id"] == "attack-pattern--parent-id"

    def test_get_parent_stix_object_no_parent(self, lightweight_diffstix, sample_technique_object):
        """Test parent resolution for objects without parents."""
        # Test with regular technique (not a subtechnique)
        result = lightweight_diffstix.hierarchy_builder.get_parent_stix_object(sample_technique_object, "new", "enterprise-attack")

        # Should return empty dict for objects without parents
        assert result == {}

    def test_placard_different_sections(self, lightweight_diffstix, sample_technique_object, mock_stix_object_factory):
        """Test real placard generation for different section types."""
        # Test additions section
        additions_result = lightweight_diffstix.markdown_generator.placard(sample_technique_object, "additions", "enterprise-attack")
        assert isinstance(additions_result, str)
        assert len(additions_result) > 0
        assert "T1234" in additions_result

        # Test deletions section
        deletions_result = lightweight_diffstix.markdown_generator.placard(sample_technique_object, "deletions", "enterprise-attack")
        assert isinstance(deletions_result, str)
        # Deletions only show name, no link
        assert sample_technique_object["name"] in deletions_result

    def test_placard_with_revocations(self, lightweight_diffstix, mock_stix_object_factory):
        """Test real placard generation for revoked objects."""
        # Create revoking object
        revoking_object = mock_stix_object_factory(name="Replacement Technique", attack_id="T9999")

        # Create revoked object
        revoked_object = mock_stix_object_factory(name="Revoked Technique", attack_id="T1111", revoked=True)
        revoked_object["revoked_by"] = revoking_object

        # Test revocation placard
        result = lightweight_diffstix.markdown_generator.placard(revoked_object, "revocations", "enterprise-attack")

        # Verify revocation information is included
        assert isinstance(result, str)
        assert "Revoked Technique" in result
        assert "revoked by" in result
        assert "Replacement Technique" in result

    def test_get_layers_dict_real_generation(self, lightweight_diffstix):
        """Test real ATT&CK Navigator layer generation."""
        # Test real layer dictionary generation
        result = lightweight_diffstix.get_layers_dict()

        # Verify structure
        assert isinstance(result, dict)
        assert "enterprise-attack" in result

        # Verify layer structure for enterprise domain
        enterprise_layer = result["enterprise-attack"]
        assert isinstance(enterprise_layer, dict)

        # Verify required layer fields
        required_fields = ["name", "description", "domain", "versions", "techniques"]
        for field in required_fields:
            assert field in enterprise_layer

        # Verify versions structure
        versions = enterprise_layer["versions"]
        assert "layer" in versions
        assert "navigator" in versions
        assert "attack" in versions

        # Verify techniques is a list
        assert isinstance(enterprise_layer["techniques"], list)

        # Verify domain matches
        assert enterprise_layer["domain"] == "enterprise-attack"

    def test_get_changes_dict_real_structure(self, lightweight_diffstix):
        """Test real changes dictionary generation."""
        # Test real changes dict generation
        result = lightweight_diffstix.get_changes_dict()

        # Verify overall structure
        assert isinstance(result, dict)
        assert "enterprise-attack" in result
        assert "new-contributors" in result

        # Verify domain structure
        domain_changes = result["enterprise-attack"]
        assert isinstance(domain_changes, dict)

        # Verify object types are present
        expected_types = [
            "techniques",
            "software",
            "groups",
            "campaigns",
            "assets",
            "mitigations",
            "datasources",
            "datacomponents",
            "detectionstrategies",
            "analytics",
        ]
        for obj_type in expected_types:
            assert obj_type in domain_changes

            # Verify change categories
            change_categories = domain_changes[obj_type]
            assert isinstance(change_categories, dict)

            expected_categories = [
                "additions",
                "major_version_changes",
                "minor_version_changes",
                "other_version_changes",
                "patches",
                "revocations",
                "deprecations",
                "deletions",
            ]
            for category in expected_categories:
                assert category in change_categories
                assert isinstance(change_categories[category], list)

        # Verify contributors list
        assert isinstance(result["new-contributors"], list)

    def test_load_domain_file_not_found(self, tmp_path, setup_test_directories):
        """Test DiffStix behavior with missing domain files."""
        # Create empty directories without files
        old_dir, new_dir = setup_test_directories(tmp_path, None, ["enterprise-attack"], write_files=False)

        # Try to create DiffStix with missing files - should raise error
        with pytest.raises((FileNotFoundError, OSError)):
            DiffStix(domains=["enterprise-attack"], old=old_dir, new=new_dir, verbose=False)

    def test_diffstix_initialization_with_options(self, minimal_stix_bundles, tmp_path, setup_test_directories):
        """Test DiffStix initialization with various options."""
        # Set up directories
        old_dir, new_dir = setup_test_directories(tmp_path, minimal_stix_bundles, ["enterprise-attack"])

        # Test initialization with various options
        diffstix = DiffStix(
            domains=["enterprise-attack"],
            old=old_dir,
            new=new_dir,
            unchanged=True,  # Include unchanged objects
            show_key=True,  # Show key in output
            site_prefix="https://attack.mitre.org",
            verbose=False,
            include_contributors=True,
        )

        # Verify options were set correctly
        assert diffstix.unchanged is True
        assert diffstix.show_key is True
        assert diffstix.site_prefix == "https://attack.mitre.org"
        assert diffstix.include_contributors is True
        assert diffstix.domains == ["enterprise-attack"]

        # Verify data was loaded
        assert "enterprise-attack" in diffstix.data["old"]
        assert "enterprise-attack" in diffstix.data["new"]
