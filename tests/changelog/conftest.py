"""Shared fixtures for changelog helper tests.

This file contains fixtures specific to changelog_helper.py testing functionality.
Shared fixtures (STIX data, layers, etc.) are imported from the parent conftest.py.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

from mitreattack.diffStix.changelog_helper import DiffStix

# Import test utilities
from tests.changelog.test_utils import (
    assert_basic_markdown_structure,
    assert_diffstix_data_structure_valid,
    assert_json_structure_valid,
    assert_layer_structure_valid,
    create_layer_file_paths,
    create_test_output_file_paths,
    validate_comprehensive_output_generation,
    validate_json_file_content,
    validate_layer_file_content,
    validate_markdown_file_content,
    validate_output_format_consistency,
)

# Import shared fixtures from parent conftest.py
# These fixtures are used by pytest's fixture discovery system even though they appear unused
from tests.conftest import (
    # Core data infrastructure (used by multiple test suites)
    _download_attack_stix_data,
    attack_stix_dir,
    layer_v3_all,
    layer_v43,
    memstore_enterprise_latest,
    memstore_ics_latest,
    memstore_mobile_latest,
    mitre_attack_data_enterprise,
    mitre_attack_data_ics,
    mitre_attack_data_mobile,
    stix_file_enterprise_latest,
    stix_file_ics_latest,
    stix_file_mobile_latest,
)

# Export imported fixtures for pytest discovery
__all__ = [
    "attack_stix_dir",
    "stix_file_enterprise_latest",
    "stix_file_mobile_latest",
    "stix_file_ics_latest",
    "memstore_enterprise_latest",
    "memstore_mobile_latest",
    "memstore_ics_latest",
    "mitre_attack_data_enterprise",
    "mitre_attack_data_mobile",
    "mitre_attack_data_ics",
    "layer_v3_all",
    "layer_v43",
    "mitre_identity",
    "mitre_marking_definition",
    "mock_stix_object_factory",
    "mock_relationship_factory",
    "sample_technique_object",
    "sample_subtechnique_object",
    "sample_malware_object",
    "sample_tool_object",
    "sample_group_object",
    "sample_mitigation_object",
    "sample_campaign_object",
    "sample_data_source_object",
    "sample_data_component_object",
    "sample_asset_object",
    "sample_group_uses_malware_relationship",
    "sample_group_uses_tool_relationship",
    "sample_group_uses_technique_relationship",
    "sample_malware_uses_technique_relationship",
    "sample_tool_uses_technique_relationship",
    "sample_campaign_uses_malware_relationship",
    "sample_campaign_uses_tool_relationship",
    "sample_campaign_uses_technique_relationship",
    "sample_campaign_attributed_to_group_relationship",
    "sample_mitigation_mitigates_technique_relationship",
    "sample_subtechnique_of_technique_relationship",
    "sample_data_component_detects_technique_relationship",
    "sample_technique_targets_asset_relationship",
    "sample_revoked_by_relationship",
    "diffstix_with_version_scenarios",
    "empty_changes_diffstix",
    "large_dataset_diffstix",
    "setup_test_directories",
    # Enhanced assertion helper fixtures
    "assert_markdown_structure",
    "assert_json_structure",
    "assert_layer_structure",
    "assert_diffstix_structure",
    "validate_comprehensive_outputs",
    "validate_format_consistency",
    # File path creation helper fixtures
    "create_output_paths",
    "create_layer_paths",
    # File validation helper fixtures
    "validate_markdown_file",
    "validate_json_file",
    "validate_layer_file",
    # CLI argument testing helper fixtures
    "setup_monkeypatch_args",
]


# ========================================
# Standard ATT&CK STIX Object Constants
# ========================================

# Standard MITRE identity object used across all ATT&CK objects
MITRE_IDENTITY_ID = "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
MITRE_IDENTITY = {
    "type": "identity",
    "id": MITRE_IDENTITY_ID,
    "name": "The MITRE Corporation",
    "description": "",
    "created": "2017-06-01T00:00:00.000Z",
    "modified": "2025-03-19T15:00:40.855Z",
    "identity_class": "organization",
    "object_marking_refs": ["marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"],
    "x_mitre_attack_spec_version": "3.2.0",
}

# Standard marking definition (copyright year should be updated annually)
MITRE_MARKING_DEFINITION_ID = "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
MITRE_MARKING_DEFINITION = {
    "type": "marking-definition",
    "id": MITRE_MARKING_DEFINITION_ID,
    "definition": {
        "statement": "Copyright 2015-2025, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation."
    },
    "created": "2017-06-01T00:00:00.000Z",
    "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "definition_type": "statement",
}

# Valid ATT&CK relationship types and their allowed source/target combinations
ATTACK_RELATIONSHIP_RULES = {
    "uses": [
        ("intrusion-set", "malware"),
        ("intrusion-set", "tool"),
        ("intrusion-set", "attack-pattern"),
        ("malware", "attack-pattern"),
        ("tool", "attack-pattern"),
        ("campaign", "malware"),
        ("campaign", "tool"),
        ("campaign", "attack-pattern"),
    ],
    "attributed-to": [("campaign", "intrusion-set")],
    "mitigates": [("course-of-action", "attack-pattern")],
    "subtechnique-of": [("attack-pattern", "attack-pattern")],
    "detects": [("x-mitre-data-component", "attack-pattern")],
    "targets": [("attack-pattern", "x-mitre-asset")],
    "revoked-by": [
        ("any", "any")  # Any type can be revoked by same type
    ],
}


# ========================================
# Standard ATT&CK STIX Object Fixtures
# ========================================


@pytest.fixture
def mitre_identity():
    """Return the standard MITRE identity object used across all ATT&CK objects."""
    return MITRE_IDENTITY.copy()


@pytest.fixture
def mitre_marking_definition():
    """Return the standard ATT&CK marking definition object."""
    return MITRE_MARKING_DEFINITION.copy()


# ========================================
# Enhanced Mock Object and Relationship Factory Fixtures
# ========================================


@pytest.fixture
def mock_stix_object_factory():
    """Create accurate STIX 2.0 compliant ATT&CK objects with configurable parameters.

    This factory generates STIX objects that closely match the structure and fields
    of real ATT&CK objects from the MITRE CTI repository.
    """

    def _create_stix_object(
        stix_type="attack-pattern",
        name="Test Object",
        attack_id="T9999",
        stix_id=None,
        version="1.0",
        created=None,
        modified=None,
        revoked=False,
        deprecated=False,
        contributors=None,
        obj_type=None,
        external_refs=None,
        kill_chain_phases=None,
        is_subtechnique=None,
        platforms=None,
        domains=None,
        aliases=None,
        labels=None,
        attack_spec_version="3.2.0",
        **kwargs,
    ):
        # Generate unique ID if not provided
        if stix_id is None:
            stix_id = f"{(obj_type or stix_type)}--{uuid.uuid4()}"

        # Generate realistic timestamps
        default_created = created or datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        default_modified = modified or default_created

        # Auto-detect subtechnique if not explicitly specified
        if is_subtechnique is None and attack_id and "." in attack_id:
            is_subtechnique = True

        # Base STIX 2.0 object structure
        obj = {
            "type": obj_type or stix_type,
            "id": stix_id,
            "spec_version": "2.0",
            "created": default_created,
            "modified": default_modified,
            "created_by_ref": MITRE_IDENTITY_ID,
            "name": name,
            "description": f"Description for {name}",
            "object_marking_refs": [MITRE_MARKING_DEFINITION_ID],
            "x_mitre_attack_spec_version": attack_spec_version,
            "x_mitre_version": version,
            "x_mitre_modified_by_ref": MITRE_IDENTITY_ID,
        }

        # Add revoked/deprecated status
        if revoked:
            obj["revoked"] = True
        if deprecated:
            obj["x_mitre_deprecated"] = True

        # Add domains (default to enterprise)
        if domains is None:
            domains = ["enterprise-attack"]
        obj["x_mitre_domains"] = domains

        # Add contributors if provided
        if contributors:
            obj["x_mitre_contributors"] = contributors

        # Object type-specific fields
        effective_type = obj_type or stix_type

        if effective_type == "attack-pattern":
            _add_attack_pattern_fields(obj, attack_id, is_subtechnique, kill_chain_phases, platforms)
        elif effective_type == "intrusion-set":
            _add_intrusion_set_fields(obj, attack_id, aliases)
        elif effective_type in ["malware", "tool"]:
            _add_software_fields(obj, attack_id, effective_type, aliases, platforms, labels)
        elif effective_type == "course-of-action":
            _add_mitigation_fields(obj, attack_id)
        elif effective_type == "campaign":
            _add_campaign_fields(obj, attack_id, aliases)
        elif effective_type.startswith("x-mitre-"):
            _add_custom_mitre_fields(obj, attack_id, effective_type)

        # Add external references
        if external_refs is not None:
            obj["external_references"] = external_refs
        elif attack_id:
            obj["external_references"] = _generate_external_references(attack_id, effective_type, is_subtechnique)

        # Apply any additional custom fields
        obj.update(kwargs)

        return obj

    def _add_attack_pattern_fields(obj, attack_id, is_subtechnique, kill_chain_phases, platforms):
        """Add attack-pattern specific fields."""
        if is_subtechnique:
            obj["x_mitre_is_subtechnique"] = True

        # Default kill chain phases for techniques
        if kill_chain_phases is None:
            kill_chain_phases = [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]
        obj["kill_chain_phases"] = kill_chain_phases

        # Default platforms
        if platforms is None:
            platforms = ["Windows", "macOS", "Linux"]
        obj["x_mitre_platforms"] = platforms

        # Add typical technique fields
        obj["x_mitre_data_sources"] = ["Process: Process Creation", "Command: Command Execution"]
        obj["x_mitre_detection"] = f"Detection guidance for {obj['name']}"

    def _add_intrusion_set_fields(obj, attack_id, aliases):
        """Add intrusion-set specific fields."""
        if aliases is None:
            aliases = [obj["name"]]
        obj["aliases"] = aliases

    def _add_software_fields(obj, attack_id, software_type, aliases, platforms, labels):
        """Add malware/tool specific fields."""
        if labels is None:
            labels = [software_type]
        obj["labels"] = labels

        if aliases:
            obj["x_mitre_aliases"] = aliases

        if platforms is None:
            platforms = ["Windows"]
        obj["x_mitre_platforms"] = platforms

    def _add_mitigation_fields(obj, attack_id):
        """Add course-of-action specific fields."""
        # Mitigations don't have additional special fields beyond the base ones
        pass

    def _add_campaign_fields(obj, attack_id, aliases):
        """Add campaign specific fields."""
        if aliases:
            obj["aliases"] = aliases

    def _add_custom_mitre_fields(obj, attack_id, object_type):
        """Add fields for custom MITRE object types."""
        # These objects have varying structures - add basic fields
        if object_type == "x-mitre-tactic":
            obj["x_mitre_shortname"] = attack_id.lower() if attack_id else "test-tactic"

    def _generate_external_references(attack_id, object_type, is_subtechnique):
        """Generate appropriate external references based on object type."""
        # Determine URL path based on object type
        if object_type in ["malware", "tool"]:
            url_path = "software"
        elif object_type == "intrusion-set":
            url_path = "groups"
        elif object_type == "course-of-action":
            url_path = "mitigations"
        elif object_type == "campaign":
            url_path = "campaigns"
        else:
            url_path = "techniques"

        # Handle subtechnique URL format
        if is_subtechnique and "." in attack_id:
            base_technique, sub_id = attack_id.split(".", 1)
            url = f"https://attack.mitre.org/{url_path}/{base_technique}/{sub_id}"
        else:
            url = f"https://attack.mitre.org/{url_path}/{attack_id}"

        return [
            {
                "source_name": "mitre-attack",
                "external_id": attack_id,
                "url": url,
            }
        ]

    return _create_stix_object


@pytest.fixture
def mock_relationship_factory():
    """Create accurate STIX 2.0 compliant ATT&CK relationship objects.

    This factory generates relationship objects that match the structure
    of real ATT&CK relationships and validates relationship types.
    """

    def _create_relationship(
        source_ref=None,
        target_ref=None,
        relationship_type="uses",
        source_name="mitre-attack",
        relationship_id=None,
        created=None,
        modified=None,
        description=None,
        external_refs=None,
        attack_spec_version="3.2.0",
        validate_relationship=True,
        **kwargs,
    ):
        # Generate default source/target refs if not provided
        if source_ref is None:
            source_ref = f"attack-pattern--{uuid.uuid4()}"
        if target_ref is None:
            if relationship_type == "mitigates":
                target_ref = f"attack-pattern--{uuid.uuid4()}"
            elif relationship_type == "uses":
                target_ref = f"attack-pattern--{uuid.uuid4()}"
            else:
                target_ref = f"attack-pattern--{uuid.uuid4()}"

        # Validate relationship type if requested
        if validate_relationship:
            _validate_relationship_types(source_ref, target_ref, relationship_type)

        # Generate timestamps
        default_created = created or datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        default_modified = modified or default_created

        # Generate unique ID
        if relationship_id is None:
            relationship_id = f"relationship--{uuid.uuid4()}"

        # Base STIX 2.0 relationship structure
        obj = {
            "type": "relationship",
            "id": relationship_id,
            "spec_version": "2.0",
            "created": default_created,
            "modified": default_modified,
            "created_by_ref": MITRE_IDENTITY_ID,
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "object_marking_refs": [MITRE_MARKING_DEFINITION_ID],
            "x_mitre_attack_spec_version": attack_spec_version,
            "x_mitre_modified_by_ref": MITRE_IDENTITY_ID,
        }

        # Add description if provided
        if description:
            obj["description"] = description

        # Add external references
        if external_refs is not None:
            obj["external_references"] = external_refs
        else:
            obj["external_references"] = [
                {"source_name": source_name, "description": f"ATT&CK {relationship_type} relationship"}
            ]

        # Apply any additional custom fields
        obj.update(kwargs)

        return obj

    def _validate_relationship_types(source_ref, target_ref, relationship_type):
        """Validate that the relationship type is valid for the given source/target types."""
        # Extract types from STIX IDs
        source_type = source_ref.split("--")[0] if "--" in source_ref else source_ref
        target_type = target_ref.split("--")[0] if "--" in target_ref else target_ref

        # Check if relationship type exists in our rules
        if relationship_type not in ATTACK_RELATIONSHIP_RULES:
            # Allow unknown relationship types for flexibility in testing
            return

        # Check if the source/target combination is valid
        valid_combinations = ATTACK_RELATIONSHIP_RULES[relationship_type]

        # Special handling for "revoked-by" which allows any type
        if relationship_type == "revoked-by":
            return  # Any combination is valid for revoked-by

        # Check if this specific combination is allowed
        for valid_source, valid_target in valid_combinations:
            if source_type == valid_source and target_type == valid_target:
                return

        # If we get here, the combination isn't explicitly allowed
        # For testing flexibility, we'll allow it but could add warnings
        pass

    return _create_relationship


# ========================================
# Mock DiffStix Fixtures
# ========================================


@pytest.fixture
def diffstix_data():
    """Provide standard attack domains data structure for enterprise/mobile/ics."""
    return {
        "old": {
            "enterprise-attack": {
                "attack_objects": {
                    "techniques": {},
                    "software": {},
                    "groups": {},
                    "campaigns": {},
                    "assets": {},
                    "mitigations": {},
                    "datasources": {},
                    "datacomponents": {},
                },
                "relationships": {
                    "subtechniques": {},
                    "revoked-by": {},
                    "mitigations": {},
                    "detections": {},
                },
                "attack_release_version": "16.1",
                "stix_datastore": None,
            },
            "mobile-attack": {
                "attack_objects": {
                    "techniques": {},
                    "software": {},
                    "groups": {},
                    "campaigns": {},
                    "assets": {},
                    "mitigations": {},
                    "datasources": {},
                    "datacomponents": {},
                },
                "relationships": {
                    "subtechniques": {},
                    "revoked-by": {},
                    "mitigations": {},
                    "detections": {},
                },
                "attack_release_version": "16.1",
                "stix_datastore": None,
            },
            "ics-attack": {
                "attack_objects": {
                    "techniques": {},
                    "software": {},
                    "groups": {},
                    "campaigns": {},
                    "assets": {},
                    "mitigations": {},
                    "datasources": {},
                    "datacomponents": {},
                },
                "relationships": {
                    "subtechniques": {},
                    "revoked-by": {},
                    "mitigations": {},
                    "detections": {},
                },
                "attack_release_version": "16.1",
                "stix_datastore": None,
            },
        },
        "new": {
            "enterprise-attack": {
                "attack_objects": {
                    "techniques": {},
                    "software": {},
                    "groups": {},
                    "campaigns": {},
                    "assets": {},
                    "mitigations": {},
                    "datasources": {},
                    "datacomponents": {},
                },
                "relationships": {
                    "subtechniques": {},
                    "revoked-by": {},
                    "mitigations": {},
                    "detections": {},
                },
                "attack_release_version": "17.0",
                "stix_datastore": None,
            },
            "mobile-attack": {
                "attack_objects": {
                    "techniques": {},
                    "software": {},
                    "groups": {},
                    "campaigns": {},
                    "assets": {},
                    "mitigations": {},
                    "datasources": {},
                    "datacomponents": {},
                },
                "relationships": {
                    "subtechniques": {},
                    "revoked-by": {},
                    "mitigations": {},
                    "detections": {},
                },
                "attack_release_version": "17.0",
                "stix_datastore": None,
            },
            "ics-attack": {
                "attack_objects": {
                    "techniques": {},
                    "software": {},
                    "groups": {},
                    "campaigns": {},
                    "assets": {},
                    "mitigations": {},
                    "datasources": {},
                    "datacomponents": {},
                },
                "relationships": {
                    "subtechniques": {},
                    "revoked-by": {},
                    "mitigations": {},
                    "detections": {},
                },
                "attack_release_version": "17.0",
                "stix_datastore": None,
            },
        },
        "changes": {
            "techniques": {},
            "software": {},
            "groups": {},
            "campaigns": {},
            "assets": {},
            "mitigations": {},
            "datasources": {},
            "datacomponents": {},
        },
    }


@pytest.fixture
def mock_diffstix(diffstix_data):
    """Pre-configured DiffStix mock with standard data structures."""
    mock_diffstix = Mock(spec=DiffStix)
    mock_diffstix.data = diffstix_data.copy()
    mock_diffstix.types = [
        "techniques",
        "software",
        "groups",
        "campaigns",
        "assets",
        "mitigations",
        "datasources",
        "datacomponents",
    ]
    mock_diffstix.domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
    mock_diffstix.verbose = False
    mock_diffstix.release_contributors = {}
    mock_diffstix.unchanged = False
    mock_diffstix.site_prefix = ""
    mock_diffstix.show_key = False
    mock_diffstix.include_contributors = False

    # Add domain and type mappings
    mock_diffstix.domain_to_domain_label = {
        "enterprise-attack": "Enterprise",
        "mobile-attack": "Mobile",
        "ics-attack": "ICS",
    }
    mock_diffstix.attack_type_to_title = {
        "techniques": "Techniques",
        "software": "Software",
        "groups": "Groups",
        "campaigns": "Campaigns",
        "assets": "Assets",
        "mitigations": "Mitigations",
        "datasources": "Data Sources",
        "datacomponents": "Data Components",
    }
    mock_diffstix.section_headers = {}
    for obj_type in mock_diffstix.types:
        mock_diffstix.section_headers[obj_type] = {
            "additions": f"New {mock_diffstix.attack_type_to_title[obj_type]}",
            "major_version_changes": "Major Version Changes",
            "minor_version_changes": "Minor Version Changes",
            "other_version_changes": "Other Version Changes",
            "patches": "Patches",
            "deprecations": "Deprecations",
            "revocations": "Revocations",
            "deletions": "Deletions",
            "unchanged": "Unchanged",
        }

    return mock_diffstix


# ========================================
# Mock STIX Object Fixtures
# ========================================


@pytest.fixture
def sample_technique_object(mock_stix_object_factory):
    """Sample technique STIX object for testing."""
    return mock_stix_object_factory(
        stix_type="attack-pattern",
        name="Test Technique",
        attack_id="T1234",
        version="1.0",
        kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        platforms=["Windows", "macOS", "Linux"],
    )


@pytest.fixture
def sample_subtechnique_object(mock_stix_object_factory):
    """Sample subtechnique STIX object for testing."""
    return mock_stix_object_factory(
        stix_type="attack-pattern",
        name="Test Subtechnique",
        attack_id="T1234.001",
        version="1.0",
        kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        platforms=["Windows"],
    )


@pytest.fixture
def sample_malware_object(mock_stix_object_factory):
    """Sample malware STIX object for testing."""
    return mock_stix_object_factory(
        stix_type="malware",
        name="Test Malware",
        attack_id="S1234",
        version="1.0",
        obj_type="malware",
        aliases=["TestMalware", "Evil Software"],
        platforms=["Windows", "Linux"],
    )


@pytest.fixture
def sample_tool_object(mock_stix_object_factory):
    """Sample tool STIX object for testing."""
    return mock_stix_object_factory(
        stix_type="tool",
        name="Test Tool",
        attack_id="S5678",
        version="1.0",
        obj_type="tool",
        aliases=["TestTool", "Utility"],
        platforms=["Windows", "macOS", "Linux"],
    )


@pytest.fixture
def sample_group_object(mock_stix_object_factory):
    """Sample group STIX object for testing."""
    return mock_stix_object_factory(
        stix_type="intrusion-set",
        name="Test Group",
        attack_id="G1234",
        version="1.0",
        obj_type="intrusion-set",
        aliases=["Test Group", "APT-Test", "Group X"],
    )


@pytest.fixture
def sample_mitigation_object(mock_stix_object_factory):
    """Sample mitigation STIX object for testing."""
    return mock_stix_object_factory(
        stix_type="course-of-action",
        name="Test Mitigation",
        attack_id="M1234",
        version="1.0",
        obj_type="course-of-action",
    )


@pytest.fixture
def sample_campaign_object(mock_stix_object_factory):
    """Sample campaign STIX object for testing."""
    return mock_stix_object_factory(
        stix_type="campaign",
        name="Test Campaign",
        attack_id="C1234",
        version="1.0",
        obj_type="campaign",
        aliases=["Operation Test", "Test Campaign"],
    )


@pytest.fixture
def sample_data_source_object(mock_stix_object_factory):
    """Sample data source STIX object for testing."""
    return mock_stix_object_factory(
        stix_type="x-mitre-data-source",
        name="Test Data Source",
        attack_id="DS1234",
        version="1.0",
        obj_type="x-mitre-data-source",
    )


@pytest.fixture
def sample_data_component_object(mock_stix_object_factory):
    """Sample data component STIX object for testing."""
    return mock_stix_object_factory(
        stix_type="x-mitre-data-component",
        name="Test Data Component",
        attack_id="DC1234",
        version="1.0",
        obj_type="x-mitre-data-component",
    )


@pytest.fixture
def sample_asset_object(mock_stix_object_factory):
    """Sample asset STIX object for testing."""
    return mock_stix_object_factory(
        stix_type="x-mitre-asset",
        name="Test Asset",
        attack_id="A1234",
        version="1.0",
        obj_type="x-mitre-asset",
    )


# ========================================
# Sample Relationship Fixtures
# ========================================


@pytest.fixture
def sample_group_uses_malware_relationship(mock_relationship_factory, sample_group_object, sample_malware_object):
    """Sample relationship: intrusion-set uses malware."""
    return mock_relationship_factory(
        source_ref=sample_group_object["id"],
        target_ref=sample_malware_object["id"],
        relationship_type="uses",
        description=f"{sample_group_object['name']} uses {sample_malware_object['name']}",
    )


@pytest.fixture
def sample_group_uses_tool_relationship(mock_relationship_factory, sample_group_object, sample_tool_object):
    """Sample relationship: intrusion-set uses tool."""
    return mock_relationship_factory(
        source_ref=sample_group_object["id"],
        target_ref=sample_tool_object["id"],
        relationship_type="uses",
        description=f"{sample_group_object['name']} uses {sample_tool_object['name']}",
    )


@pytest.fixture
def sample_group_uses_technique_relationship(mock_relationship_factory, sample_group_object, sample_technique_object):
    """Sample relationship: intrusion-set uses attack-pattern."""
    return mock_relationship_factory(
        source_ref=sample_group_object["id"],
        target_ref=sample_technique_object["id"],
        relationship_type="uses",
        description=f"{sample_group_object['name']} uses {sample_technique_object['name']}",
    )


@pytest.fixture
def sample_malware_uses_technique_relationship(
    mock_relationship_factory, sample_malware_object, sample_technique_object
):
    """Sample relationship: malware uses attack-pattern."""
    return mock_relationship_factory(
        source_ref=sample_malware_object["id"],
        target_ref=sample_technique_object["id"],
        relationship_type="uses",
        description=f"{sample_malware_object['name']} uses {sample_technique_object['name']}",
    )


@pytest.fixture
def sample_tool_uses_technique_relationship(mock_relationship_factory, sample_tool_object, sample_technique_object):
    """Sample relationship: tool uses attack-pattern."""
    return mock_relationship_factory(
        source_ref=sample_tool_object["id"],
        target_ref=sample_technique_object["id"],
        relationship_type="uses",
        description=f"{sample_tool_object['name']} uses {sample_technique_object['name']}",
    )


@pytest.fixture
def sample_campaign_uses_malware_relationship(mock_relationship_factory, sample_campaign_object, sample_malware_object):
    """Sample relationship: campaign uses malware."""
    return mock_relationship_factory(
        source_ref=sample_campaign_object["id"],
        target_ref=sample_malware_object["id"],
        relationship_type="uses",
        description=f"{sample_campaign_object['name']} uses {sample_malware_object['name']}",
    )


@pytest.fixture
def sample_campaign_uses_tool_relationship(mock_relationship_factory, sample_campaign_object, sample_tool_object):
    """Sample relationship: campaign uses tool."""
    return mock_relationship_factory(
        source_ref=sample_campaign_object["id"],
        target_ref=sample_tool_object["id"],
        relationship_type="uses",
        description=f"{sample_campaign_object['name']} uses {sample_tool_object['name']}",
    )


@pytest.fixture
def sample_campaign_uses_technique_relationship(
    mock_relationship_factory, sample_campaign_object, sample_technique_object
):
    """Sample relationship: campaign uses attack-pattern."""
    return mock_relationship_factory(
        source_ref=sample_campaign_object["id"],
        target_ref=sample_technique_object["id"],
        relationship_type="uses",
        description=f"{sample_campaign_object['name']} uses {sample_technique_object['name']}",
    )


@pytest.fixture
def sample_campaign_attributed_to_group_relationship(
    mock_relationship_factory, sample_campaign_object, sample_group_object
):
    """Sample relationship: campaign attributed-to intrusion-set."""
    return mock_relationship_factory(
        source_ref=sample_campaign_object["id"],
        target_ref=sample_group_object["id"],
        relationship_type="attributed-to",
        description=f"{sample_campaign_object['name']} attributed to {sample_group_object['name']}",
    )


@pytest.fixture
def sample_mitigation_mitigates_technique_relationship(
    mock_relationship_factory, sample_mitigation_object, sample_technique_object
):
    """Sample relationship: course-of-action mitigates attack-pattern."""
    return mock_relationship_factory(
        source_ref=sample_mitigation_object["id"],
        target_ref=sample_technique_object["id"],
        relationship_type="mitigates",
        description=f"{sample_mitigation_object['name']} mitigates {sample_technique_object['name']}",
    )


@pytest.fixture
def sample_subtechnique_of_technique_relationship(
    mock_relationship_factory, sample_subtechnique_object, sample_technique_object
):
    """Sample relationship: attack-pattern subtechnique-of attack-pattern."""
    return mock_relationship_factory(
        source_ref=sample_subtechnique_object["id"],
        target_ref=sample_technique_object["id"],
        relationship_type="subtechnique-of",
        description=f"{sample_subtechnique_object['name']} is a subtechnique of {sample_technique_object['name']}",
    )


@pytest.fixture
def sample_data_component_detects_technique_relationship(
    mock_relationship_factory, sample_data_component_object, sample_technique_object
):
    """Sample relationship: x-mitre-data-component detects attack-pattern."""
    return mock_relationship_factory(
        source_ref=sample_data_component_object["id"],
        target_ref=sample_technique_object["id"],
        relationship_type="detects",
        description=f"{sample_data_component_object['name']} detects {sample_technique_object['name']}",
    )


@pytest.fixture
def sample_technique_targets_asset_relationship(
    mock_relationship_factory, sample_technique_object, sample_asset_object
):
    """Sample relationship: attack-pattern targets x-mitre-asset."""
    return mock_relationship_factory(
        source_ref=sample_technique_object["id"],
        target_ref=sample_asset_object["id"],
        relationship_type="targets",
        description=f"{sample_technique_object['name']} targets {sample_asset_object['name']}",
    )


@pytest.fixture
def sample_revoked_by_relationship(mock_relationship_factory, sample_technique_object):
    """Sample relationship: attack-pattern revoked-by attack-pattern."""
    # Create a replacement technique for the revoked-by relationship
    replacement_technique = {
        "id": "attack-pattern--12345678-1234-5678-9abc-123456789012",
        "name": "Replacement Technique",
    }
    return mock_relationship_factory(
        source_ref=sample_technique_object["id"],
        target_ref=replacement_technique["id"],
        relationship_type="revoked-by",
        description=f"{sample_technique_object['name']} revoked by {replacement_technique['name']}",
    )


# ========================================
# Enhanced Fixtures for Advanced Coverage
# Useful for HTML output and behavioral testing
# ========================================


@pytest.fixture
def sample_deepdiff_data():
    """Sample DeepDiff output for testing detailed HTML generation."""
    return {
        "values_changed": {
            "root['description']": {"old_value": "Old description text", "new_value": "New description text"},
            "root['x_mitre_version']": {"old_value": "1.0", "new_value": "1.1"},
        },
        "iterable_item_added": {
            "root['kill_chain_phases'][1]": {"kill_chain_name": "mitre-attack", "phase_name": "persistence"}
        },
        "iterable_item_removed": {"root['x_mitre_platforms'][0]": "Windows"},
        "dictionary_item_added": {"root['x_mitre_data_sources']": ["Process monitoring"]},
        "dictionary_item_removed": {"root['old_field']": "removed_value"},
    }


@pytest.fixture
def complex_diffstix_with_all_changes(diffstix_data, mock_stix_object_factory):
    """DiffStix instance with all possible change types for comprehensive testing."""
    mock_diffstix = Mock(spec=DiffStix)
    mock_diffstix.data = diffstix_data.copy()

    # Add comprehensive test data for all change types
    test_objects = {
        # Technique with all relationship types
        "T1001": mock_stix_object_factory(
            name="Test Addition Technique", attack_id="T1001", stix_type="attack-pattern"
        ),
        "T1002": mock_stix_object_factory(
            name="Test Version Change Technique", attack_id="T1002", version="2.0", stix_type="attack-pattern"
        ),
        "T1003": mock_stix_object_factory(
            name="Test Revoked Technique", attack_id="T1003", revoked=True, stix_type="attack-pattern"
        ),
        "T1004": mock_stix_object_factory(
            name="Test Deprecated Technique", attack_id="T1004", deprecated=True, stix_type="attack-pattern"
        ),
        # Subtechnique
        "T1001.001": mock_stix_object_factory(
            name="Test Subtechnique", attack_id="T1001.001", stix_type="attack-pattern", is_subtechnique=True
        ),
        # Software
        "S1001": mock_stix_object_factory(
            name="Test Software", attack_id="S1001", stix_type="malware", obj_type="malware"
        ),
    }

    # Add revoked_by field to revoked objects
    revoking_object = mock_stix_object_factory(
        name="Replacement Technique", attack_id="T9999", stix_type="attack-pattern"
    )
    test_objects["T1003"]["revoked_by"] = revoking_object

    # Populate all change types
    for domain in ["enterprise-attack", "mobile-attack", "ics-attack"]:
        mock_diffstix.data["changes"]["techniques"] = {
            domain: {
                "additions": [test_objects["T1001"]],
                "major_version_changes": [test_objects["T1002"]],
                "minor_version_changes": [],
                "other_version_changes": [],
                "patches": [],
                "revocations": [test_objects["T1003"]],
                "deprecations": [test_objects["T1004"]],
                "deletions": [],
                "unchanged": [],
            }
        }

        mock_diffstix.data["changes"]["software"] = {
            domain: {
                "additions": [test_objects["S1001"]],
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

    # Set up mock attributes
    mock_diffstix.domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
    mock_diffstix.types = [
        "techniques",
        "software",
        "groups",
        "campaigns",
        "assets",
        "mitigations",
        "datasources",
        "datacomponents",
    ]
    mock_diffstix.site_prefix = "https://attack.mitre.org"
    mock_diffstix.show_key = True
    mock_diffstix.include_contributors = True
    mock_diffstix.release_contributors = {"Test Contributor": 1}

    # Add mappings
    mock_diffstix.domain_to_domain_label = {
        "enterprise-attack": "Enterprise",
        "mobile-attack": "Mobile",
        "ics-attack": "ICS",
    }
    mock_diffstix.attack_type_to_title = {
        "techniques": "Techniques",
        "software": "Software",
        "groups": "Groups",
        "campaigns": "Campaigns",
        "assets": "Assets",
        "mitigations": "Mitigations",
        "datasources": "Data Sources",
        "datacomponents": "Data Components",
    }
    mock_diffstix.section_headers = {}
    for obj_type in mock_diffstix.types:
        mock_diffstix.section_headers[obj_type] = {
            "additions": f"New {mock_diffstix.attack_type_to_title[obj_type]}",
            "major_version_changes": "Major Version Changes",
            "minor_version_changes": "Minor Version Changes",
            "other_version_changes": "Other Version Changes",
            "patches": "Patches",
            "deprecations": "Deprecations",
            "revocations": "Revocations",
            "deletions": "Deletions",
            "unchanged": "Unchanged",
        }

    return mock_diffstix


@pytest.fixture
def minimal_stix_bundles(mock_stix_object_factory, mock_relationship_factory):
    """Create comprehensive STIX bundles for thorough changelog testing.

    Includes 2-3 objects of each major type and various change scenarios:
    - Techniques (including subtechniques)
    - Software (malware/tools)
    - Groups, Campaigns, Mitigations
    - Data Sources, Data Components, Assets
    - Multiple relationship types
    - All change types: additions, modifications, revocations, deprecations, deletions
    """
    # ========================================
    # OLD BUNDLE OBJECTS (baseline state)
    # ========================================

    # Techniques (2 regular + 1 subtechnique)
    old_technique1 = mock_stix_object_factory(
        name="Existing Technique One", attack_id="T9001", version="1.0", stix_type="attack-pattern"
    )
    old_technique2 = mock_stix_object_factory(
        name="Technique To Be Revoked", attack_id="T9002", version="1.0", stix_type="attack-pattern"
    )
    old_subtechnique = mock_stix_object_factory(
        name="Existing Subtechnique",
        attack_id="T9001.001",
        version="1.0",
        stix_type="attack-pattern",
        is_subtechnique=True,
    )

    # Software (2 malware + 1 tool)
    old_malware1 = mock_stix_object_factory(
        name="Existing Malware One", attack_id="S9001", version="1.0", stix_type="malware", obj_type="malware"
    )
    old_malware2 = mock_stix_object_factory(
        name="Malware To Be Deprecated", attack_id="S9002", version="1.0", stix_type="malware", obj_type="malware"
    )
    old_tool = mock_stix_object_factory(
        name="Existing Tool", attack_id="S9003", version="1.0", stix_type="tool", obj_type="tool"
    )

    # Groups (2)
    old_group1 = mock_stix_object_factory(
        name="Existing Group One", attack_id="G9001", version="1.0", stix_type="intrusion-set", obj_type="intrusion-set"
    )
    old_group2 = mock_stix_object_factory(
        name="Group To Be Modified",
        attack_id="G9002",
        version="1.0",
        stix_type="intrusion-set",
        obj_type="intrusion-set",
    )

    # Campaigns (2)
    old_campaign1 = mock_stix_object_factory(
        name="Existing Campaign One", attack_id="C9001", version="1.0", stix_type="campaign", obj_type="campaign"
    )
    old_campaign2 = mock_stix_object_factory(
        name="Campaign To Be Deleted", attack_id="C9002", version="1.0", stix_type="campaign", obj_type="campaign"
    )

    # Mitigations (2)
    old_mitigation1 = mock_stix_object_factory(
        name="Existing Mitigation One",
        attack_id="M9001",
        version="1.0",
        stix_type="course-of-action",
        obj_type="course-of-action",
    )
    old_mitigation2 = mock_stix_object_factory(
        name="Mitigation To Be Modified",
        attack_id="M9002",
        version="1.0",
        stix_type="course-of-action",
        obj_type="course-of-action",
    )

    # Data Sources (2)
    old_datasource1 = mock_stix_object_factory(
        name="Existing Data Source One",
        attack_id="DS9001",
        version="1.0",
        stix_type="x-mitre-data-source",
        obj_type="x-mitre-data-source",
    )
    old_datasource2 = mock_stix_object_factory(
        name="Data Source To Be Modified",
        attack_id="DS9002",
        version="1.0",
        stix_type="x-mitre-data-source",
        obj_type="x-mitre-data-source",
    )

    # Data Components (2) - linked to data sources
    old_datacomponent1 = mock_stix_object_factory(
        name="Existing Data Component One",
        attack_id="DC9001",
        version="1.0",
        stix_type="x-mitre-data-component",
        obj_type="x-mitre-data-component",
    )

    old_datacomponent2 = mock_stix_object_factory(
        name="Data Component To Be Modified",
        attack_id="DC9002",
        version="1.0",
        stix_type="x-mitre-data-component",
        obj_type="x-mitre-data-component",
    )

    # Assets (2)
    old_asset1 = mock_stix_object_factory(
        name="Existing Asset One", attack_id="A9001", version="1.0", stix_type="x-mitre-asset", obj_type="x-mitre-asset"
    )
    old_asset2 = mock_stix_object_factory(
        name="Asset To Be Modified",
        attack_id="A9002",
        version="1.0",
        stix_type="x-mitre-asset",
        obj_type="x-mitre-asset",
    )

    # Relationships in old bundle
    old_relationship1 = mock_relationship_factory(
        source_ref=old_group1["id"], target_ref=old_malware1["id"], relationship_type="uses"
    )
    old_relationship2 = mock_relationship_factory(
        source_ref=old_malware1["id"], target_ref=old_technique1["id"], relationship_type="uses"
    )
    old_relationship3 = mock_relationship_factory(
        source_ref=old_subtechnique["id"], target_ref=old_technique1["id"], relationship_type="subtechnique-of"
    )
    old_relationship4 = mock_relationship_factory(
        source_ref=old_mitigation1["id"], target_ref=old_technique1["id"], relationship_type="mitigates"
    )
    old_relationship5 = mock_relationship_factory(
        source_ref=old_datacomponent1["id"], target_ref=old_technique1["id"], relationship_type="detects"
    )

    # ========================================
    # NEW BUNDLE OBJECTS (with changes)
    # ========================================

    # Unchanged objects (copied to new bundle)
    new_technique1 = old_technique1.copy()  # Unchanged
    new_subtechnique = old_subtechnique.copy()  # Unchanged
    new_malware1 = old_malware1.copy()  # Unchanged
    new_tool = old_tool.copy()  # Unchanged
    new_group1 = old_group1.copy()  # Unchanged
    new_campaign1 = old_campaign1.copy()  # Unchanged
    new_mitigation1 = old_mitigation1.copy()  # Unchanged
    new_datasource1 = old_datasource1.copy()  # Unchanged
    new_datacomponent1 = old_datacomponent1.copy()  # Unchanged
    new_asset1 = old_asset1.copy()  # Unchanged

    # Modified objects (version changes)
    new_group2_modified = old_group2.copy()
    new_group2_modified["x_mitre_version"] = "1.1"
    new_group2_modified["modified"] = "2025-01-15T12:00:00.000Z"
    new_group2_modified["description"] = "Updated description for modified group"

    new_mitigation2_modified = old_mitigation2.copy()
    new_mitigation2_modified["x_mitre_version"] = "1.1"
    new_mitigation2_modified["modified"] = "2025-01-15T12:00:00.000Z"

    new_datasource2_modified = old_datasource2.copy()
    new_datasource2_modified["x_mitre_version"] = "1.1"
    new_datasource2_modified["modified"] = "2025-01-15T12:00:00.000Z"

    new_datacomponent2_modified = old_datacomponent2.copy()
    new_datacomponent2_modified["x_mitre_version"] = "1.1"
    new_datacomponent2_modified["modified"] = "2025-01-15T12:00:00.000Z"

    new_asset2_modified = old_asset2.copy()
    new_asset2_modified["x_mitre_version"] = "1.1"
    new_asset2_modified["modified"] = "2025-01-15T12:00:00.000Z"

    # Revoked object with replacement technique
    replacement_technique = mock_stix_object_factory(
        name="Replacement for Revoked Technique", attack_id="T9999", version="1.0", stix_type="attack-pattern"
    )
    new_technique2_revoked = old_technique2.copy()
    new_technique2_revoked["revoked"] = True
    new_technique2_revoked["x_mitre_version"] = "1.1"
    new_technique2_revoked["modified"] = "2025-01-15T12:00:00.000Z"

    # Deprecated object
    new_malware2_deprecated = old_malware2.copy()
    new_malware2_deprecated["x_mitre_deprecated"] = True
    new_malware2_deprecated["x_mitre_version"] = "1.1"
    new_malware2_deprecated["modified"] = "2025-01-15T12:00:00.000Z"

    # New additions (only in new bundle)
    new_technique_added = mock_stix_object_factory(
        name="Brand New Technique", attack_id="T9100", version="1.0", stix_type="attack-pattern"
    )
    new_malware_added = mock_stix_object_factory(
        name="Brand New Malware", attack_id="S9100", version="1.0", stix_type="malware", obj_type="malware"
    )
    new_group_added = mock_stix_object_factory(
        name="Brand New Group", attack_id="G9100", version="1.0", stix_type="intrusion-set", obj_type="intrusion-set"
    )
    new_campaign_added = mock_stix_object_factory(
        name="Brand New Campaign", attack_id="C9100", version="1.0", stix_type="campaign", obj_type="campaign"
    )
    new_mitigation_added = mock_stix_object_factory(
        name="Brand New Mitigation",
        attack_id="M9100",
        version="1.0",
        stix_type="course-of-action",
        obj_type="course-of-action",
    )
    new_datasource_added = mock_stix_object_factory(
        name="Brand New Data Source",
        attack_id="DS9100",
        version="1.0",
        stix_type="x-mitre-data-source",
        obj_type="x-mitre-data-source",
    )

    # Relationships in new bundle (some unchanged, some new)
    new_relationship1 = old_relationship1.copy()  # Unchanged
    new_relationship2 = old_relationship2.copy()  # Unchanged
    new_relationship3 = old_relationship3.copy()  # Unchanged
    new_relationship4 = old_relationship4.copy()  # Unchanged
    new_relationship5 = old_relationship5.copy()  # Unchanged

    # New relationships
    new_relationship6 = mock_relationship_factory(
        source_ref=new_group_added["id"], target_ref=new_malware_added["id"], relationship_type="uses"
    )
    new_relationship7 = mock_relationship_factory(
        source_ref=new_campaign_added["id"], target_ref=new_group_added["id"], relationship_type="attributed-to"
    )
    new_relationship8 = mock_relationship_factory(
        source_ref=new_mitigation_added["id"], target_ref=new_technique_added["id"], relationship_type="mitigates"
    )
    # Revoked-by relationship
    new_relationship9 = mock_relationship_factory(
        source_ref=new_technique2_revoked["id"], target_ref=replacement_technique["id"], relationship_type="revoked-by"
    )

    # ========================================
    # CREATE BUNDLES
    # ========================================

    old_objects = [
        MITRE_IDENTITY,
        MITRE_MARKING_DEFINITION,
        old_technique1,
        old_technique2,
        old_subtechnique,
        old_malware1,
        old_malware2,
        old_tool,
        old_group1,
        old_group2,
        old_campaign1,
        old_campaign2,
        old_mitigation1,
        old_mitigation2,
        old_datasource1,
        old_datasource2,
        old_datacomponent1,
        old_datacomponent2,
        old_asset1,
        old_asset2,
        old_relationship1,
        old_relationship2,
        old_relationship3,
        old_relationship4,
        old_relationship5,
    ]

    new_objects = [
        MITRE_IDENTITY,
        MITRE_MARKING_DEFINITION,
        # Unchanged objects
        new_technique1,
        new_subtechnique,
        new_malware1,
        new_tool,
        new_group1,
        new_campaign1,
        new_mitigation1,
        new_datasource1,
        new_datacomponent1,
        new_asset1,
        # Modified objects
        new_group2_modified,
        new_mitigation2_modified,
        new_datasource2_modified,
        new_datacomponent2_modified,
        new_asset2_modified,
        # Revoked/deprecated objects
        new_technique2_revoked,
        new_malware2_deprecated,
        # New additions
        new_technique_added,
        new_malware_added,
        new_group_added,
        new_campaign_added,
        new_mitigation_added,
        new_datasource_added,
        replacement_technique,
        # Relationships
        new_relationship1,
        new_relationship2,
        new_relationship3,
        new_relationship4,
        new_relationship5,
        new_relationship6,
        new_relationship7,
        new_relationship8,
        new_relationship9,
        # Note: old_campaign2 is deleted (not in new bundle)
    ]

    old_bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": old_objects}
    new_bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": new_objects}

    # ========================================
    # EXPECTED CHANGES STRUCTURE
    # ========================================

    expected_changes = {
        "additions": [
            new_technique_added,
            new_malware_added,
            new_group_added,
            new_campaign_added,
            new_mitigation_added,
            new_datasource_added,
            replacement_technique,
        ],
        "minor_version_changes": [
            new_group2_modified,
            new_mitigation2_modified,
            new_datasource2_modified,
            new_datacomponent2_modified,
            new_asset2_modified,
        ],
        "revocations": [new_technique2_revoked],
        "deprecations": [new_malware2_deprecated],
        "deletions": [old_campaign2],  # Deleted from new bundle
        "new_relationships": [new_relationship6, new_relationship7, new_relationship8, new_relationship9],
    }

    return {
        "old": old_bundle,
        "new": new_bundle,
        "expected_changes": expected_changes,
    }


@pytest.fixture
def lightweight_diffstix(minimal_stix_bundles, tmp_path):
    """Create a DiffStix instance with minimal test data for fast testing."""
    # Create directory structure that DiffStix expects
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    old_dir.mkdir()
    new_dir.mkdir()

    # Write test bundles to domain-specific files
    old_file = old_dir / "enterprise-attack.json"
    new_file = new_dir / "enterprise-attack.json"

    with open(old_file, "w") as f:
        json.dump(minimal_stix_bundles["old"], f)

    with open(new_file, "w") as f:
        json.dump(minimal_stix_bundles["new"], f)

    # Create DiffStix with test data
    return DiffStix(
        domains=["enterprise-attack"],
        old=str(old_dir),
        new=str(new_dir),
        show_key=False,
        verbose=False,
        include_contributors=False,
    )


# ========================================
# Fixtures for ATT&CK Navigator Layers
# ========================================


@pytest.fixture
def mock_layers_dict():
    """Mock layers dictionary for testing layer file generation."""
    return {
        "enterprise-attack": {
            "versions": {"layer": "4.5", "navigator": "5.0.0", "attack": "17.0"},
            "name": "Test Enterprise Updates",
            "description": "Test enterprise layer description",
            "domain": "enterprise-attack",
            "techniques": [
                {
                    "techniqueID": "T1001",
                    "tactic": "initial-access",
                    "enabled": True,
                    "color": "#a1d99b",
                    "comment": "addition",
                }
            ],
            "sorting": 0,
            "hideDisabled": False,
            "legendItems": [{"color": "#a1d99b", "label": "additions: New objects"}],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#205b8f",
            "selectTechniquesAcrossTactics": True,
        },
        "mobile-attack": {
            "versions": {"layer": "4.5", "navigator": "5.0.0", "attack": "17.0"},
            "name": "Test Mobile Updates",
            "description": "Test mobile layer description",
            "domain": "mobile-attack",
            "techniques": [],
            "sorting": 0,
            "hideDisabled": False,
            "legendItems": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#205b8f",
            "selectTechniquesAcrossTactics": True,
        },
        "ics-attack": {
            "versions": {"layer": "4.5", "navigator": "5.0.0", "attack": "17.0"},
            "name": "Test ICS Updates",
            "description": "Test ICS layer description",
            "domain": "ics-attack",
            "techniques": [],
            "sorting": 0,
            "hideDisabled": False,
            "legendItems": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#205b8f",
            "selectTechniquesAcrossTactics": True,
        },
    }


# ========================================
# Real Data Testing Fixtures
# ========================================


@pytest.fixture(scope="session")
def golden_161_170_changelog_dir():
    """Path to golden files directory."""
    base_path = Path(__file__).parent.parent.parent
    return base_path / "tests/resources/changelog-v16.1_to_v17.0"


@pytest.fixture(scope="session")
def generated_161_170_diffstix(tmp_path_factory) -> DiffStix:
    """Create and cache a DiffStix instance for reuse across tests."""
    versions_param = ["16.1", "17.0"]
    result_paths = _download_attack_stix_data(versions_param, tmp_path_factory)
    return DiffStix(
        domains=["enterprise-attack", "mobile-attack", "ics-attack"],
        old=result_paths["16.1"],
        new=result_paths["17.0"],
        show_key=True,
        verbose=False,
        include_contributors=True,
    )


# ========================================
# Reusable DiffStix Test Scenario Fixtures
# ========================================


@pytest.fixture
def diffstix_with_version_scenarios(minimal_stix_bundles, tmp_path):
    """Create factory for DiffStix instances with different version scenarios."""

    def _create_diffstix(old_version="16.1", new_version=None):
        import uuid

        # Create unique subdirectory for this diffstix instance
        instance_dir = tmp_path / f"diffstix_{uuid.uuid4().hex[:8]}"
        instance_dir.mkdir()
        old_dir = instance_dir / "old"
        new_dir = instance_dir / "new"
        old_dir.mkdir()
        new_dir.mkdir()

        old_bundle = minimal_stix_bundles["old"].copy()
        new_bundle = minimal_stix_bundles["new"].copy()

        with open(old_dir / "enterprise-attack.json", "w") as f:
            json.dump(old_bundle, f)
        with open(new_dir / "enterprise-attack.json", "w") as f:
            json.dump(new_bundle, f)

        diffstix = DiffStix(
            domains=["enterprise-attack"],
            old=str(old_dir),
            new=str(new_dir),
            show_key=False,
            verbose=False,
            include_contributors=False,
        )

        # Set version data for testing
        diffstix.data["old"]["enterprise-attack"]["attack_release_version"] = old_version
        diffstix.data["new"]["enterprise-attack"]["attack_release_version"] = new_version

        return diffstix

    return _create_diffstix


@pytest.fixture
def empty_changes_diffstix(tmp_path):
    """Create DiffStix instance with identical old/new bundles for testing no-change scenarios."""
    bundle_id = str(uuid.uuid4())
    object_id = str(uuid.uuid4())

    identical_bundle = {
        "type": "bundle",
        "id": f"bundle--{bundle_id}",
        "objects": [
            MITRE_IDENTITY,
            MITRE_MARKING_DEFINITION,
            {
                "type": "attack-pattern",
                "id": f"attack-pattern--{object_id}",
                "spec_version": "2.0",
                "created": "2023-01-01T00:00:00.000Z",
                "modified": "2023-01-01T00:00:00.000Z",
                "created_by_ref": MITRE_IDENTITY_ID,
                "name": "Test Technique",
                "description": "Test technique for no-change scenario",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T9999",
                        "url": "https://attack.mitre.org/techniques/T9999",
                    }
                ],
                "object_marking_refs": [MITRE_MARKING_DEFINITION_ID],
                "x_mitre_attack_spec_version": "3.2.0",
                "x_mitre_version": "1.0",
                "x_mitre_modified_by_ref": MITRE_IDENTITY_ID,
                "x_mitre_domains": ["enterprise-attack"],
                "x_mitre_platforms": ["Windows"],
            },
        ],
    }

    # Create directories
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    old_dir.mkdir()
    new_dir.mkdir()

    # Write identical bundles
    with open(old_dir / "enterprise-attack.json", "w") as f:
        json.dump(identical_bundle, f)
    with open(new_dir / "enterprise-attack.json", "w") as f:
        json.dump(identical_bundle, f)

    # Create DiffStix instance
    return DiffStix(
        domains=["enterprise-attack"],
        old=str(old_dir),
        new=str(new_dir),
        show_key=False,
        verbose=False,
        include_contributors=False,
    )


@pytest.fixture
def large_dataset_diffstix(mock_stix_object_factory, tmp_path):
    """Create DiffStix instance with larger test dataset (50+ objects)."""
    # Create larger test dataset
    old_objects = [MITRE_IDENTITY, MITRE_MARKING_DEFINITION]
    new_objects = [MITRE_IDENTITY, MITRE_MARKING_DEFINITION]

    # Create 50 techniques in old version
    for i in range(50):
        old_objects.append(mock_stix_object_factory(name=f"Technique {i}", attack_id=f"T{1000 + i}", version="1.0"))

    # Create modified techniques + new ones in new version
    for i in range(50):
        # First 25 are modified versions
        if i < 25:
            modified_technique = mock_stix_object_factory(
                name=f"Technique {i} Modified", attack_id=f"T{1000 + i}", version="1.1"
            )
            new_objects.append(modified_technique)
        else:
            # Last 25 are unchanged
            new_objects.append(mock_stix_object_factory(name=f"Technique {i}", attack_id=f"T{1000 + i}", version="1.0"))

    # Add 10 completely new techniques
    for i in range(10):
        new_objects.append(mock_stix_object_factory(name=f"New Technique {i}", attack_id=f"T{2000 + i}", version="1.0"))

    # Create bundles
    old_bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": old_objects}
    new_bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": new_objects}

    # Create directories
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    old_dir.mkdir()
    new_dir.mkdir()

    # Write bundles
    with open(old_dir / "enterprise-attack.json", "w") as f:
        json.dump(old_bundle, f)
    with open(new_dir / "enterprise-attack.json", "w") as f:
        json.dump(new_bundle, f)

    # Create DiffStix instance
    return DiffStix(
        domains=["enterprise-attack"],
        old=str(old_dir),
        new=str(new_dir),
        show_key=False,
        verbose=False,
        include_contributors=False,
    )


# ========================================
# Test Directory Setup Utilities
# ========================================


@pytest.fixture
def setup_test_directories():
    """Set up test directories with STIX bundles for specified domains.

    This fixture provides a reusable method to create old/new directory
    structures with STIX bundle files for testing changelog functionality.

    Returns
    -------
    callable
        Function that takes (tmp_path, minimal_stix_bundles, domains, custom_bundles=None, write_files=True) and
        returns (old_dir_path, new_dir_path) as strings
    """

    def _setup_directories(tmp_path, minimal_stix_bundles, domains, custom_bundles=None, write_files=True):
        """Set up test directories with STIX bundles for specified domains.

        Parameters
        ----------
        tmp_path : pathlib.Path
            pytest tmp_path fixture
        minimal_stix_bundles : dict
            dict with 'old' and 'new' STIX bundles (used if custom_bundles is None)
        domains : list of str
            list of domain names (e.g. ['enterprise-attack', 'mobile-attack'])
        custom_bundles : dict, optional
            dict with 'old' and 'new' custom content to write instead of minimal_stix_bundles
            Can contain raw strings for invalid JSON or custom bundle objects
        write_files : bool, optional
            Whether to write files to the directories (default True)
            If False, only creates empty directories

        Returns
        -------
        tuple of str
            (old_dir_path, new_dir_path) as strings
        """
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        new_dir.mkdir()

        if write_files:
            # Use custom bundles if provided, otherwise use minimal_stix_bundles
            bundles_to_use = custom_bundles if custom_bundles is not None else minimal_stix_bundles

            for domain in domains:
                # Handle old bundle content
                old_content = bundles_to_use["old"]
                with open(old_dir / f"{domain}.json", "w") as f:
                    if isinstance(old_content, str):
                        # Raw string content (e.g., invalid JSON)
                        f.write(old_content)
                    else:
                        # JSON object
                        json.dump(old_content, f)

                # Handle new bundle content
                new_content = bundles_to_use["new"]
                with open(new_dir / f"{domain}.json", "w") as f:
                    if isinstance(new_content, str):
                        # Raw string content (e.g., invalid JSON)
                        f.write(new_content)
                    else:
                        # JSON object
                        json.dump(new_content, f)

        return str(old_dir), str(new_dir)

    return _setup_directories


# ========================================
# Enhanced Assertion Helper Fixtures
# ========================================


@pytest.fixture
def assert_markdown_structure():
    """Assert markdown content has expected basic structure."""
    return assert_basic_markdown_structure


@pytest.fixture
def assert_json_structure():
    """Assert JSON data has expected structure for changelog output."""
    return assert_json_structure_valid


@pytest.fixture
def assert_layer_structure():
    """Assert layer data has expected ATT&CK Navigator structure."""
    return assert_layer_structure_valid


@pytest.fixture
def assert_diffstix_structure():
    """Assert DiffStix instance has valid data structure."""
    return assert_diffstix_data_structure_valid


@pytest.fixture
def validate_comprehensive_outputs():
    """Validate comprehensive output generation scenario."""
    return validate_comprehensive_output_generation


@pytest.fixture
def validate_format_consistency():
    """Validate that all output formats are consistent."""
    return validate_output_format_consistency


# ========================================
# File Path Creation Helper Fixtures
# ========================================


@pytest.fixture
def create_output_paths():
    """Create standard test output file paths."""
    return create_test_output_file_paths


@pytest.fixture
def create_layer_paths():
    """Create layer file paths for specified domains."""
    return create_layer_file_paths


# ========================================
# File Validation Helper Fixtures
# ========================================


@pytest.fixture
def validate_markdown_file():
    """Validate markdown file content and return it."""
    return validate_markdown_file_content


@pytest.fixture
def validate_json_file():
    """Validate JSON file content and return it."""
    return validate_json_file_content


@pytest.fixture
def validate_layer_file():
    """Validate layer file content and return it."""
    return validate_layer_file_content


# ========================================
# CLI Argument Testing Helper Fixtures
# ========================================


@pytest.fixture
def setup_monkeypatch_args():
    """Set up monkeypatch for CLI argument testing."""

    def _setup_args(argv_list, monkeypatch):
        """Set up sys.argv with monkeypatch for argument parsing tests."""
        import sys

        monkeypatch.setattr(sys, "argv", argv_list)

    return _setup_args
