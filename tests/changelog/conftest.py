"""Shared fixtures for changelog helper tests.

This file contains fixtures specific to changelog_helper.py testing functionality.
Shared fixtures (STIX data, layers, etc.) are imported from the parent conftest.py.
"""

import json
import uuid
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
from tests.fixtures.stix_objects import (
    MITRE_IDENTITY,
    MITRE_IDENTITY_ID,
    MITRE_MARKING_DEFINITION,
    MITRE_MARKING_DEFINITION_ID,
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
    "diffstix_with_version_scenarios",
    "empty_changes_diffstix",
    "large_dataset_diffstix",
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
