"""Reusable synthetic ATT&CK STIX object fixtures for tests."""

import json
import uuid
from datetime import datetime

import pytest
from stix2 import MemoryStore

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

MITRE_MARKING_DEFINITION_ID = "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
MITRE_MARKING_DEFINITION = {
    "type": "marking-definition",
    "id": MITRE_MARKING_DEFINITION_ID,
    "definition": {
        "statement": "Copyright 2015-2025, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation."
    },
    "created": "2017-06-01T00:00:00.000Z",
    "created_by_ref": MITRE_IDENTITY_ID,
    "definition_type": "statement",
}

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
    "revoked-by": [("any", "any")],
}


@pytest.fixture
def mitre_identity():
    """Return the standard MITRE identity object used across ATT&CK objects."""
    return MITRE_IDENTITY.copy()


@pytest.fixture
def mitre_marking_definition():
    """Return the standard ATT&CK marking definition object."""
    return MITRE_MARKING_DEFINITION.copy()


@pytest.fixture
def mock_stix_object_factory():
    """Create STIX 2.0 compliant ATT&CK objects with configurable fields."""

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
        if stix_id is None:
            stix_id = f"{obj_type or stix_type}--{uuid.uuid4()}"

        default_created = created or datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        default_modified = modified or default_created

        if is_subtechnique is None and attack_id and "." in attack_id:
            is_subtechnique = True

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
            "x_mitre_domains": domains or ["enterprise-attack"],
        }

        if revoked:
            obj["revoked"] = True
        if deprecated:
            obj["x_mitre_deprecated"] = True
        if contributors:
            obj["x_mitre_contributors"] = contributors

        effective_type = obj_type or stix_type
        if effective_type == "attack-pattern":
            if is_subtechnique:
                obj["x_mitre_is_subtechnique"] = True
            obj["kill_chain_phases"] = kill_chain_phases or [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ]
            obj["x_mitre_platforms"] = platforms or ["Windows", "macOS", "Linux"]
            obj["x_mitre_data_sources"] = ["Process: Process Creation", "Command: Command Execution"]
            obj["x_mitre_detection"] = f"Detection guidance for {obj['name']}"
        elif effective_type == "intrusion-set":
            obj["aliases"] = aliases or [obj["name"]]
        elif effective_type in {"malware", "tool"}:
            obj["labels"] = labels or [effective_type]
            if aliases:
                obj["x_mitre_aliases"] = aliases
            obj["x_mitre_platforms"] = platforms or ["Windows"]
        elif effective_type == "campaign" and aliases:
            obj["aliases"] = aliases
        elif effective_type == "x-mitre-tactic":
            obj["x_mitre_shortname"] = attack_id.lower() if attack_id else "test-tactic"

        if external_refs is not None:
            obj["external_references"] = external_refs
        elif attack_id:
            obj["external_references"] = _generate_external_references(attack_id, effective_type, is_subtechnique)

        obj.update(kwargs)
        return obj

    return _create_stix_object


def _generate_external_references(attack_id, object_type, is_subtechnique):
    if object_type in {"malware", "tool"}:
        url_path = "software"
    elif object_type == "intrusion-set":
        url_path = "groups"
    elif object_type == "course-of-action":
        url_path = "mitigations"
    elif object_type == "campaign":
        url_path = "campaigns"
    else:
        url_path = "techniques"

    if is_subtechnique and "." in attack_id:
        base_technique, sub_id = attack_id.split(".", 1)
        url = f"https://attack.mitre.org/{url_path}/{base_technique}/{sub_id}"
    else:
        url = f"https://attack.mitre.org/{url_path}/{attack_id}"

    return [{"source_name": "mitre-attack", "external_id": attack_id, "url": url}]


@pytest.fixture
def mock_relationship_factory():
    """Create STIX 2.0 compliant ATT&CK relationship objects."""

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
        source_ref = source_ref or f"attack-pattern--{uuid.uuid4()}"
        target_ref = target_ref or f"attack-pattern--{uuid.uuid4()}"

        if validate_relationship:
            _validate_relationship_types(source_ref, target_ref, relationship_type)

        default_created = created or datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        default_modified = modified or default_created

        obj = {
            "type": "relationship",
            "id": relationship_id or f"relationship--{uuid.uuid4()}",
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

        if description:
            obj["description"] = description

        obj["external_references"] = external_refs or [
            {"source_name": source_name, "description": f"ATT&CK {relationship_type} relationship"}
        ]
        obj.update(kwargs)
        return obj

    return _create_relationship


def _validate_relationship_types(source_ref, target_ref, relationship_type):
    source_type = source_ref.split("--")[0] if "--" in source_ref else source_ref
    target_type = target_ref.split("--")[0] if "--" in target_ref else target_ref

    if relationship_type not in ATTACK_RELATIONSHIP_RULES or relationship_type == "revoked-by":
        return

    for valid_source, valid_target in ATTACK_RELATIONSHIP_RULES[relationship_type]:
        if source_type == valid_source and target_type == valid_target:
            return


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


@pytest.fixture
def attack_bundle_factory():
    """Create a STIX bundle from provided objects."""

    def _create_bundle(objects, include_mitre_objects=True):
        bundle_objects = list(objects)
        if include_mitre_objects:
            bundle_objects = [MITRE_IDENTITY, MITRE_MARKING_DEFINITION, *bundle_objects]
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": bundle_objects}

    return _create_bundle


@pytest.fixture
def attack_memstore_factory(attack_bundle_factory):
    """Create a MemoryStore from provided STIX objects."""

    def _create_memstore(objects, include_mitre_objects=True):
        bundle = attack_bundle_factory(objects, include_mitre_objects=include_mitre_objects)
        return MemoryStore(stix_data=bundle["objects"])

    return _create_memstore


@pytest.fixture
def minimal_stix_bundles(mock_stix_object_factory, mock_relationship_factory, attack_bundle_factory):
    """Create small old/new ATT&CK STIX bundles for changelog-style scenarios."""
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
    old_malware1 = mock_stix_object_factory(
        name="Existing Malware One", attack_id="S9001", version="1.0", stix_type="malware", obj_type="malware"
    )
    old_malware2 = mock_stix_object_factory(
        name="Malware To Be Deprecated", attack_id="S9002", version="1.0", stix_type="malware", obj_type="malware"
    )
    old_tool = mock_stix_object_factory(
        name="Existing Tool", attack_id="S9003", version="1.0", stix_type="tool", obj_type="tool"
    )
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
    old_campaign1 = mock_stix_object_factory(
        name="Existing Campaign One", attack_id="C9001", version="1.0", stix_type="campaign", obj_type="campaign"
    )
    old_campaign2 = mock_stix_object_factory(
        name="Campaign To Be Deleted", attack_id="C9002", version="1.0", stix_type="campaign", obj_type="campaign"
    )
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

    new_technique1 = old_technique1.copy()
    new_subtechnique = old_subtechnique.copy()
    new_malware1 = old_malware1.copy()
    new_tool = old_tool.copy()
    new_group1 = old_group1.copy()
    new_campaign1 = old_campaign1.copy()
    new_mitigation1 = old_mitigation1.copy()
    new_datasource1 = old_datasource1.copy()
    new_datacomponent1 = old_datacomponent1.copy()
    new_asset1 = old_asset1.copy()

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

    replacement_technique = mock_stix_object_factory(
        name="Replacement for Revoked Technique", attack_id="T9999", version="1.0", stix_type="attack-pattern"
    )
    new_technique2_revoked = old_technique2.copy()
    new_technique2_revoked["revoked"] = True
    new_technique2_revoked["x_mitre_version"] = "1.1"
    new_technique2_revoked["modified"] = "2025-01-15T12:00:00.000Z"

    new_malware2_deprecated = old_malware2.copy()
    new_malware2_deprecated["x_mitre_deprecated"] = True
    new_malware2_deprecated["x_mitre_version"] = "1.1"
    new_malware2_deprecated["modified"] = "2025-01-15T12:00:00.000Z"

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

    new_relationship1 = old_relationship1.copy()
    new_relationship2 = old_relationship2.copy()
    new_relationship3 = old_relationship3.copy()
    new_relationship4 = old_relationship4.copy()
    new_relationship5 = old_relationship5.copy()
    new_relationship6 = mock_relationship_factory(
        source_ref=new_group_added["id"], target_ref=new_malware_added["id"], relationship_type="uses"
    )
    new_relationship7 = mock_relationship_factory(
        source_ref=new_campaign_added["id"], target_ref=new_group_added["id"], relationship_type="attributed-to"
    )
    new_relationship8 = mock_relationship_factory(
        source_ref=new_mitigation_added["id"], target_ref=new_technique_added["id"], relationship_type="mitigates"
    )
    new_relationship9 = mock_relationship_factory(
        source_ref=new_technique2_revoked["id"], target_ref=replacement_technique["id"], relationship_type="revoked-by"
    )

    old_bundle = attack_bundle_factory(
        [
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
    )
    new_bundle = attack_bundle_factory(
        [
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
            new_group2_modified,
            new_mitigation2_modified,
            new_datasource2_modified,
            new_datacomponent2_modified,
            new_asset2_modified,
            new_technique2_revoked,
            new_malware2_deprecated,
            new_technique_added,
            new_malware_added,
            new_group_added,
            new_campaign_added,
            new_mitigation_added,
            new_datasource_added,
            replacement_technique,
            new_relationship1,
            new_relationship2,
            new_relationship3,
            new_relationship4,
            new_relationship5,
            new_relationship6,
            new_relationship7,
            new_relationship8,
            new_relationship9,
        ]
    )

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
        "deletions": [old_campaign2],
        "new_relationships": [new_relationship6, new_relationship7, new_relationship8, new_relationship9],
    }

    return {"old": old_bundle, "new": new_bundle, "expected_changes": expected_changes}


@pytest.fixture
def setup_test_directories():
    """Create old/new directories with STIX bundle files for selected domains."""

    def _setup_directories(tmp_path, minimal_stix_bundles, domains, custom_bundles=None, write_files=True):
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        new_dir.mkdir()

        if write_files:
            bundles_to_use = custom_bundles if custom_bundles is not None else minimal_stix_bundles
            for domain in domains:
                _write_bundle(old_dir / f"{domain}.json", bundles_to_use["old"])
                _write_bundle(new_dir / f"{domain}.json", bundles_to_use["new"])

        return str(old_dir), str(new_dir)

    return _setup_directories


def _write_bundle(path, content):
    with open(path, "w") as f:
        if isinstance(content, str):
            f.write(content)
        else:
            json.dump(content, f)
