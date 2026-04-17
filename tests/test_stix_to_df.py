"""Unit tests for STIX-to-dataframe conversion helpers."""

import stix2

from mitreattack.attackToExcel import stixToDf


def test_techniques_to_df_handles_missing_tactic_definition(monkeypatch):
    """TechniquesToDf should not fail when tactic shortnames are missing from x-mitre-tactic objects."""
    monkeypatch.setattr(stixToDf, "relationshipsToDf", lambda src, relatedType: {})
    monkeypatch.setattr(stixToDf, "_get_relationship_citations", lambda df, codex: [""] * len(df))

    mem_store = stix2.MemoryStore(
        stix_data=[
            {
                "type": "attack-pattern",
                "spec_version": "2.0",
                "id": "attack-pattern--11111111-1111-4111-8111-111111111111",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "name": "Test Technique",
                "description": "Test",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "defense-evasion",
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T0001",
                        "url": "https://example.com",
                    }
                ],
                "x_mitre_domains": ["enterprise-attack"],
            }
        ]
    )

    dataframes = stixToDf.techniquesToDf(mem_store, "enterprise-attack")
    techniques_df = dataframes["techniques"]

    assert len(techniques_df) == 1
    assert techniques_df.iloc[0]["tactics"] == "Defense Evasion"


def test_techniques_to_df_handles_targets_relationship_without_description():
    """TechniquesToDf should tolerate asset targets relationships with no description."""
    mem_store = stix2.MemoryStore(
        stix_data=[
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": "attack-pattern--11111111-1111-4111-8111-111111111111",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "name": "Test Technique",
                "description": "Test technique",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "inhibit-response-function",
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T0001",
                        "url": "https://example.com/technique",
                    }
                ],
                "x_mitre_domains": ["ics-attack"],
            },
            {
                "type": "x-mitre-asset",
                "spec_version": "2.1",
                "id": "x-mitre-asset--22222222-2222-4222-8222-222222222222",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "name": "Test Asset",
                "description": "Test asset",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "A0001",
                        "url": "https://example.com/asset",
                    }
                ],
                "x_mitre_domains": ["ics-attack"],
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--33333333-3333-4333-8333-333333333333",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "relationship_type": "targets",
                "source_ref": "attack-pattern--11111111-1111-4111-8111-111111111111",
                "target_ref": "x-mitre-asset--22222222-2222-4222-8222-222222222222",
                "external_references": [
                    {
                        "source_name": "Test Reference",
                        "description": "Test citation",
                        "url": "https://example.com/reference",
                    }
                ],
            },
        ]
    )

    dataframes = stixToDf.techniquesToDf(mem_store, "ics-attack")

    assert "targeted assets" in dataframes
    assert len(dataframes["targeted assets"]) == 1
    assert dataframes["targeted assets"].iloc[0]["target name"] == "Test Asset"
    assert dataframes["techniques"].iloc[0]["relationship citations"] == ""
    if "citations" in dataframes:
        assert dataframes["citations"].empty
