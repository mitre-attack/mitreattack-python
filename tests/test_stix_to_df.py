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
