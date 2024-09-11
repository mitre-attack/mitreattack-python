# ATT&CK Analytic Extractor
# Extracts Analytics from an ATT&CK STIX 2.0 file
# Writes output to attack_analytics.md
# Example usage: python3 analytic_extractor.py --in_file enterprise-attack-14.1.json

import argparse
import json
import re

from mitreattack.stix20 import MitreAttackData

# Prune an input string to remove any non-analytic text
# This assumes that all analytics start the <h4> html block
STRING_RE = "Analytic(\s|.)*"


def pruneString(in_string):
    result = re.search(STRING_RE, in_string).group(0)
    return result


if __name__ == "__main__":
    # Argparse setup
    parser = argparse.ArgumentParser(
        prog="analytic_extractor.py",
        description="This script extracts and dumps the analytics for a given ATT&CK STIX JSON file.",
    )
    parser.add_argument("--in_file", help="The input ATT&CK STIX JSON file to extract analytics from.", required=True)
    args = parser.parse_args()

    mitre_attack_data = MitreAttackData(stix_filepath=args.in_file)

    # Open/parse the ATT&CK STIX JSON
    with open(args.in_file, "r") as attack_file:
        attack_json = json.load(attack_file)

    # Get all of the techniques
    techniques = mitre_attack_data.get_techniques(remove_revoked_deprecated=True)

    # Get all of the data components
    data_components = mitre_attack_data.get_datacomponents(remove_revoked_deprecated=True)

    # Get all of the detects relationships
    detects_relationships = [
        x for x in attack_json["objects"] if x["type"] == "relationship" and x["relationship_type"] == "detects"
    ]

    # Build a mapping of ATT&CK STIX UUIDs -> ATT&CK IDs
    # For later relationship dereferencing
    technique_map = {}
    for technique in techniques:
        external_ref = technique["external_references"][0]
        if external_ref["source_name"] == "mitre-attack":
            technique_map[technique["id"]] = external_ref["external_id"]

    # Build a mapping of ATT&CK STIX UUIDs -> Data Components
    # For later relationship dereferencing
    dc_map = {}
    for dc in data_components:
        dc_map[dc["id"]] = dc["name"]

    technique_analytics = {}
    # Iterate over the detects relationships to find analytics
    for rel in detects_relationships:
        if "description" in rel:
            desc = rel["description"]
            if "Analytic" in desc and "<code>" in desc:
                # Get the ID of the parent technique
                tech_id = technique_map[rel["target_ref"]]
                # Get the name of the data component
                data_comp = dc_map[rel["source_ref"]]
                if tech_id not in technique_analytics:
                    technique_analytics[tech_id] = {}
                    technique_analytics[tech_id][data_comp] = desc
                else:
                    if data_comp not in technique_analytics[tech_id]:
                        technique_analytics[tech_id][data_comp] = desc

    # Write the output to markdown
    with open("attack_analytics.md", "w") as md_file:
        md_file.write("# Analytics Extracted from ATT&CK STIX\n\n")

        for tech_id, data_comps in dict(sorted(technique_analytics.items())).items():
            tech_header = "## " + tech_id + "\n"
            md_file.write(tech_header)
            for data_comp, desc in data_comps.items():
                data_comp_header = "### " + data_comp + "\n"
                md_file.write(data_comp_header)
                md_file.write(pruneString(desc))
                md_file.write("\n")
                if not str(desc).endswith("\n"):
                    md_file.write("\n")

    print("DONE. Results written to attack_analytics.md")
