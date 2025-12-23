import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get parent techniques of sub-techniques
    parent_techniques = mitre_attack_data.get_all_parent_techniques_of_all_subtechniques()

    print(f"Parent techniques of sub-techniques ({len(parent_techniques.keys())} sub-techniques):")
    for id, parent_technique in parent_techniques.items():
        parent = parent_technique[0]["object"]
        print(f"* {parent.id} is the parent of {id}")


if __name__ == "__main__":
    main()
