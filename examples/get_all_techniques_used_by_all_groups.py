import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get all techniques related to groups
    techniques_used_by_groups = mitre_attack_data.get_all_techniques_used_by_all_groups()

    print(f"Techniques used by groups ({len(techniques_used_by_groups.keys())} groups):")
    for id, techniques_used in techniques_used_by_groups.items():
        print(f"* {id} - {len(techniques_used)} {'technique' if len(techniques_used) == 1 else 'techniques'} used")


if __name__ == "__main__":
    main()
