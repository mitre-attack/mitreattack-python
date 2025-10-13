import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get all software related to groups
    all_software_used_by_all_groups = mitre_attack_data.get_all_software_used_by_all_groups()

    print(f"Software used by groups ({len(all_software_used_by_all_groups.keys())} groups):")
    for id, software_used in all_software_used_by_all_groups.items():
        print(f"* {id} - {len(software_used)} software used")


if __name__ == "__main__":
    main()
