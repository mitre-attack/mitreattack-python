import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get all groups related to software
    all_groups_using_all_software = mitre_attack_data.get_all_groups_using_all_software()

    print(f"Groups using software ({len(all_groups_using_all_software.keys())} software):")
    for id, groups in all_groups_using_all_software.items():
        print(f"* {id} - used by {len(groups)} {'group' if len(groups) == 1 else 'groups'}")


if __name__ == "__main__":
    main()
