from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    groups_using_software = mitre_attack_data.get_groups_using_software()
    print(f"Groups using software ({len(groups_using_software.keys())}):")
    for id, groups in groups_using_software.items():
        print(f"* {id} - used by {len(groups)} {'group' if len(groups) == 1 else 'groups'}")


if __name__ == "__main__":
    main()
