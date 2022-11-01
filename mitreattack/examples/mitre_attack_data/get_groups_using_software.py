from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    # get all groups related to software
    groups_using_software = mitre_attack_data.get_groups_using_software()
    print(f"Groups using software ({len(groups_using_software.keys())} software):")
    for id, groups in groups_using_software.items():
        print(f"* {id} - used by {len(groups)} {'group' if len(groups) == 1 else 'groups'}")

    # get groups related to S0349
    groups_using_s0349 = groups_using_software['tool--b76b2d94-60e4-4107-a903-4a3a7622fb3b']
    print(f"\nGroups using S0349 ({len(groups_using_s0349)}):")
    for g in groups_using_s0349:
        group = g['object']
        print(f"* {group.name} ({mitre_attack_data.get_attack_id(group.id)})")


if __name__ == "__main__":
    main()
