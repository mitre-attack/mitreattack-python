from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    groups_using_s0061 = mitre_attack_data.get_groups_using_software_with_id('tool--03342581-f790-4f03-ba41-e82e67392e23')
    print(f"Groups using S0061 ({len(groups_using_s0061)}):")
    for g in groups_using_s0061:
        group = g['object']
        print(f"* {group.name} ({mitre_attack_data.get_attack_id(group.id)})")


if __name__ == "__main__":
    main()
