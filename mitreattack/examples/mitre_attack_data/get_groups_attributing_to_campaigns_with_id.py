from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    groups_attributing_to_c0011 = mitre_attack_data.get_groups_attributing_to_campaign_with_id('campaign--b4e5a4a9-f3be-4631-ba8f-da6ebb067fac')
    print(f"Groups attributing to C0011 ({len(groups_attributing_to_c0011)}):")
    for g in groups_attributing_to_c0011:
        group = g['object']
        print(f"* {group.name} ({mitre_attack_data.get_attack_id(group.id)})")


if __name__ == "__main__":
    main()
